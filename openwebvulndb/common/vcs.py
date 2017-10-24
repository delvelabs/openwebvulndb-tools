# openwebvulndb-tools: A collection of tools to maintain vulnerability databases
# Copyright (C) 2016-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import asyncio
from asyncio import create_subprocess_exec
from uuid import uuid4
from os.path import join
from os import mkdir, walk, rmdir, remove
from contextlib import contextmanager
from urllib.parse import urljoin, urlparse, urlunparse
import re
from datetime import datetime

from .errors import ExecutionFailure, DirectoryExpected
from .logs import logger


line_pattern = re.compile("(?P<revision>\d+)\s+(?P<author>[\w\s\.-]+)\s+(?P<month>[A-Z][a-z]{2})\s+"
                          "(?P<day>\d{2})\s+(?:(?P<year>\d{4})|(?P<time>\d\d:\d\d))\s+(?P<component>\S+)/$")


class Workspace:

    async def to_version(self, version):
        raise NotImplemented()

    async def list_versions(self):
        raise NotImplemented()


class RepositoryChecker:

    def __init__(self, subversion=None):
        self.subversion = subversion
        self.handlers = dict(subversion=self.svn_has_content)

    async def has_content(self, repository):
        """
        Determines if the provided repository contains content or if the entry is bogus.

        Subversion:
           - Typical structure, tagged revisions
           - Direct version list
        """
        try:
            return await self.handlers[repository.type](repository)
        except KeyError:
            return False

    async def svn_has_content(self, repository):
        base_content = await self.subversion.ls(repository.location)
        if self.is_classic_structure(base_content):
            tags = await self.subversion.ls(join(repository.location, 'tags'))
            return len(tags) > 0

        return len(base_content) > 0

    def is_classic_structure(self, content):
        return "tags/" in content


class Subversion:
    def __init__(self, *, loop, svn_base_dir="/tmp"):
        self.loop = loop
        self.svn_base_dir = svn_base_dir

    @staticmethod
    def build_ls(url):
        return ["svn", "ls", url]

    async def ls(self, url):
        try:
            command = self.build_ls(url)
            return await asyncio.wait_for(self.read_lines(command), 30.0, loop=self.loop)
        except asyncio.TimeoutError:
            raise ExecutionFailure('Timeout reached')

    async def read_lines(self, command, *, ignore_errors=False):
        process = await create_subprocess_exec(
            *command,
            loop=self.loop,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL
        )

        out = []
        while not process.stdout.at_eof():
            line = await process.stdout.readline()
            if line != b'':
                out.append(line.decode('utf8').strip("\n"))

        # No need to wait for a long time, we're at EOF
        code = await process.wait()
        if code == 0 or ignore_errors:
            return out

        raise ExecutionFailure("Listing failure")

    async def checkout(self, path, *, workdir):
        if await self.has_recursive_externals(path, workdir=workdir):
            logger.info("%s has recursive externals. Ignoring all externals" % path)
            await self._process(["svn", "checkout", "--ignore-externals", path, "."], workdir=workdir)
        else:
            await self._process(["svn", "checkout", path, "."], workdir=workdir)

    async def switch(self, path, *, workdir):
        if await self.has_recursive_externals(path, workdir=workdir):
            logger.info("%s has recursive externals. Ignoring all externals" % path)
            await self._process(["svn", "switch", "--ignore-ancestry", "--ignore-externals", path], workdir=workdir)
        else:
            await self._process(["svn", "switch", "--ignore-ancestry", path], workdir=workdir)

    async def has_recursive_externals(self, path, *, workdir):
        externals = await self.list_externals(path, workdir=workdir)
        for external in externals:
            if external["url"] in path:
                return True
        return False

    async def list_externals(self, path, *, workdir):
        out = await self._process(["svn", "propget", "-R", "svn:externals", path], workdir=workdir)
        if len(out) == 0:
            return []
        out = out.decode()
        externals = []
        for line in out.split("\n"):
            if len(line) > 0 and " - " in line:
                line = line[line.index(" - ") + 3:]
                part0, part1 = line.split(" ")
                if part0.startswith("http") or self.is_relative_external_url(part0):
                    externals.append({"name": part1, "url": part0})
                elif part1.startswith("http") or self.is_relative_external_url(part1):
                    externals.append({"name": part0, "url": part1})
                else:
                    logger.warn("invalid external definition: %s" % line)
        repo_info = await self.info(path, workdir=workdir)
        for external in externals:
            if self.is_relative_external_url(external["url"]):
                logger.info("relative url: %s" % external["url"])
                external["url"] = self.to_absolute_url(external["url"], repo_info)
                logger.info("absolute url: %s" % external["url"])
        return externals

    def is_relative_external_url(self, url):
        for prefix in ["/", "^/", "../", "//"]:
            if url.startswith(prefix):
                return True
        return False

    def to_absolute_url(self, url, repo_info):
        if url.startswith("//"):
            repo_url = urlparse(repo_info["url"])
            external_url = urlparse(url)
            return urlunparse((repo_url.scheme, external_url.netloc, external_url.path, external_url.params,
                               external_url.query, external_url.fragment))
        if url.startswith("/"):
            parsed_url = urlparse(repo_info["root"])
            server_url = urlunparse((parsed_url.scheme, parsed_url.netloc, "", "", "", ""))
            return urljoin(server_url, url)
        if url.startswith("^/"):
            url = url[len("^/"):]
            if "../" in url:
                parsed_url = urlparse(repo_info["root"])
                url_path = self._backtrack_path(url, parsed_url.path)
                return urlunparse((parsed_url.scheme, parsed_url.netloc, url_path, "", "", ""))
            else:
                return "/".join((repo_info["root"], url))
        if url.startswith("../"):
            parsed_url = urlparse(repo_info["url"])
            path = self._backtrack_path(url, parsed_url.path)
            return urlunparse((parsed_url.scheme, parsed_url.netloc, path, "", "", ""))
        return url

    def _backtrack_path(self, relative_path, base_url_path):
        rel_path_parts = relative_path.split("/")
        backtrack = len([part for part in rel_path_parts if part == ".."])
        base_path_parts = base_url_path.split("/")
        if backtrack < len(base_path_parts):
            base_path_parts = base_path_parts[:-backtrack]
            path = "/".join(base_path_parts)
        else:
            path = ""
        return "/".join([path] + rel_path_parts[backtrack:])

    async def info(self, path, *, workdir):
        out = await self._process(["svn", "info", "--show-item", "url", path], workdir=workdir)
        out = out.decode()
        url = out.rstrip("\n")
        out = await self._process(["svn", "info", "--show-item", "repos-root-url", path], workdir=workdir)
        out = out.decode()
        root = out.rstrip("\n")
        return {"url": url, "root": root}

    async def get_plugins_with_new_release(self, date):
        return await self.get_components_with_new_release("plugins", "http://plugins.svn.wordpress.org/", date)

    async def get_themes_with_new_release(self, date):
        return await self.get_components_with_new_release("themes", "http://themes.svn.wordpress.org/", date)

    async def get_components_with_new_release(self, key, repository_url, date):
        try:
            components_update_date = await self._get_last_release_date_of_components(key, repository_url)
            components = set()
            for key, update_date in components_update_date.items():
                if update_date >= date:
                    components.add(key)
            return components
        except ExecutionFailure as e:
            logger.warn("A command failed to execute: %s", e)
            return set()

    async def _get_last_release_date_of_components(self, key, repository_url):

        def parse_line(line):
            line = line.lstrip()  # Remove whitespace added at beginning of line when revision has less digits.
            match = line_pattern.match(line)
            if match:
                component_key, day, month, year = match.group("component", "day", "month", "year")
                if component_key is not ".":
                    component_key = "%s/%s" % (key, component_key)
                    year = datetime.today().year if year is None else year
                    date = datetime.strptime("%s %s %s" % (day, month, year), "%d %b %Y")
                    return component_key, date
            return None, None

        try:
            command = ["svn", "ls", "-v", "^/tags", repository_url]
            out = await asyncio.wait_for(self.read_lines(command, ignore_errors=True), timeout=60, loop=self.loop)
            update_dates = {}
            for line in out:
                component_key, date = parse_line(line)
                if component_key is not None:
                    update_dates[component_key] = date.date()
            return update_dates
        except asyncio.TimeoutError:
            raise ExecutionFailure('Timeout reached')

    async def _process(self, command, workdir):
        process = await create_subprocess_exec(
            *command,
            cwd=workdir,
            loop=self.loop,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE
        )
        try:
            out, err = await process.communicate()
            if err.startswith(b"svn: E200007"):
                raise DirectoryExpected(err)

            if process.returncode != 0:
                raise ExecutionFailure(err)

            return out
        finally:
            if process.returncode is None:  # return code is None if process is still running
                process.kill()

    @contextmanager
    def workspace(self, *, repository):
        try:
            workspace = SubversionWorkspace(subversion=self,
                                            repository=repository,
                                            workdir=join(self.svn_base_dir, str(uuid4())))
            workspace.create()
            yield workspace
        finally:
            workspace.destroy()


class SubversionWorkspace(Workspace):
    def __init__(self, *, workdir, subversion, repository):
        self.workdir = workdir
        self.subversion = subversion
        self.repository = repository
        self.is_empty = True

    @staticmethod
    def dirname():
        return str(uuid4())

    def create(self):
        mkdir(self.workdir, mode=0o755)

    async def prepare(self):
        content = await self.subversion.ls(self.repository)
        if "tags/" in content:
            self.repository = join(self.repository, "tags/")

    async def to_version(self, version):
        if self.is_empty:
            await self.subversion.checkout(join(self.repository, version), workdir=self.workdir)
            self.is_empty = False
        else:
            await self.subversion.switch(join(self.repository, version), workdir=self.workdir)

        logger.debug("Version %s ready (%s)", version, self.repository)

    async def list_versions(self):
        versions = await self.subversion.ls(self.repository)
        return [v.strip("/") for v in versions if re.search("\d", v)]

    def destroy(self):
        for path, dirs, files in walk(self.workdir, topdown=False):
            for f in files:
                remove(join(path, f))
            rmdir(path)
