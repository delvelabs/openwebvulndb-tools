import asyncio
from asyncio import create_subprocess_exec
from uuid import uuid4
from os.path import join
from os import mkdir, walk, rmdir, remove
from contextlib import contextmanager

from .errors import ExecutionFailure


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

    async def read_lines(self, command):
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
        if code == 0:
            return out

        raise ExecutionFailure()

    async def checkout(self, path, *, workdir):
        process = await create_subprocess_exec(
            "svn", "checkout", path, ".",
            cwd=workdir,
            loop=self.loop,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL
        )
        await process.communicate()

    async def switch(self, path, *, workdir):
        process = await create_subprocess_exec(
            "svn", "switch", path,
            cwd=workdir,
            loop=self.loop,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL
        )
        await process.communicate()

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
            self.subversion.checkout(join(self.repository, version), workdir=self.workdir)
            self.is_empty = False
        else:
            self.subversion.switch(join(self.repository, version), workdir=self.workdir)

    async def list_versions(self):
        versions = await self.subversion.ls(self.repository)
        return [v.strip("/") for v in versions]

    def destroy(self):
        for path, dirs, files in walk(self.workdir, topdown=False):
            for f in files:
                remove(join(path, f))
            rmdir(path)
