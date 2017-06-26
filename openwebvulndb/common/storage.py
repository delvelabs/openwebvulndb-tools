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

import re
from json.decoder import JSONDecodeError
from os.path import join, dirname
from os import makedirs, scandir, walk, remove
from contextlib import contextmanager

from .schemas import MetaSchema, VulnerabilityListSchema, VersionListSchema, FileListSchema
from .serialize import serialize
from .config import DEFAULT_PATH
from .logs import logger
from .versionbuilder import VersionImporter, VersionBuilder
from .models import FileList, VersionList


class Storage:

    def __init__(self, base_path=DEFAULT_PATH):
        self.base_path = base_path
        self.known = set()

    def write_meta(self, meta):
        self._write(MetaSchema(), meta, 'META.json')

    def read_meta(self, key):
        return self._read(MetaSchema(), key, 'META.json')

    def list_meta(self, *args):
        for key, path, dirs, files in self.walk(*args):
            if "META.json" in files:
                yield self.read_meta(key)

    def write_vulnerabilities(self, vlist):
        self._write(VulnerabilityListSchema(), vlist, 'vuln-%s.json' % vlist.producer.lower())

    def read_vulnerabilities(self, key, producer):
        return self._read(VulnerabilityListSchema(), key, 'vuln-%s.json' % producer.lower())

    def list_vulnerabilities(self, key):
        name_format = re.compile(r'^vuln-(\w+)\.json$')

        for entry in scandir(self._path(key)):
            parts = name_format.match(entry.name)
            if parts and not entry.is_dir():
                yield self.read_vulnerabilities(key, parts.group(1))

    def write_versions(self, versions):
        if isinstance(versions, VersionList):
            self._write_to_cache(VersionListSchema(), versions, "version_list.json")
            exporter = VersionBuilder()
            try:
                file_list = self._read(FileListSchema(), versions.key, "versions.json")
                exporter.update_file_list(file_list, versions)
                self._write(FileListSchema(), file_list, "versions.json")
            except FileNotFoundError:
                file_list = exporter.create_file_list_from_version_list(versions)
                if file_list is not None:
                    self._write(FileListSchema(), file_list, "versions.json")
        elif isinstance(versions, FileList):
            self._write(FileListSchema(), versions, "versions.json")

    def read_versions(self, key):
        importer = VersionImporter()
        try:
            return self._read_from_cache(VersionListSchema(), key, 'version_list.json')
        except FileNotFoundError:
            file_list = self._read(FileListSchema(), key, 'versions.json')
            return importer.import_version_list(file_list)

    def read_version_list(self, key):
        return self._read(VersionListSchema(), key, 'versions.json')

    def list_directories(self, path):
        try:
            return {entry.name for entry in scandir(self._path(path)) if entry.is_dir()}
        except FileNotFoundError:
            return set()

    def append(self, relative, content):
        path = dirname(relative)
        self._prepare_path(path)
        with self._open('a+', relative) as fp:
            fp.write(content.strip("\n") + "\n")

    def read_lines(self, relative):
        try:
            with self._open('r', relative) as fp:
                for line in fp.readlines():
                    yield line.strip("\n")
        except FileNotFoundError:
            pass

    def walk(self, *args):
        base_len = len(self.base_path)

        for path, dirs, files in walk(self._path(*args)):
            key = path[base_len + 1:]
            yield key, path, dirs, files

    def _write_to_cache(self, schema, item, *args):
        data, errors = serialize(schema, item)
        path = join(".cache", item.key)
        self._prepare_path(path)
        with self._open('w', path, *args) as fp:
            fp.write(data)

    def _read_from_cache(self, schema, key, filename):
        try:
            return self._read(schema, ".cache", key, filename)
        except FileNotFoundError as e:
            raise e

    def remove(self, *args):
        remove(self._path(*args))

    def _write(self, schema, item, *args):
        data, errors = serialize(schema, item)
        self._prepare_path(item.key)
        with self._open('w', item.key, *args) as fp:
            fp.write(data)

    def _read(self, schema, *args):
        try:
            with self._open('r', *args) as fp:
                data, errors = schema.loads(fp.read())
                if errors:
                    raise Exception(*args, errors)
                return data
        except JSONDecodeError:
            logger.critical("JSON Decode error in %s", args)

    @contextmanager
    def _open(self, mode, *args):
        with open(self._path(*args), mode) as fp:
            yield fp

    def _prepare_path(self, relative):
        if relative not in self.known:
            makedirs(self._path(relative), mode=0o755, exist_ok=True)
            self.known.add(relative)

    def _path(self, *args):
        return join(self.base_path, *args)
