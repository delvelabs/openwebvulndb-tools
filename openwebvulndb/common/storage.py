from os.path import join, dirname
from os import makedirs, scandir
from contextlib import contextmanager

from .schemas import MetaSchema, VulnerabilityListSchema, serialize
from .config import DEFAULT_PATH


class Storage:

    def __init__(self, base_path=DEFAULT_PATH):
        self.base_path = base_path
        self.known = set()

    def write_meta(self, meta):
        self._write(MetaSchema(), meta, 'META.json')

    def read_meta(self, key):
        return self._read(MetaSchema(), key, 'META.json')

    def write_vulnerabilities(self, vlist):
        self._write(VulnerabilityListSchema(), vlist, 'vuln-%s.json' % vlist.producer.lower())

    def read_vulnerabilities(self, key, producer):
        return self._read(VulnerabilityListSchema(), key, 'vuln-%s.json' % producer.lower())

    def list_directories(self, path):
        try:
            return {entry.name for entry in scandir(join(self.base_path, path)) if entry.is_dir()}
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

    def _write(self, schema, item, *args):
        data, errors = serialize(schema, item)
        self._prepare_path(item.key)
        with self._open('w', item.key, *args) as fp:
            fp.write(data)

    def _read(self, schema, *args):
        with self._open('r', *args) as fp:
            data, errors = schema.loads(fp.read())
            return data

    @contextmanager
    def _open(self, mode, *args):
        with open(join(self.base_path, *args), mode) as fp:
            yield fp

    def _prepare_path(self, relative):
        if relative not in self.known:
            makedirs(join(self.base_path, relative), mode=0o755, exist_ok=True)
            self.known.add(relative)
