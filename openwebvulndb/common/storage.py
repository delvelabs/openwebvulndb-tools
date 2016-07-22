from os.path import join, dirname
from os import makedirs, scandir

from .schemas import MetaSchema, serialize
from .config import DEFAULT_PATH


class Storage:

    def __init__(self, base_path=DEFAULT_PATH):
        self.base_path = base_path
        self.known = set()

    def write_meta(self, meta):
        data, errors = serialize(MetaSchema(), meta)
        self.prepare_path(meta.key)
        with open(join(self.base_path, meta.key, 'META.json'), 'w') as fp:
            fp.write(data)

    def prepare_path(self, relative):
        if relative not in self.known:
            makedirs(join(self.base_path, relative), mode=0o755, exist_ok=True)
            self.known.add(relative)

    def list_directories(self, path):
        try:
            return {entry.name for entry in scandir(join(self.base_path, path)) if entry.is_dir()}
        except FileNotFoundError:
            return set()

    def append(self, relative, content):
        path = dirname(relative)
        self.prepare_path(path)
        with open(join(self.base_path, relative), 'a+') as fp:
            fp.write(content.strip("\n") + "\n")

    def read(self, relative):
        try:
            with open(join(self.base_path, relative), 'r') as fp:
                for line in fp.readlines():
                    yield line.strip("\n")
        except FileNotFoundError:
            pass
