from os.path import join
from os import makedirs, scandir

from .schemas import MetaSchema
from .config import DEFAULT_PATH


class Storage:

    def __init__(self, base_path=DEFAULT_PATH):
        self.base_path = base_path

    def write_meta(self, meta):
        schema = MetaSchema()
        data, errors = schema.dumps(meta, indent=4)
        makedirs(join(self.base_path, meta.key), mode=0o755, exist_ok=True)
        with open(join(self.base_path, meta.key, 'META.json'), 'w') as fp:
            fp.write(data)

    def list_directories(self, path):
        try:
            return {entry.name for entry in scandir(join(self.base_path, path)) if entry.is_dir()}
        except FileNotFoundError:
            return set()
