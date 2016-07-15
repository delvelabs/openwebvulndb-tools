from os.path import join
from os import makedirs

from .schemas import MetaSchema


class Storage:

    def __init__(self, base_path):
        self.base_path = base_path

    def write_meta(self, meta):
        schema = MetaSchema()
        data, errors = schema.dumps(meta)
        makedirs(join(self.base_path, meta.key), mode=0o755, exist_ok=True)
        with open(join(self.base_path, meta.key, 'META.json'), 'w') as fp:
            fp.write(data)
