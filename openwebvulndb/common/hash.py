import hashlib
from os import walk
from os.path import join

from .models import Signature


class HashCollector:

    def __init__(self, *, path, hasher, prefix=""):
        self.path = path
        self.hasher = hasher
        self.prefix = prefix

    def collect(self):
        for path, dirs, files in walk(self.path):
            files = [f for f in files if f[-4:] != ".php"]

            for file in files:
                full_path = join(path, file)
                relative = full_path[len(self.path):].strip("/")
                hash = self.hasher.hash(full_path)

                yield Signature(path=join(self.prefix, relative), hash=hash, algo=self.hasher.algo)


class Hasher:
    def __init__(self, algo):
        self.algo = algo

    def hash(self, file_path):
        hash = hashlib.new(self.algo)
        with open(file_path, "rb") as fp:
            for chunk in iter(lambda: fp.read(4096), b""):
                hash.update(chunk)

            return hash.hexdigest()
