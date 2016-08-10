import hashlib
from os import walk
from os.path import join

from .models import Signature


class HashCollector:

    def __init__(self, *, path, hasher, prefix="", lookup_version=None):
        self.path = path
        self.hasher = hasher
        self.prefix = prefix
        self.version_checker = VersionChecker(lookup_version)

    def collect(self):
        for path, dirs, files in walk(self.path):
            files = [f for f in files if f[-4:] != ".php"]

            for file in files:
                self.version_checker.reset()

                full_path = join(path, file)
                relative = full_path[len(self.path):].strip("/")
                hash = self.hasher.hash(full_path, chunk_cb=self.version_checker)

                yield Signature(path=join(self.prefix, relative), hash=hash, algo=self.hasher.algo,
                                contains_version=self.version_checker.contains_version)


class Hasher:
    def __init__(self, algo):
        self.algo = algo

    def hash(self, file_path, chunk_cb=lambda c: None):
        hash = hashlib.new(self.algo)
        with open(file_path, "rb") as fp:
            for chunk in iter(lambda: fp.read(4096), b""):
                hash.update(chunk)
                chunk_cb(chunk)

            return hash.hexdigest()


class VersionChecker:
    def __init__(self, version):
        self.version = version.encode('utf-8') if version is not None else version
        self.reset()

    def reset(self):
        self.contains_version = None

    def __call__(self, chunk):
        if self.version is not None and self.version in chunk:
            self.contains_version = True
