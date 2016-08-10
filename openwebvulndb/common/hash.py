import hashlib
from os import walk
from os.path import join

from .models import Signature, VersionList
from .version import VersionCompare


class RepositoryHasher:
    def __init__(self, *, storage, hasher, subversion=None):
        self.storage = storage
        self.hasher = hasher
        self.handlers = dict(subversion=subversion)

    async def collect_for_version(self, workspace, version, *, prefix=""):
        await workspace.to_version(version)

        collector = HashCollector(workspace.workdir, hasher=self.hasher, prefix=prefix, lookup_version=version)
        return collector.collect()

    async def collect_for_workspace(self, key, workspace, *, prefix=""):
        version_list = self.get_version_list(key)
        repository_versions = set(await workspace.list_versions())
        stored_versions = {v.version for v in version_list.versions}
        required_versions = VersionCompare.sorted(repository_versions - stored_versions)

        for v in required_versions:
            signatures = await self.collect_for_version(workspace, v, prefix=prefix)
            desc = version_list.get_version(v, create_missing=True)
            desc.signatures = signatures

        self.storage.write_versions(version_list)

    async def collect_from_meta(self, meta, prefix_pattern=""):
        for repo in meta.repositories:
            repo_handler = self.handlers.get(repo.type)
            if repo_handler is None:
                continue

            with repo_handler.workspace(repo.location) as workspace:
                await workspace.prepare()

                prefix = prefix_pattern.format(meta=meta)
                await self.collect_for_workspace(meta.key, workspace, prefix=prefix)

            return True

        return False

    def get_version_list(self, key):
        try:
            return self.storage.read_versions(key)
        except FileNotFoundError:
            return VersionList(producer="RepositoryHasher", key=key)


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

                sig = Signature(path=join(self.prefix, relative), algo=self.hasher.algo)

                sig.hash = self.hasher.hash(full_path, chunk_cb=self.version_checker)
                sig.contains_version = self.version_checker.contains_version
                yield sig


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
