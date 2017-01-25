from .models import Model


class FilesList(Model):

    def init(self, *, producer, key, files=None):
        self.producer = producer
        self.key = key
        self.files = files or []


class File(Model):

    def init(self, *, path, signatures=None):
        self.path = path
        self.signatures = signatures


class Signature(Model):

    def init(self, *, hash, algo="SHA256", versions=None):
        self.hash = hash
        self.algo = algo
        self.versions = versions or []
