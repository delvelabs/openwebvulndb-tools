from .errors import VulnerabilityNotFound
from .basemodel import Model
from itertools import chain


class Meta(Model):

    def init(self, *, key, name=None, url=None, repositories=None):
        self.key = key
        self.name = name
        self.url = url
        self.repositories = repositories or []


class Repository(Model):

    def init(self, *, type, location):
        self.type = type
        self.location = location


class VulnerabilityList(Model):

    def init(self, *, producer, key, vulnerabilities=None):
        self.producer = producer
        self.key = key
        self.vulnerabilities = vulnerabilities or []

    def get_vulnerability(self, id, *, create_missing=False):
        id = str(id)

        for v in self.vulnerabilities:
            if v.id == id:
                return v

        if not create_missing:
            raise VulnerabilityNotFound(id)

        vuln = Vulnerability(id=id)
        self.vulnerabilities.append(vuln)
        return vuln

    @property
    def children(self):
        return self.vulnerabilities


class Vulnerability(Model):

    def init(self, *, id, title=None, reported_type=None, updated_at=None, created_at=None,
             references=None, affected_versions=None):
        self.id = id
        self.title = title
        self.reported_type = reported_type
        self.updated_at = updated_at
        self.created_at = created_at
        self.references = references or []
        self.affected_versions = affected_versions or []

    def add_affected_version(self, range):
        if range.fixed_in is None and range.introduced_in is None:
            return

        if range.fixed_in is not None \
           and any(v.fixed_in == range.fixed_in for v in self.affected_versions):
            return
        if range.introduced_in is not None \
           and any(v.introduced_in == range.introduced_in for v in self.affected_versions):
            return

        self.affected_versions.append(range)

    @property
    def children(self):
        return chain(self.references, self.affected_versions)


class Reference(Model):

    def init(self, *, type=None, id=None, url=None):
        self.type = type
        self.id = id
        self.url = url


class VersionRange(Model):
    def init(self, *, introduced_in=None, fixed_in=None):
        self.introduced_in = introduced_in
        self.fixed_in = fixed_in
