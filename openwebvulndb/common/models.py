from .errors import VulnerabilityNotFound
from itertools import chain


def _clean(item):
    return {key: value for key, value in item.__dict__.items() if key[0] != "_"}


class Model:

    def __init__(self, **kwargs):
        self.init(**kwargs)
        self._dirty = False

    def __eq__(self, other):
        # Skip internal properties (such as _dirty) on equality checks

        return _clean(self) == _clean(other)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "{name}({content})".format(name=self.__class__.__name__,
                                          content=str(_clean(self))[1:-1])

    def __setattr__(self, attr, value):
        # Not fully initalized yet, let anything happen
        if not hasattr(self, '_dirty'):
            super().__setattr__(attr, value)
            return

        # If the attribute is not declared after initialization, we don't want it
        if not hasattr(self, attr):
            raise AttributeError(attr)

        # If the value is different, change it and flag dirty
        if getattr(self, attr) != value:
            super().__setattr__(attr, value)
            super().__setattr__('_dirty', True)

    def clean(self):
        super().__setattr__('_dirty', False)
        for c in self.children:
            c.clean()

    @property
    def dirty(self):
        return self._dirty or any(c.dirty for c in self.children)

    @property
    def children(self):
        return []


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

    def add_affected_versions(self, range):
        if any(v.fixed_in == range.fixed_in or v.introduced_in == range.introduced_in for v in self.affected_versions):
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
