from .errors import VulnerabilityNotFound, VersionNotFound
from .basemodel import Model
from .version import parse
from itertools import chain


class Meta(Model):

    def init(self, *, key, name=None, url=None, repositories=None, is_popular=None, cpe_names=None):
        self.key = key
        self.name = name
        self.cpe_names = cpe_names
        self.url = url
        self.is_popular = is_popular
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
             references=None, affected_versions=None, description=None, cvss=None):
        self.id = id
        self.title = title
        self.cvss = cvss
        self.description = description
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

    def applies_to(self, version):
        for r in self.affected_versions:
            if r.contains(version):
                return True

        return len(self.affected_versions) == 0

    def matches(self, match_reference=None):
        outcomes = []
        if match_reference is not None:
            outcomes.append(any(ref.matches(match_reference) for ref in self.references))

        return all(outcomes)

    @property
    def children(self):
        return chain(self.references, self.affected_versions)


class Reference(Model):

    def init(self, *, type=None, id=None, url=None):
        self.type = type
        self.id = id
        self.url = url

    def matches(self, other):
        if self.type != other.type:
            return False

        if self.id is not None or other.id is not None:
            return self.id == other.id

        return self.url == other.url


class VersionRange(Model):
    def init(self, *, introduced_in=None, fixed_in=None):
        self.introduced_in = introduced_in
        self.fixed_in = fixed_in

    @property
    def introduced_in(self):
        return str(self._introduced_in) if self._introduced_in is not None else None

    @introduced_in.setter
    def introduced_in(self, val):
        self._introduced_in = None if val is None else parse(val)

    @property
    def fixed_in(self):
        return str(self._fixed_in) if self._fixed_in is not None else None

    @fixed_in.setter
    def fixed_in(self, val):
        self._fixed_in = None if val is None else parse(val)

    def contains(self, version):
        version = parse(version)
        return self._check_lower(version) and self._check_upper(version)

    def _check_lower(self, version):
        return self._introduced_in is None or version >= self._introduced_in

    def _check_upper(self, version):
        return self._fixed_in is None or version < self._fixed_in


class VersionList(Model):

    def init(self, *, producer, key, versions=None):
        self.producer = producer
        self.key = key
        self.versions = versions or []

    def get_version(self, version, *, create_missing=False):
        for v in self.versions:
            if v.version == version:
                return v

        if not create_missing:
            raise VersionNotFound(version)

        version = VersionDefinition(version=version)
        self.versions.append(version)
        return version

    @property
    def children(self):
        return self.versions


class VersionDefinition(Model):

    def init(self, *, version, signatures=None):
        self.version = version
        self.signatures = signatures or []

    def add_signature(self, path, hash, *, algo="SHA256", contains_version=None):
        self.signatures.append(Signature(path=path, hash=hash, algo=algo, contains_version=contains_version))

    @property
    def children(self):
        return self.signatures


class Signature(Model):

    def init(self, *, path, hash=None, algo="SHA256", contains_version=None):
        self.path = path
        self.algo = algo
        self.hash = hash
        self.contains_version = contains_version
