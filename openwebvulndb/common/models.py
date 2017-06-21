# openwebvulndb-tools: A collection of tools to maintain vulnerability databases
# Copyright (C) 2016-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from .errors import VulnerabilityNotFound, VersionNotFound
from .basemodel import Model
from .version import parse
from itertools import chain


class Meta(Model):

    def init(self, *, key, name=None, url=None, repositories=None, is_popular=None, cpe_names=None, hints=None):
        self.key = key
        self.name = name
        self.cpe_names = cpe_names
        self.url = url
        self.is_popular = is_popular
        self.repositories = repositories or []
        self.hints = hints or []


class MetaList(Model):
    def init(self, *, key, metas=None):
        self.key = key
        self.metas = metas or []

    def get_meta(self, key):
        for meta in self.metas:
            if meta.key == key:
                return meta
        return None


class Repository(Model):

    def init(self, *, type, location):
        self.type = type
        self.location = location


class VulnerabilityListGroup(Model):

    def init(self, *, producer, vulnerability_lists=None):
        self.producer = producer
        self.vulnerability_lists = vulnerability_lists or []


class VulnerabilityList(Model):

    def init(self, *, producer, key, vulnerabilities=None, license=None, copyright=None):
        self.producer = producer
        self.key = key
        self.copyright = copyright
        self.license = license
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
             references=None, affected_versions=None, unaffected_versions=None, description=None, cvss=None):
        self.id = id
        self.title = title
        self.cvss = cvss
        self.description = description
        self.reported_type = reported_type
        self.updated_at = updated_at
        self.created_at = created_at
        self.references = references or []
        self.affected_versions = affected_versions or []
        self.unaffected_versions = unaffected_versions or []

    def add_affected_version(self, range):
        if range.fixed_in is None and range.introduced_in is None:
            return

        if range.introduced_in is not None and any(u.contains(range.introduced_in) for u in self.unaffected_versions):
            return
        if range.fixed_in is not None and any(u.contains(range.fixed_in) for u in self.unaffected_versions):
            return

        # Check direct matches
        if range.fixed_in is not None \
           and any(v.fixed_in == range.fixed_in for v in self.affected_versions):
            return
        if range.introduced_in is not None and range.fixed_in is None \
           and self._applies_to_explicit(range.introduced_in):
            return

        # Check conflicting information
        if range.fixed_in is not None and range.introduced_in is None \
           and self._applies_to_explicit(range.fixed_in):
            return

        self.affected_versions.append(range)

    def add_unaffected_version(self, range):
        self.unaffected_versions.append(range)

    def applies_to(self, version):
        # An applicable range means the vulnerability is applicable
        # No ranges at all also means the vulnerablity is applicable
        return len(self.affected_versions) == 0 or self._applies_to_explicit(version)

    def _applies_to_explicit(self, version):
        # Determines if a range is explicitly making this vulnerability applicable
        for r in self.affected_versions:
            if r.contains(version):
                return True

        return False

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


class FileListGroup(Model):

    def init(self, *, key, producer, file_lists=None):
        self.key = key
        self.producer = producer
        self.file_lists = file_lists or []


class FileList(Model):

    def init(self, *, producer, key, hash_algo="SHA256", files=None):
        self.producer = producer
        self.key = key
        self.hash_algo = hash_algo
        self.files = files or []


class File(Model):

    def init(self, *, path, signatures=None):
        self.path = path
        self.signatures = signatures or []

    def get_signature(self, hash, *, create_missing=False):
        for signature in self.signatures:
            if signature.hash == hash:
                return signature
        if create_missing:
            signature = FileSignature(hash=hash)
            self.signatures.append(signature)
            return signature
        return None


class FileSignature(Model):

    def init(self, *, hash, versions=None):
        self.hash = hash
        self.versions = versions or []
