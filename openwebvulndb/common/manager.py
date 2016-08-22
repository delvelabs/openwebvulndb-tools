from collections import defaultdict

from .models import VulnerabilityList, Reference
from .errors import VulnerabilityNotFound


class VulnerabilityManager:

    def __init__(self, *, storage):
        self.storage = storage
        self.files = defaultdict(dict)

    def flush(self):
        for file_set in self.files.values():
            for vlist in file_set.values():
                if vlist.dirty:
                    self.storage.write_vulnerabilities(vlist)
                    vlist.clean()

    def get_producer_list(self, producer, *args):
        key = "/".join(args)

        if key not in self.files[producer]:
            self.files[producer][key] = self._create_producer_list(key, producer)

        return self.files[producer][key]

    def get_lists(self, *args):
        for vlist in self.storage.list_vulnerabilities("/".join(args)):
            if vlist.key not in self.files[vlist.producer]:
                self.files[vlist.producer][vlist.key] = vlist

            yield self.files[vlist.producer][vlist.key]

    def find_vulnerability(self, *args, **kwargs):
        for vlist in self.get_lists(*args):
            for vuln in vlist.vulnerabilities:
                if vuln.matches(**kwargs):
                    return vuln

        raise VulnerabilityNotFound()

    def _create_producer_list(self, key, producer):
        try:
            return self.storage.read_vulnerabilities(key=key, producer=producer)
        except FileNotFoundError:
            return VulnerabilityList(producer=producer, key=key)

    def filter_for_version(self, version, vulnerability_lists):
        for l in vulnerability_lists:
            for v in l.vulnerabilities:
                if v.applies_to(version):
                    yield v


class ReferenceManager:

    normalized_sources = ["cve", "exploitdb", "secunia", "metasploit", "osvdb"]

    def __init__(self):
        self.references = None

    @classmethod
    def for_list(cls, references):
        manager = cls()
        manager.references = references
        return manager

    def include_normalized(self, type, id):
        id = str(id)
        try:
            return next(x for x in self.references if x.type == type and x.id == id)
        except StopIteration:
            ref = Reference()
            ref.type = type
            ref.id = id
            if type == "cve":
                ref.url = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-%s" % id

            self.references.append(ref)
            return ref

    def include_url(self, url):
        try:
            return next(x for x in self.references if x.url == url)
        except StopIteration:
            ref = Reference()
            ref.type = "other"
            ref.url = url
            self.references.append(ref)
            return ref
