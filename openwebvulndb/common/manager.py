from collections import defaultdict

from .models import VulnerabilityList, Reference


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

    def _create_producer_list(self, key, producer):
        try:
            return self.storage.read_vulnerabilities(key=key, producer=producer)
        except FileNotFoundError:
            return VulnerabilityList(producer=producer, key=key)


class ReferenceManager:

    def __init__(self):
        self.references = None

    @classmethod
    def for_list(cls, references):
        manager = cls()
        manager.references = references
        return manager

    def include_cve(self, cve):
        try:
            return next(x for x in self.references if x.type == "cve" and x.id == cve)
        except StopIteration:
            ref = Reference()
            ref.type = "cve"
            ref.id = cve
            ref.url = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-%s" % id
            self.references.append(ref)
            return ref

    def include_osvdb(self, osvdb_id):
        try:
            return next(x for x in self.references if x.type == "osvdb" and x.id == osvdb_id)
        except StopIteration:
            ref = Reference()
            ref.type = "osvdb"
            ref.id = osvdb_id
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
