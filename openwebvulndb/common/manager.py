from collections import defaultdict

from .models import VulnerabilityList


class VulnerabilityManager:

    def __init__(self, *, storage):
        self.storage = storage
        self.files = defaultdict(dict)

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
