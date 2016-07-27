from collections import defaultdict

from .models import VulnerabilityList


class VulnerabilityManager:

    def __init__(self, *, storage):
        self.storage = storage
        self.files = defaultdict(dict)

    def get_producer_list(self, producer, *args):
        key = "/".join(args)

        if key not in self.files[producer]:
            self.files[producer][key] = VulnerabilityList(producer=producer, key=key)

        return self.files[producer][key]
