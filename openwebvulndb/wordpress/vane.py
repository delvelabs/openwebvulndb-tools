from openwebvulndb.common.manager import ReferenceManager
from datetime import datetime
import json


class VaneImporter:

    def __init__(self, *, vulnerability_manager):
        self.manager = vulnerability_manager
        self.reference_manager = ReferenceManager()
        self.files = {}

    def get_list(self, *args):
        return self.manager.get_producer_list("VaneImporter", *args)

    def load_plugins(self, data_file_path):
        for key, data in self.iterate(data_file_path):
            vl = self.get_list("plugins", key)

            for vuln_data in data["vulnerabilities"]:
                vuln = vl.get_vulnerability(vuln_data["id"], create_missing=True)
                self.apply_data(vuln, vuln_data)

    def iterate(self, data_file_path):
        with open(data_file_path, 'r') as fp:
            data_file = json.load(fp)
            for entry in data_file:
                for key, vuln_data in entry.items():
                    yield key, vuln_data

    def apply_data(self, vuln, vuln_data):
        if "title" in vuln_data:
            vuln.title = vuln_data["title"]

        if "updated_at" in vuln_data:
            vuln.updated_at = self.parse_date(vuln_data["updated_at"])
        if "created_at" in vuln_data:
            vuln.created_at = self.parse_date(vuln_data["created_at"])

        ref_manager = self.reference_manager.for_list(vuln.references)

        for normalized in self.reference_manager.normalized_sources:
            for id in self.values_for(vuln_data, normalized):
                ref_manager.include_normalized(normalized, id)

        for url in self.values_for(vuln_data, "url"):
            ref_manager.include_url(url)

    @staticmethod
    def values_for(vuln_data, key):
        if key in vuln_data:
            for v in vuln_data[key]:
                yield v

    def parse_date(self, data):
        return datetime.strptime(data, "%Y-%m-%dT%H:%M:%S.%fZ")
