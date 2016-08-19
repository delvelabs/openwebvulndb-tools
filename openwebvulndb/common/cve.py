import re
import json


match_svn = re.compile(r'https?://(plugins|themes)\.svn\.wordpress\.org/([^/]+)')
match_website = re.compile(r'https?://(?:www\.)?wordpress\.org(?:/extend)?/(plugins|themes)/([^/]+)')

match_cpe = re.compile(r':a:(?P<vendor>[^:]+):(?P<product>[^:]+)(?::(?P<version>[^:]+))?')


class CVEReader:

    def __init__(self, *, storage):
        self.groups = []
        self.storage = storage
        self.known_entries = False

    def read_file(self, file_name):
        with open(file_name, "r") as fp:
            return json.load(fp)

    def identify_target(self, data):
        for cpe in data.get("vulnerable_configuration", []):
            if ":a:wordpress:wordpress:" in cpe:
                # Full: cpe:2.3:a:wordpress:wordpress:4.4.3
                # Rationale: if it targets a specific version, it's wordpress
                return "wordpress"

        for cpe in data.get("vulnerable_configuration", []):
            if ":a:wordpress:wordpress_mu:" in cpe:
                # Full: cpe:2.3:a:wordpress:wordpress:4.4.3
                # Rationale: if it targets a specific version, it's wordpress
                return "mu"

        for url in data.get('references', []):
            match = self.identify_from_url(url)
            if match is not None:
                return match

        if self.known_entries is False:
            self.known_entries = {"{g}/{n}".format(g=g, n=n)
                                  for g in self.groups
                                  for n in self.storage.list_directories(g)}
            self.known_entries = self.known_entries - {"{g}/{n}".format(g=g, n="wordpress")
                                                       for g in self.groups}

        for has_version, candidate in self.enumerate_candidates(data.get("vulnerable_configuration", [])):
            if candidate in self.known_entries:
                return candidate

    def identify_from_url(self, url):
        match = match_svn.search(url) or match_website.search(url)
        if match:
            return "{group}/{name}".format(group=match.group(1), name=match.group(2))

    def enumerate_candidates(self, cpe_list):
        for entry in cpe_list:
            res = match_cpe.search(entry)

            has_version = res.group('version') is not None

            if res is None:
                continue

            vendor = res.group('vendor').replace("_", "-")
            product = res.group('product').replace("_", "-")
            if product.endswith("-plugin"):
                product = product[0:-len("-plugin")]

            for g in self.groups:
                yield has_version, "{group}/{product}".format(group=g, vendor=vendor, product=product)
                yield has_version, "{group}/{vendor}-{product}".format(group=g, vendor=vendor, product=product)
