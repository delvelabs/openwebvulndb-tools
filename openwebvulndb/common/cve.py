import re
import json
from datetime import datetime
from collections import OrderedDict

from .logs import logger
from .models import Reference, VersionRange
from .manager import ReferenceManager
from .errors import VulnerabilityNotFound
from .version import VersionCompare


match_version_in_summary = re.compile(r'before (\d[\d\.]+)')

match_svn = re.compile(r'https?://(plugins|themes)\.svn\.wordpress\.org/([^/]+)')
match_website = re.compile(r'https?://(?:www\.)?wordpress\.org(?:/extend)?/(plugins|themes)/([^/]+)')

match_cpe = re.compile(r':a:(?P<vendor>[^:]+):(?P<product>[^:]+)(?::(?P<version>[^:]+))?')

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


class CVEReader:

    def __init__(self, *, storage, vulnerability_manager=None):
        self.groups = []
        self.storage = storage
        self.known_entries = False
        self.vulnerability_manager = vulnerability_manager

        self.cpe_mapper = CPEMapper(storage=storage)
        self.range_guesser = RangeGuesser(storage=storage)
        self.reference_manager = ReferenceManager()

    def load_mapping(self, mapping):
        self.cpe_mapper.load(mapping)

    def read_file(self, file_name):
        with open(file_name, "r") as fp:
            return json.load(fp)

    def read_one(self, entry):
        target = self.identify_target(entry)
        if target is None:
            logger.info("No suitable target found for %s", entry)
            return

        this_ref = Reference(type="cve", id=entry["id"][4:])
        try:
            v = self.vulnerability_manager.find_vulnerability(target, match_reference=this_ref)
        except VulnerabilityNotFound:
            producer = self.vulnerability_manager.get_producer_list("CVEReader", target)
            v = producer.get_vulnerability(entry["id"], create_missing=True)

        last_modified = self._get_last_modified(entry)

        if last_modified is None or v.updated_at is None or last_modified > v.updated_at:
            self.range_guesser.load(target)
            self.apply_data(v, entry)

        self.vulnerability_manager.flush()
        return v

    def apply_data(self, vuln, entry):
        if vuln.title is None:
            vuln.title = entry.get("summary")

        vuln.description = entry.get("summary")

        vuln.updated_at = self._get_last_modified(entry)

        ref_manager = self.reference_manager.for_list(vuln.references)
        ref_manager.include_normalized("cve", entry["id"][4:])

        for url in entry.get('references', []):
            ref_manager.include_url(url)

        for range in self.range_guesser.guess(vuln.description, entry.get('vulnerable_configuration', [])):
            vuln.add_affected_version(range)

    def identify_target(self, data):
        vuln_configurations = data.get("vulnerable_configuration", [])

        # If we have a known CPE with a version specified in the configuration, it applies
        for cpe in vuln_configurations:
            key = self.cpe_mapper.lookup(cpe)
            if key is not None:
                return key

        # Otherwise, search for accurate matches through the references
        for url in data.get('references', []):
            match = self.identify_from_url(url)
            if match is not None:
                return match

        # Attempt to guess the CPE name from the configurations and see if they match
        self.load_known_data()
        any_has_version = False
        for has_version, candidate in self.enumerate_candidates(data.get("vulnerable_configuration", [])):
            any_has_version = any_has_version or has_version
            if candidate in self.known_entries:
                return candidate

        # If none of the entries have specified versions, attempt to use the CPE names directly
        if not any_has_version:
            values = [self.cpe_mapper.lookup(cpe, ignore_version=True) for cpe in vuln_configurations]
            valid = [(10 - v.count("/"), v) for v in values if v is not None]

            # All CPE names must be known for this to apply, otherwise we always fall-back to the platform
            if len(values) == len(valid) and len(valid) > 0:
                # Prioritize the nested groups as they are more specific than the platform
                return next(iter(x for _, x in sorted(valid)))

    def identify_from_url(self, url):
        match = match_svn.search(url) or match_website.search(url)
        if match:
            return "{group}/{name}".format(group=match.group(1), name=match.group(2))

    def load_known_data(self):
        if self.known_entries is not False:
            return

        self.known_entries = {"{g}/{n}".format(g=g, n=n)
                              for g in self.groups
                              for n in self.storage.list_directories(g)}
        # There happens to be a theme called wordpress, we skip this one. Too many misdetections.
        self.known_entries = self.known_entries - {"{g}/{n}".format(g=g, n="wordpress")
                                                   for g in self.groups}

    def enumerate_candidates(self, cpe_list):
        for entry in cpe_list:
            res = match_cpe.search(entry)

            if res is None:
                logger.warn("CPE format unrecognized: %s", entry)
                continue

            has_version = res.group('version') is not None

            vendor = res.group('vendor').replace("_", "-")
            product = res.group('product').replace("_", "-")
            if product.endswith("-plugin"):
                product = product[0:-len("-plugin")]

            for g in self.groups:
                yield has_version, "{group}/{product}".format(group=g, vendor=vendor, product=product)
                yield has_version, "{group}/{vendor}-{product}".format(group=g, vendor=vendor, product=product)

    def _get_last_modified(self, entry):
        string = entry.get('last-modified')
        if string is None:
            return None

        string = string[0:-6]  # Strip the timezone, it's horrible to deal with

        return datetime.strptime(string, DATE_FORMAT)


class CPEMapper:

    def __init__(self, *, storage):
        self.storage = storage
        self.rules = OrderedDict()
        self.loaded = False

    def load(self, mapping):
        self.loaded = True
        for k, v in mapping.items():
            if k in self.rules:
                raise KeyError(k, "Item already defined")
            else:
                self.rules[k] = v

    def load_meta(self, meta):
        self.load({cpe: meta.key for cpe in meta.cpe_names or []})

    def lookup(self, cpe, *, ignore_version=False):
        if not self.loaded:
            self.load_from_storage()

        for k, v in self.rules.items():
            if ignore_version and cpe == k:
                return v
            elif cpe.startswith(k + ":"):
                return v

    def load_from_storage(self):
        logger.info("Loading CPE mapping.")
        for meta in self.storage.list_meta():
            self.load_meta(meta)
        logger.info("CPE Mapping loaded.")


class RangeGuesser:
    def __init__(self, *, storage):
        self.known_versions = []
        self.storage = storage

    def load(self, key):
        try:
            vlist = self.storage.read_versions(key)
            self.known_versions = [v.version for v in vlist.versions]
        except FileNotFoundError:
            self.known_versions = []

    def guess(self, summary, configurations):
        summary_fix = match_version_in_summary.search(summary)
        if summary_fix:
            yield VersionRange(fixed_in=summary_fix.group(1))

        versions = [match_cpe.search(v) for v in configurations]

        if len(versions) == 0:
            return

        versions = VersionCompare.sorted(p.group('version') for p in versions if p.group('version') is not None)
        next_minor = VersionCompare.next_minor(versions[-1])
        if next_minor in self.known_versions:
            yield VersionRange(fixed_in=next_minor)
