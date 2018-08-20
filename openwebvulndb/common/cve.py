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

import re
import json
from datetime import datetime, timedelta
from collections import OrderedDict

from .logs import logger
from .models import Reference, VersionRange
from .manager import ReferenceManager
from .errors import VulnerabilityNotFound
from .version import VersionCompare


match_version_in_summary = re.compile(r'(?:(?:before |and )?(?P<intro>\d[\d\.]*)\.x )?before (?P<fix>\d[\d\.]+)(, )?')
match_standalone_version = re.compile(r'(?P<pre>[^\w])(?:possibly )?(?:in )?(?P<intro>\d[\d\.]*)\.[x\d]*(?:,? and (?:possibly )?earlier)? ?')
match_different_vector = re.compile(r',? (a )?(different|similar|related) (vulnerability|vector|vectors|issue) (than|to) CVE-\d+-\d+\.?')
match_spaces = re.compile(r'(\s\s+|,\s+,\s+)')

match_svn = re.compile(r'https?://(plugins|themes)\.svn\.wordpress\.org/([^/]+)')
match_website = re.compile(r'https?://(?:www\.)?wordpress\.org(?:/extend)?/(plugins|themes)/([^/]+)')

match_cpe = re.compile(r':a:(?P<vendor>[^:]+):(?P<product>[^:]+)(?::(?P<version>[^-][^:]+))?')

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
DATE_FORMAT_NO_MICROSECONDS = "%Y-%m-%dT%H:%M:%S"
microseconds_in_datetime = re.compile("\.\d{3}")
timezone_in_datetime = re.compile("(\+|-)\d\d:\d\d$")


class CVEReader:

    def __init__(self, *, storage, vulnerability_manager=None, aiohttp_session=None):
        self.session = aiohttp_session

        self.groups = []
        self.storage = storage
        self.known_entries = False
        self.vulnerability_manager = vulnerability_manager

        self.cpe_mapper = CPEMapper(storage=storage)
        self.range_guesser = RangeGuesser(storage=storage)
        self.reference_manager = ReferenceManager()

    def load_mapping(self, *args, **kwargs):
        self.cpe_mapper.load(*args, **kwargs)

    def read_file(self, file_name):
        with open(file_name, "r") as fp:
            data = json.load(fp)
            for entry in data:
                self.read_one(entry)

    async def read_api(self, url):
        async with self.session.get(url) as response:
            data = await response.json()
            for entry in data:
                self.read_one(entry)

    async def read_one_from_api(self, cve_id):
        try:
            url = "https://cve.circl.lu/api/cve/" + cve_id
            async with self.session.get(url) as response:
                entry = await response.json()
                if entry is None:
                    logger.info("No entry found for %s" % cve_id)
                    return
                self._convert_vulnerable_configuration(entry)
                self.read_one(entry)
        except Exception as e:
            logger.warn("Error fetching %s: %s", cve_id, e)

    def read_one(self, entry):
        target = self.identify_target(entry)
        if target is None:
            logger.info("No suitable target found for %s", entry["id"])
            return

        this_ref = Reference(type="cve", id=entry["id"][4:])
        try:
            v = self.vulnerability_manager.find_vulnerability(target, match_reference=this_ref)
        except VulnerabilityNotFound:
            producer = self.vulnerability_manager.get_producer_list("CVEReader", target)
            v = producer.get_vulnerability(entry["id"], create_missing=True)

        last_modified = self._get_last_modified(entry)
        updated_at = v.updated_at.replace(tzinfo=None) if v.updated_at else None
        allow_override = last_modified is None or updated_at is None or last_modified > updated_at

        self.range_guesser.load(target)
        self.apply_data(v, entry, allow_override=allow_override)

        self.vulnerability_manager.flush()
        return v

    def apply_data(self, vuln, entry, allow_override=False):
        def apply_value(field, value):
            if allow_override or getattr(vuln, field) is None:
                setattr(vuln, field, value)

        if vuln.title is None:
            apply_value("title", entry.get("summary"))

        apply_value("description", entry.get("summary"))
        apply_value("cvss", entry.get("cvss"))

        if vuln.title == vuln.description:
            vuln.title = self.summarize(vuln.description)

        if vuln.reported_type is None or vuln.reported_type.lower() == "unknown":
            if entry.get("cwe") is not None:
                vuln.reported_type = entry.get("cwe")

        dates = [x for x in [vuln.updated_at.replace(tzinfo=None) if vuln.updated_at else None,
                             self._get_last_modified(entry)] if x is not None]
        if len(dates):
            vuln.updated_at = max(dates)

        ref_manager = self.reference_manager.for_list(vuln.references)
        ref_manager.include_normalized("cve", entry["id"][4:])

        for url in entry.get('references', []):
            ref_manager.include_url(url)

        for range in self.range_guesser.guess(vuln.description, entry.get('vulnerable_configuration', [])):
            vuln.add_affected_version(range)

    def identify_target(self, data):
        if "id" in data:
            from_id = self.cpe_mapper.lookup_id(data["id"])
            if from_id is not None:
                return from_id

        vuln_configurations = data.get("vulnerable_configuration", [])

        # If we have a known CPE with a version specified in the configuration, it applies
        for cpe in vuln_configurations:
            key = self.cpe_mapper.lookup_cpe(cpe)
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
            values = [self.cpe_mapper.lookup_cpe(cpe, ignore_version=True) for cpe in vuln_configurations]
            valid = [(10 - v.count("/"), v) for v in values if v is not None]

            # All CPE names must be known for this to apply, otherwise we always fall-back to the platform
            if len(values) == len(valid) and len(valid) > 0:
                # Prioritize the nested groups as they are more specific than the platform
                return next(iter(x for _, x in sorted(valid)))

        # if nothing has been found, attempt to find an existing vulnerability with a reference to the cve number.
        return self.identify_from_cve(data)

    def identify_from_url(self, url):
        match = match_svn.search(url) or match_website.search(url)
        if match:
            return "{group}/{name}".format(group=match.group(1), name=match.group(2))

    def identify_from_cve(self, entry):
        if "id" in entry:
            reference = Reference(type="cve", id=entry["id"][4:])
            keys = self.known_entries | {"wordpress"}
            for key in keys:
                try:
                    self.vulnerability_manager.find_vulnerability(key, match_reference=reference)
                    return key
                except VulnerabilityNotFound:
                    pass
        return None

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
        for field in ["last-modified", "Modified"]:
            string = entry.get(field)
            if string is not None:
                return self.parse_datetime(string)

    @staticmethod
    def parse_datetime(string):
        if timezone_in_datetime.search(string):
            string = string[0:-6]  # Strip the timezone, it's horrible to deal with
        if microseconds_in_datetime.search(string):
            parsed = datetime.strptime(string, DATE_FORMAT).replace(tzinfo=None)
        else:
            parsed = datetime.strptime(string, DATE_FORMAT_NO_MICROSECONDS).replace(tzinfo=None)
        return parsed - timedelta(microseconds=parsed.microsecond)

    @staticmethod
    def summarize(summary):
        summary = match_different_vector.sub("", summary)
        summary = match_version_in_summary.sub("", summary)
        summary = match_standalone_version.sub("\g<pre>", summary)
        summary = match_spaces.sub(" ", summary)
        summary = summary.strip(".")
        period = summary.find(". ")

        if period > 0:
            if len(summary) >= period:
                if summary[period] == "." and summary[period - 1] == ".":
                    return summary
                else:
                    return summary[0:period]
        else:
            return summary
        return summary[0:period] if period > 0 else summary

    def _convert_vulnerable_configuration(self, entry):
        """When fetching a single cve entry from the cve api, the vulnerable configuration is a list of dict instead of
         a list of string."""
        try:
            vulnerable_configuration = entry["vulnerable_configuration"]
            entry["vulnerable_configuration"] = []
            for config in vulnerable_configuration:
                if isinstance(config, dict):
                    entry["vulnerable_configuration"].append(config["id"])
                elif isinstance(config, str):
                    entry["vulnerable_configuration"].append(config)
        except KeyError:
            pass


class CPEMapper:

    def __init__(self, *, storage):
        self.storage = storage
        self.rules = OrderedDict()
        self.hints = dict()
        self.loaded = False

    def load(self, cpe_mapping={}, hint_mapping={}):
        def _load(mapping, output, message):
            for k, v in mapping.items():
                if k in output:
                    raise KeyError(k, message)
                else:
                    output[k] = v

        self.loaded = True
        _load(cpe_mapping, self.rules, "CPE already defined")
        _load(hint_mapping, self.hints, "Hint already defined")

    def load_meta(self, meta):
        self.load({cpe: meta.key for cpe in meta.cpe_names or []},
                  {ref.id: meta.key for ref in meta.hints or [] if ref.id is not None and ref.type == "cve"})

    def lookup_cpe(self, cpe, *, ignore_version=False):
        if not self.loaded:
            self.load_from_storage()

        for k, v in self.rules.items():
            if ignore_version and cpe == k:
                return v
            elif cpe.startswith(k + ":"):
                return v

    def lookup_id(self, id):
        if id.startswith("CVE-"):
            id = id[4:]

        if id in self.hints:
            return self.hints[id]

    def load_from_storage(self):
        logger.info("Loading CPE mapping.")
        for meta in self.storage.list_meta():
            self.load_meta(meta)
        logger.info("CPE Mapping loaded.")


class RangeGuesser:
    def __init__(self, *, storage):
        self.known_versions = []
        self.storage = storage
        self.cache = dict()

    def load(self, key):
        try:
            if key not in self.cache:
                vlist = self.storage.read_versions(key)
                self.cache[key] = [v.version for v in vlist.versions]
        except FileNotFoundError:
            self.cache[key] = []
        finally:
            self.known_versions = self.cache[key]

    def guess(self, summary, configurations):
        matches = list(match_version_in_summary.finditer(summary))
        for v in matches:
            yield VersionRange(introduced_in=v.group('intro'), fixed_in=v.group('fix'))

        if len(matches) > 0:
            return

        def filter_bad_versions(versions):
            return [p.group('version') for p in versions if p is not None and p.group('version') is not None]

        versions = filter_bad_versions([match_cpe.search(v) for v in configurations])
        versions = VersionCompare.sorted(versions)

        if len(versions) == 0:
            return

        next_revision = VersionCompare.next_revision(versions[-1])
        next_minor = VersionCompare.next_minor(versions[-1])
        if next_revision in self.known_versions:
            yield VersionRange(fixed_in=next_revision)
        elif next_minor in self.known_versions:
            yield VersionRange(fixed_in=next_minor)
