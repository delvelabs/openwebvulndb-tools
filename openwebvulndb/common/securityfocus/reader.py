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

import json
import re
from openwebvulndb.common.logs import logger
from openwebvulndb.common.models import Reference, VersionRange
from openwebvulndb.common.errors import VulnerabilityNotFound
from openwebvulndb.common.cve import CPEMapper
from openwebvulndb.common.manager import VulnerabilityManager, ReferenceManager
from openwebvulndb.common.version import parse
from statistics import median

match_svn = re.compile(r'https?://(plugins|themes)\.svn\.wordpress\.org/([^/]+)')
match_website = re.compile(r'https?://(?:www\.)?wordpress\.org(?:/extend)?/(plugins|themes)/([^/]+)')


class SecurityFocusReader:

    def __init__(self, storage, vulnerability_manager=None):
        self.storage = storage
        if vulnerability_manager is None:
            self.vulnerability_manager = VulnerabilityManager(storage=storage)
        else:
            self.vulnerability_manager = vulnerability_manager
        self.cpe_mapper = CPEMapper(storage=storage)
        self.meta_mapper = MetaMapper(storage)
        self.reference_manager = ReferenceManager()
        self.cvss_mapper = CvssMapper(storage)

    def read_file(self, file_name):
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                self.read_one(entry)

    def read_one(self, entry):
        target = self.identify_target(entry)
        if target is None:
            logger.info("No suitable target found for %s (%s).", entry["id"], entry["info_parser"].get_title())
            return
        v = self._get_existing_vulnerability(entry, target)
        if v is None:
            producer = self.vulnerability_manager.get_producer_list("securityfocus", target)
            v = producer.get_vulnerability(entry['id'], create_missing=True)
        last_modified = self._get_last_modified(entry)
        updated_at = v.updated_at.replace(tzinfo=None) if v.updated_at else None
        allow_override = last_modified is None or updated_at is None or last_modified > updated_at
        self.apply_data(v, entry, allow_override=allow_override)
        self.vulnerability_manager.flush()
        return v

    def apply_data(self, vuln, entry, allow_override=False):

        def apply_value(field, value):
            if allow_override or getattr(vuln, field) is None:
                setattr(vuln, field, value)

        # todo if title is not none check if title from securityfocus is better instead of doing blind override.
        if vuln.title is None or allow_override:
            if vuln.title != entry['info_parser'].get_title():
                vuln.title = entry['info_parser'].get_title()

        if entry['info_parser'].get_vuln_class() is not None:
            if vuln.reported_type is None or vuln.reported_type.lower() == "unknown":
                vuln.reported_type = entry['info_parser'].get_vuln_class()
            if vuln.cvss is None and len(entry["info_parser"].get_cve_id()) == 0:
                cvss = self.cvss_mapper.get_cvss_from_vulnerability_type(entry['info_parser'].get_vuln_class())
                if cvss is not None:
                    vuln.cvss = cvss

        apply_value('created_at', entry['info_parser'].get_publication_date())

        fixed_in = self._get_fixed_in(entry)
        if fixed_in is not None:
            version_range = VersionRange(fixed_in=fixed_in)
            if version_range not in vuln.affected_versions:
                vuln.add_affected_version(version_range)

        ref_manager = self.reference_manager.for_list(vuln.references)
        self._add_bugtraqid_reference(ref_manager, entry["id"])
        for cve in entry['info_parser'].get_cve_id():
            ref_manager.include_normalized("cve", cve[4:])  # Remove the "CVE-" at the beginning of the cve id string
        useful_references = self._remove_useless_references(entry['references_parser'].get_references())
        for reference in useful_references:
            ref_manager.include_url(reference["url"])

        if vuln.dirty:
            apply_value('updated_at', self._get_last_modified(entry))

    def identify_target(self, entry):
        from_url = self._identify_from_url(entry['references_parser'])
        if from_url is not None:
            return from_url
        return self._identify_from_title(entry)

    def _identify_from_url(self, references_parser):
        for reference in references_parser.get_references():
            url = reference["url"]
            match = match_svn.search(url) or match_website.search(url)
            if match:
                return "{group}/{name}".format(group=match.group(1), name=match.group(2))

    def _identify_from_title(self, entry):
        if self._is_plugin(entry):
            return self._get_plugin_name(entry)
        if self._is_theme(entry):
            return self._get_theme_name(entry)
        if self._is_wordpress(entry):
            return "wordpress"

    def _is_plugin(self, entry):
        match = re.search("[Ww]ord[Pp]ress [\w\s-]* [Pp]lugin", entry['info_parser'].get_title())
        if match is None or len(match.group()) == 0:
            return False
        else:
            return True

    def _is_theme(self, entry):
        match = re.search("[Ww]ord[Pp]ress [\w\s-]* [Tt]heme", entry['info_parser'].get_title())
        if match is None or len(match.group()) == 0:
            return False
        else:
            return True

    def _is_wordpress(self, entry):
        match = re.search("([Pp]lugin[s?]|[Tt]heme[s?])", entry['info_parser'].get_title())
        if match is None:
            match = re.search("^[Ww]ord[Pp]ress", entry['info_parser'].get_title())
            if match is not None:
                if len(match.group()) != 0:
                    return True
        return False

    def _get_plugin_name(self, entry):
        match = re.search("[Ww]ord[Pp]ress [\w\s-]* [Pp]lugin", entry['info_parser'].get_title())
        if len(match.group()) != 0:
            plugin_name = match.group()
            plugin_name = plugin_name.lower()
            plugin_name = re.sub("wordpress ", '', plugin_name)
            plugin_name = re.sub(" plugin", '', plugin_name)
            plugin_name = re.sub(" ", '-', plugin_name)  # replace spaces with '-'.
            if plugin_name in self.storage.list_directories("plugins"):
                return "plugins/" + plugin_name
            else:
                return self.meta_mapper.lookup_id(entry["id"])
        return None

    def _get_theme_name(self, entry):
        match = re.search("[Ww]ord[Pp]ress [\w\s-]* [Tt]heme", entry['info_parser'].get_title())
        if len(match.group()) != 0:
            theme_name = match.group()
            theme_name = theme_name.lower()
            theme_name = re.sub("wordpress ", '', theme_name)
            theme_name = re.sub(" theme", '', theme_name)
            theme_name = re.sub(" ", '-', theme_name)  # replace spaces with '-'.
            if theme_name in self.storage.list_directories("themes"):
                return "themes/" + theme_name
            else:
                return self.meta_mapper.lookup_id(entry["id"])
        return None

    def _get_last_modified(self, entry):
        return entry['info_parser'].get_last_update_date()

    def _get_fixed_in(self, entry):
        not_vuln_versions = entry['info_parser'].get_not_vulnerable_versions()
        if len(not_vuln_versions) == 0:
            return None
        elif len(not_vuln_versions) == 1:
            return self._strip_version(not_vuln_versions[0])
        else:  # If there is more than one fixed_in, return the lowest version:
            not_vuln_versions = [self._strip_version(version) for version in not_vuln_versions]
            not_vuln_parsed_versions = []
            for version in not_vuln_versions:
                not_vuln_parsed_versions.append(parse(version))
            for version in not_vuln_parsed_versions:
                if version < not_vuln_parsed_versions[0]:
                    not_vuln_parsed_versions[0] = version
            return str(not_vuln_parsed_versions[0])

    def _strip_version(self, version):
        return re.sub("WordPress (\D)*", '', version)

    def _get_existing_vulnerability(self, entry, target):
        for ref in self._get_possible_existing_references(entry):
            try:
                vuln = self.vulnerability_manager.find_vulnerability(target, match_reference=ref)
                return vuln
            except VulnerabilityNotFound:
                pass

    def _get_possible_existing_references(self, entry):
        possible_references = []
        securityfocus_url = "http://www.securityfocus.com/bid/{0}".format(entry["info_parser"].get_bugtraq_id())
        possible_references.append(Reference(type="other", url=securityfocus_url))
        for cve_id in entry["info_parser"].get_cve_id():
            cve_id = cve_id[4:]  # Remove the "CVE-" before the id.
            possible_references.append(Reference(type="cve", id=cve_id))
        possible_references.append(Reference(type="bugtraqid", id=entry["id"]))
        return possible_references

    def _add_bugtraqid_reference(self, references_manager, bugtraq_id):
        """Add the bugtraq id to the references of a vuln. If a security focus url is already in the references,
        replace it with the bugtraqid."""
        for ref in references_manager.references:
            if ref.type == "other" and ref.url is not None and references_manager.is_bugtraqid_url(ref.url):
                if bugtraq_id == self._get_bugtraq_id_from_url(ref.url):
                    self._replace_existing_securityfocus_reference_with_bugtraq_id(ref, bugtraq_id)
                    return
        references_manager.include_normalized(type="bugtraqid", id=bugtraq_id)

    def _replace_existing_securityfocus_reference_with_bugtraq_id(self, reference, bugtraq_id):
        reference.type = "bugtraqid"
        reference.id = bugtraq_id
        reference.url = None

    def _get_bugtraq_id_from_url(self, url):
        match = re.sub(r"http://www.securityfocus.com/bid/", "", url)
        return re.match("\d+", match).group()

    def _remove_useless_references(self, references_list):
        """Remove the useless references that the references tab of a vuln in the security focus db usually contains,
        like a link to wordpress/the plugin homepage."""
        useful_references = []
        for reference in references_list:
            url = reference["url"]
            if not (re.search(r"https?://((www|downloads)\.)?wordpress\.(com|org)/(?!(news|support))", url) or
                    match_website.search(url)):
                useful_references.append(reference)
        return useful_references


class MetaMapper:

    def __init__(self, storage):
        self.storage = storage
        self.hints = dict()
        self.loaded = False

    def load_meta(self, meta):
        hint_mapping = {ref.id: meta.key for ref in meta.hints or [] if ref.id is not None and ref.type == "bugtraqid"}
        for k, v in hint_mapping.items():
            if k in self.hints:
                raise KeyError(k, "Hint already defined")
            else:
                self.hints[k] = v
        self.loaded = True

    def lookup_id(self, id):
        if not self.loaded:
            self.load_from_storage()
        if id in self.hints:
            return self.hints[id]

    def load_from_storage(self):
        logger.info("Loading Meta mapping.")
        for meta in self.storage.list_meta():
            self.load_meta(meta)
        logger.info("Meta Mapping loaded.")


class CvssMapper:

    def __init__(self, storage):
        self.storage = storage
        self.cvss_map = {}
        self.loaded = False

    def load_cvss_mapping(self):
        types = {}
        for meta in self.storage.list_meta():
            for vuln_list in self.storage.list_vulnerabilities(meta.key):
                for vuln in vuln_list.vulnerabilities:
                    if vuln.reported_type is not None and vuln.reported_type.lower() != "unknown":
                        if not vuln.reported_type in types:
                            types[vuln.reported_type] = {"count": 0, "cvss": []}
                        types[vuln.reported_type]["count"] += 1
                        if vuln.cvss is not None:
                            types[vuln.reported_type]["cvss"].append(vuln.cvss)

        sorted_types = types.keys()
        for type in sorted_types:
            data = types[type]
            len_cvss = len(data["cvss"])
            if len_cvss > 5:  # Below 5 cvss, the cvss median is not really significant
                cvss_median = median(data["cvss"])
                self.cvss_map[type] = round(cvss_median, 1)

    def get_cvss_from_vulnerability_type(self, vulnerability_type):
        if not self.loaded:
            self.load_cvss_mapping()
            self.loaded = True
        if vulnerability_type in self.cvss_map.keys():
            return self.cvss_map[vulnerability_type]
        return None
