import json
import re
from openwebvulndb.common.logs import logger
from openwebvulndb.common.models import Reference, VersionRange
from openwebvulndb.common.errors import VulnerabilityNotFound
from openwebvulndb.common.cve import CPEMapper
from openwebvulndb.common.manager import VulnerabilityManager, ReferenceManager

match_svn = re.compile(r'https?://(plugins|themes)\.svn\.wordpress\.org/([^/]+)')
match_website = re.compile(r'https?://(?:www\.)?wordpress\.org(?:/extend)?/(plugins|themes)/([^/]+)')


class SecurityFocusReader:

    def __init__(self, storage, vulnerability_manager=None, aiohttp_session=None):
        self.storage = storage
        if vulnerability_manager is None:
            self.vulnerability_manager = VulnerabilityManager(storage=storage)
        else:
            self.vulnerability_manager = vulnerability_manager
        self.aiohttp_session = aiohttp_session
        self.cpe_mapper = CPEMapper(storage=storage)
        self.reference_manager = ReferenceManager()

    def read_file(self, file_name):
        with open(file_name, 'r') as file:
            data = json.load(file)
            for entry in data:
                self.read_one(entry)

    #todo
    def read_api(self, url):
        pass

    def read_one(self, entry):
        target = self.identify_target(entry)
        if target is None:
            logger.info("No suitable target found for %s.", entry["id"])
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

        if vuln.title is None or allow_override:
            apply_value("title", entry['info_parser'].get_title())

        if vuln.reported_type is None or vuln.reported_type.lower() == "unknown" or allow_override:
            vuln.reported_type = entry['info_parser'].get_vuln_class()

        apply_value('updated_at', self._get_last_modified(entry))
        apply_value('created_at', entry['info_parser'].get_publication_date())
        fixed_in = self._get_fixed_in(entry)
        if fixed_in is not None:
            version_range = VersionRange(fixed_in=fixed_in)
            vuln.add_affected_version(version_range)

        ref_manager = self.reference_manager.for_list(vuln.references)
        self._add_bugtraqid_reference(ref_manager, entry["id"])
        for cve in entry['info_parser'].get_cve_id():
            ref_manager.include_normalized("cve", cve[4:])  # Remove the "CVE-" at the beginning of the cve id string
        for reference in entry['references_parser'].get_references():
            ref_manager.include_url(reference["url"])

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

    #todo add plugin existence validation
    #todo add theme identification
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
            logger.debug(plugin_name)
            if plugin_name in self.storage.list_directories("plugins"):
                return "plugins/" + plugin_name
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
        return None

    def _get_last_modified(self, entry):
        return entry['info_parser'].get_last_update_date()

    def _get_fixed_in(self, entry):
        # TODO if more than one not vulnerable version, find the older one and return it as the fixed_in.
        if len(entry['info_parser'].get_not_vulnerable_versions()) == 0:
            return None
        version_str = entry['info_parser'].get_not_vulnerable_versions()[0]
        if version_str is not None:
            version = re.sub("WordPress (\D)*", '', version_str)
            return version
        else:
            return None

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
        if len(entry["info_parser"].get_cve_id()) != 0:
            cve_id = entry["info_parser"].get_cve_id()[0][4:]  # Remove the "CVE-" before the id.
            possible_references.append(Reference(type="cve", id=cve_id))
        possible_references.append(Reference(type="bugtraqid", id=entry["id"]))
        return possible_references

    def _add_bugtraqid_reference(self, references_manager, bugtraq_id):
        """Add the bugtraq id to the references of a vuln. If a security focus url is already in the references, replace it with the bugtraqid."""
        for ref in references_manager.references:
            if ref.type == "other" and ref.url is not None and "securityfocus" in ref.url:
                ref.type = "bugtraqid"
                ref.id = bugtraq_id
                ref.url = None
                return
        references_manager.include_normalized(type="bugtraqid", id=bugtraq_id)