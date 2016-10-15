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
        file = open(file_name, 'r')
        data = json.load(file)
        for entry in data:
            self.read_one(entry)

    def read_api(self, url):
        pass

    def read_one(self, entry):
        target = self.identify_target(entry)
        if target is None:
            logger.info("No suitable target found for %s.", entry)
            return
        this_ref = Reference(type="bugtraqid", id=entry['id'])
        try:
            v = self.vulnerability_manager.find_vulnerability(target, match_reference=this_ref)
        except VulnerabilityNotFound:
            producer = self.vulnerability_manager.get_producer_list("security-focus", target)
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
        ref_manager.include_normalized("bugtraqid", entry['info_parser'].get_bugtraq_id())
        for cve in entry['info_parser'].get_cve_id():
            ref_manager.include_normalized("cve", cve[4:])  # Remove the "CVE-" and the beginning of the cve id string
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

    def _identify_from_title(self, entry):
        if self._is_plugin(entry):
            return self._get_plugin_name(entry)
        if self._is_wordpress(entry):
            return "wordpress"

    def _is_plugin(self, entry):
        match = re.search("Word[Pp]ress [\w\s-]* Plugin", entry['info_parser'].get_title())
        if match is None or len(match.group()) == 0:
            return False
        else:
            return True

    def _is_wordpress(self, entry):
        match = re.search("([Pp]lugin[s?]|[Tt]heme[s?])", entry['info_parser'].get_title())
        if match is None:
            match = re.search("WordPress", entry['info_parser'].get_title())
            if match is not None:
                if len(match.group()) != 0:
                    return True
        return False

    def _get_plugin_name(self, entry):
        match = re.search("Word[Pp]ress [\w\s-]* Plugin", entry['info_parser'].get_title())
        if len(match.group()) != 0:
            plugin_name = (match.group())
            plugin_name = re.sub("WordPress ", '', plugin_name)
            plugin_name = re.sub(" Plugin", '', plugin_name)
            plugin_name = re.sub(" ", '-', plugin_name)  # replace spaces with '-'.
            plugin_name = plugin_name.lower()
            return "plugins/" + plugin_name
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
