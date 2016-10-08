import json
import re
from openwebvulndb.common.logs import logger
from openwebvulndb.common.models import Reference
from openwebvulndb.common.errors import VulnerabilityNotFound
from openwebvulndb.common.cve import CPEMapper
from openwebvulndb.common.manager import VulnerabilityManager, ReferenceManager

match_svn = re.compile(r'https?://(plugins|themes)\.svn\.wordpress\.org/([^/]+)')
match_website = re.compile(r'https?://(?:www\.)?wordpress\.org(?:/extend)?/(plugins|themes)/([^/]+)')


class SecurityFocusReader:

    def __init__(self, storage, vulnerability_manager=None, aiohttp_session=None):
        self.storage = storage
        self.vulnerability_manager = VulnerabilityManager(storage=storage)
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
        this_ref = Reference(type="Bugtraq-ID", id=entry['id'])
        try:
            v = self.vulnerability_manager.find_vulnerability(target, match_reference=this_ref)
        except VulnerabilityNotFound:
            producer = self.vulnerability_manager.get_producer_list("security-focus", target)
            v = producer.get_vulnerability(entry['id'], create_missing=True)
        #last_modified = self._get_last_modified(entry)
        #updated_at = v.updated_at.replace(tzinfo=None) if v.updated_at else None
        #allow_override = last_modified is None or updated_at is None or last_modified > updated_at
        allow_override = True
        #self.range_guesser.load(target)
        self.apply_data(v, entry, allow_override=allow_override)

        self.vulnerability_manager.flush()
        return v

    def apply_data(self, vuln, entry, allow_override=False):
        def apply_value(field, value):
            if allow_override or getattr(vuln, field) is None:
                setattr(vuln, field, value)

        if vuln.title is None:
            apply_value("title", entry['info_parser'].get_title())

        if vuln.reported_type is None or vuln.reported_type.lower() == "unknown":
            vuln.reported_type = entry['info_parser'].get_vuln_class()

        ref_manager = self.reference_manager.for_list(vuln.references)
        ref_manager.include_normalized("Bugtraq-ID", entry['info_parser'].get_bugtraq_id())

    def identify_target(self, entry):
        print(entry['info_parser'].get_cve_id())
        if entry['info_parser'].get_cve_id() is not None:
            from_cve = self.cpe_mapper.lookup_id(entry['info_parser'].get_cve_id())
            if from_cve is not None:
                return from_cve
        #from_url = self._identify_from_url(entry['references_parser'])  # skip it because no reference tab is provided during the test.
        #if from_url is not None:
            #return from_url
        return self._identify_from_name(entry)

    def _identify_from_url(self, references_parser):
        for reference in references_parser.get_references():
            url = reference[1]
            match = match_svn.search(url) or match_website.search(url)
            if match:
                return "{group}/{name}".format(group=match.group(1), name=match.group(2))

    def _identify_from_name(self, entry):
        if self._is_plugin(entry):
            return self._get_plugin_name(entry)

    def _is_plugin(self, entry):
        match = re.search("WordPress [\w\s]* Plugin", entry['info_parser'].get_title())
        if len(match.group()) == 0:
            return False
        else:
            return True

    def _get_plugin_name(self, entry):
        match = re.search("WordPress [\w\s]* Plugin", entry['info_parser'].get_title())
        if len(match.group()) != 0:
            plugin_name = (match.group())
            plugin_name = re.sub("WordPress ", '', plugin_name)
            plugin_name = re.sub(" Plugin", '', plugin_name)
            plugin_name = re.sub(" ", '-', plugin_name)  # replace spaces with '-'.
            plugin_name = plugin_name.lower()
            print(plugin_name)
            return "plugins/" + plugin_name
        return None
