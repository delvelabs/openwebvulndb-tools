import unittest
from unittest.mock import MagicMock
from openwebvulndb.common.securityfocus.securityfocusparsers import InfoTabParser, ReferenceTabParser
from fixtures import file_path
from openwebvulndb.common.securityfocus.securityfocus import SecurityFocusReader
from openwebvulndb.common.storage import Storage
from openwebvulndb.common.manager import VulnerabilityManager
from openwebvulndb.common.errors import VulnerabilityNotFound
from openwebvulndb.common.models import VulnerabilityList, Vulnerability, Reference
from datetime import datetime
import json
import os
import re


class TargetIdentificationTest(unittest.TestCase):

    def setUp(self):
        self.storage = MagicMock()
        self.reader = SecurityFocusReader(self.storage)

    def test_identify_target_from_url(self):
        entry = dict()
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/73931/references_tab.html"))
        info_parser = MagicMock()
        get_cve_method = MagicMock(return_value=None)
        info_parser.attach_mock(get_cve_method, "get_cve_id")
        entry['info_parser'] = info_parser
        entry['references_parser'] = parser
        self.assertEqual(self.reader.identify_target(entry), "plugins/wassup")

    def test_identify_target_from_title(self):
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/73931/info_tab.html"))
        references_parser = MagicMock()
        get_references_function = MagicMock(return_value=list())
        references_parser.attach_mock(get_references_function, "get_references")
        entry = dict()
        entry['info_parser'] = info_parser
        entry['references_parser'] = references_parser
        self.assertEqual(self.reader.identify_target(entry), "plugins/wassup")

    def test_identify_target_fallback_to_wordpress(self):
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/92572/info_tab.html"))
        references_parser = MagicMock()
        get_references_function = MagicMock(return_value=list())
        references_parser.attach_mock(get_references_function, "get_references")
        entry = dict()
        entry['info_parser'] = info_parser
        entry['references_parser'] = references_parser
        self.assertEqual(self.reader.identify_target(entry), "wordpress")

    def test_no_suitable_target(self):
        info_parser = MagicMock()
        get_cve_id = MagicMock(return_value=None)
        get_title = MagicMock(return_value="Random title with no clear indication about a plugin name or wordpress")
        info_parser.attach_mock(get_cve_id, "get_cve_id")
        info_parser.attach_mock(get_title, "get_title")
        references_parser = MagicMock()
        get_references = MagicMock(return_value=list())
        references_parser.attach_mock(get_references, "get_references")
        entry=dict()
        entry["info_parser"] = info_parser
        entry["references_parser"] = references_parser
        self.assertEqual(self.reader.identify_target(entry), None)


class SecurityFocusReaderTest(unittest.TestCase):

    def setUp(self):
        self.storage = MagicMock()
        self.vulnerability_manager = MagicMock()
        self.reader = SecurityFocusReader(self.storage, self.vulnerability_manager)

    def test_add_plugin_vuln_to_database(self):
        bugtraq_id = "73931"
        entry = dict()
        entry['id'] = bugtraq_id
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
        entry['info_parser'] = info_parser
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry['references_parser'] = references_parser
        self.vulnerability_manager.find_vulnerability.side_effect = VulnerabilityNotFound()
        self.vulnerability_manager.get_producer_list.return_value = VulnerabilityList(producer="security-focus", key="plugins/wassup")
        vuln_entry = self.reader.read_one(entry)

        self.assertEqual(vuln_entry.id, bugtraq_id)
        self.assertEqual(vuln_entry.title, "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability")
        self.assertEqual(vuln_entry.reported_type, "Input Validation Error")
        self.assertEqual(vuln_entry.updated_at, datetime(2016, 9, 2, 20, 0))
        self.assertEqual(vuln_entry.created_at, datetime(2009, 12, 7, 0, 0))
        self.assertEqual(vuln_entry.affected_versions[0].fixed_in, "1.7.2.1")
        references = vuln_entry.references
        self.assertEqual(references[0].type, "bugtraqid")
        self.assertEqual(references[0].id, bugtraq_id)
        self.assertEqual(references[1].type, "other")
        self.assertEqual(references[1].url, "http://seclists.org/oss-sec/2015/q2/51")
        self.assertEqual(references[2].type, "other")
        self.assertEqual(references[2].url, "http://wordpress.org/extend/plugins/wassup/changelog/")
        self.assertEqual(references[3].type, "other")
        self.assertEqual(references[3].url, "http://wordpress.org/extend/plugins/wassup/")

    def test_add_vuln_to_database_allow_override(self):
        """Test if a more recent vuln entry allow to override an old one."""
        self.storage.reset_mock()
        bugtraq_id = "73931"
        previous_vuln_entry = Vulnerability(id=bugtraq_id, title="WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability",
                                            reported_type="Input Validation Error", created_at=datetime(2009, 12, 7, 0, 0),
                                            updated_at=datetime(2016, 9, 2, 20, 0), references=[Reference(type="bugtraqid", id=bugtraq_id)])
        self.storage.list_vulnerabilities.return_value = [VulnerabilityList(producer="security-focus", key="plugins/wassup",
                                                                            vulnerabilities=[previous_vuln_entry])]
        reader = SecurityFocusReader(self.storage)
        entry = dict()
        entry['id'] = bugtraq_id
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab_fake_update_date.html"))
        entry['info_parser'] = info_parser
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry['references_parser'] = references_parser
        vuln_entry = reader.read_one(entry)

        self.assertEqual(vuln_entry.id, bugtraq_id)
        self.assertEqual(vuln_entry.title, "WordPress WassUp Plugin 'main.php' Fake Title")
        self.assertEqual(vuln_entry.reported_type, "Random Vuln Class")
        self.assertEqual(vuln_entry.updated_at, datetime(2016, 9, 4, 20, 0))
        self.assertEqual(vuln_entry.created_at, datetime(2009, 12, 7, 0, 0))
        self.assertEqual(vuln_entry.affected_versions[0].fixed_in, "1.7.2.1")
        references = vuln_entry.references
        self.assertEqual(references[0].type, "bugtraqid")
        self.assertEqual(references[0].id, bugtraq_id)
        self.assertEqual(references[1].type, "other")
        self.assertEqual(references[1].url, "http://seclists.org/oss-sec/2015/q2/51")
        self.assertEqual(references[2].type, "other")
        self.assertEqual(references[2].url, "http://wordpress.org/extend/plugins/wassup/changelog/")
        self.assertEqual(references[3].type, "other")
        self.assertEqual(references[3].url, "http://wordpress.org/extend/plugins/wassup/")

    def test_add_vuln_to_database_no_override(self):
        """Test if a less recent vuln entry can't override a newer one, but can still add new references."""
        self.storage.reset_mock()
        bugtraq_id = "73931"
        previous_vuln_entry = Vulnerability(id=bugtraq_id,
                                            title="WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability",
                                            reported_type="Input Validation Error",
                                            created_at=datetime(2009, 12, 7, 0, 0),
                                            updated_at=datetime(2016, 9, 2, 20, 0),
                                            references=[Reference(type="bugtraqid", id=bugtraq_id)])
        self.storage.list_vulnerabilities.return_value = [VulnerabilityList(producer="security-focus", key="plugins/wassup", vulnerabilities=[previous_vuln_entry])]
        reader = SecurityFocusReader(self.storage)
        entry = dict()
        entry['id'] = bugtraq_id
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab_older_update_date.html"))
        entry['info_parser'] = info_parser
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry['references_parser'] = references_parser
        vuln_entry = reader.read_one(entry)

        self.assertEqual(vuln_entry.id, bugtraq_id)
        self.assertEqual(vuln_entry.title, "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability")
        self.assertEqual(vuln_entry.reported_type, "Input Validation Error")
        self.assertEqual(vuln_entry.updated_at, datetime(2016, 9, 2, 20, 0))
        self.assertEqual(vuln_entry.created_at, datetime(2009, 12, 7, 0, 0))
        self.assertEqual(vuln_entry.affected_versions[0].fixed_in, "1.7.2.1")
        references = vuln_entry.references
        self.assertEqual(references[0].type, "bugtraqid")
        self.assertEqual(references[0].id, bugtraq_id)
        self.assertEqual(references[1].type, "other")
        self.assertEqual(references[1].url, "http://seclists.org/oss-sec/2015/q2/51")
        self.assertEqual(references[2].type, "other")
        self.assertEqual(references[2].url, "http://wordpress.org/extend/plugins/wassup/changelog/")
        self.assertEqual(references[3].type, "other")
        self.assertEqual(references[3].url, "http://wordpress.org/extend/plugins/wassup/")

    def test_add_multiple_vulnerabilities_to_database(self):
        """Test the security focus reader with a lot of samples."""
        self.storage.reset_mock()
        self.storage.list_vulnerabilities.return_value = list()
        self.storage.read_vulnerabilities.side_effect = FileNotFoundError()
        reader = SecurityFocusReader(self.storage)
        bugtraq_id_list = ["73931", "82355", "91076", "91405", "92077", "92355", "92572", "92841", "93104"]
        for bugtraq_id in bugtraq_id_list:
            entry = dict()
            entry['id'] = bugtraq_id
            info_parser = InfoTabParser()
            info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
            entry['info_parser'] = info_parser
            references_parser = ReferenceTabParser()
            references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
            entry['references_parser'] = references_parser
            vuln_entry = reader.read_one(entry)

            self.assertEqual(vuln_entry.id, bugtraq_id)
            self.assertEqual(vuln_entry.title, info_parser.get_title())
            self.assertEqual(vuln_entry.reported_type, info_parser.get_vuln_class())
            self.assertEqual(vuln_entry.updated_at, info_parser.get_last_update_date())
            self.assertEqual(vuln_entry.created_at, info_parser.get_publication_date())
            parsed_fixed_in = info_parser.get_not_vulnerable_versions()
            if len(parsed_fixed_in):
                parsed_fixed_in = re.sub("WordPress (\D)*", '', parsed_fixed_in[0])
                self.assertEqual(vuln_entry.affected_versions[0].fixed_in, parsed_fixed_in)
            else:
                self.assertEqual(vuln_entry.affected_versions, list())
            references = vuln_entry.references
            self.assertEqual(references[0].type, "bugtraqid")
            self.assertEqual(references[0].id, bugtraq_id)
            reference_index = 1
            for cve_id in info_parser.get_cve_id():
                self.assertEqual(references[reference_index].type, "cve")
                self.assertEqual(references[reference_index].id, cve_id[4:])
                reference_index += 1
            self.assertEqual(len(references_parser.get_references()), len(references) - reference_index)
            for entry_ref, parser_ref in zip(references[reference_index:], references_parser.get_references()):
                self.assertEqual(entry_ref.type, "other")
                self.assertEqual(entry_ref.url, parser_ref["url"])

    def test_cve_reference_already_exists(self):
        path = file_path(__file__, "samples/fake_data")
        storage = Storage(path)
        vulnerability_manager = VulnerabilityManager(storage=storage)
        vuln_file_path = os.path.join(path, "wordpress/vuln-fakeproducer.json")
        if os.path.isfile(vuln_file_path):
            os.remove(vuln_file_path)  # If the file already exists remove it to use a clean file for the test.
        with open(vuln_file_path, "wt") as file:
            file.write(json.dumps({"key": "wordpress", "producer": "fakeproducer", "vulnerabilities": [{
                                   "id": "cve-2016-6635", "title": "Title", "references": [{"type": "cve", "id": "2016-6635"}]}]},
                                  indent=4, sort_keys=True))
        bugtraq_id = "92355"
        vuln_entry = {
            "id": bugtraq_id,
            "info_parser": InfoTabParser(),
            "references_parser": ReferenceTabParser(),
        }
        vuln_entry["info_parser"].set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
        vuln_entry["references_parser"].set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        reader = SecurityFocusReader(storage, vulnerability_manager)
        vuln = reader.read_one(vuln_entry)
        self.assertEqual(os.path.isfile(os.path.join(path, "wordpress/vuln-securityfocus.json")), False)
        self.assertEqual(vuln.references[1].type, "bugtraqid")
        self.assertEqual(vuln.references[1].id, bugtraq_id)
