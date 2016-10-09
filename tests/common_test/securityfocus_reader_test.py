import unittest
from openwebvulndb.common.securityfocus.securityfocusparsers import InfoTabParser, ReferenceTabParser
from fixtures import file_path
from openwebvulndb.common.securityfocus.securityfocus import SecurityFocusReader
from openwebvulndb.common.storage import Storage
import json
import os


class SecurityFocusReaderTest(unittest.TestCase):

    def test_add_vuln_73931_to_database(self):
        bugtraq_id = "73931"
        plugin_path = "plugins/wassup"
        # Remove the vuln entry file if it already exists to ensure the validity of the test.
        os.remove(file_path(__file__, "../../data/" + plugin_path + "/vuln-security-focus.json"))
        entry = dict()
        entry['id'] = bugtraq_id
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
        entry['info_parser'] = info_parser
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry['references_parser'] = references_parser
        storage = Storage(base_path=file_path(__file__, "../../data"))
        reader = SecurityFocusReader(storage=storage)
        reader.read_one(entry)
        vuln_entry_file = open(file_path(__file__, "../../data/" + plugin_path + "/vuln-security-focus.json"), "rt")
        json_vuln_entry = json.load(vuln_entry_file)
        self.assertEqual(json_vuln_entry['key'], plugin_path)
        self.assertEqual(json_vuln_entry['producer'], "security-focus")
        vuln_list = json_vuln_entry['vulnerabilities']
        vuln = vuln_list[0]
        self.assertEqual(vuln['id'], bugtraq_id)
        self.assertEqual(vuln['title'], "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability")
        self.assertEqual(vuln['reported_type'], "Input Validation Error")
        reference = vuln['references'][0]
        self.assertEqual(reference['type'], "Bugtraq-ID")
        self.assertEqual(reference['id'], bugtraq_id)
        vuln_entry_file.close()
