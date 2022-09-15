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

import unittest
from unittest.mock import MagicMock
from openwebvulndb.common.securityfocus.parsers import InfoTabParser, ReferenceTabParser
from tests.fixtures import file_path, ClientSessionMock, async_test
from openwebvulndb.common.securityfocus.reader import SecurityFocusReader
from openwebvulndb.common.storage import Storage
from openwebvulndb.common.manager import VulnerabilityManager
from openwebvulndb.common.errors import VulnerabilityNotFound
from openwebvulndb.common.models import VulnerabilityList, Vulnerability, Reference, VersionList
from datetime import datetime
import json
import os
import re
from openwebvulndb.common.manager import ReferenceManager
from aiohttp.test_utils import make_mocked_coro


class TargetIdentificationTest(unittest.TestCase):

    def setUp(self):
        self.storage = MagicMock()
        self.reader = SecurityFocusReader(self.storage)

    def test_identify_target_search_for_existing_vulnerability_if_entry_has_cve(self):
        entry = {"info_parser": MagicMock(), "references_parser": MagicMock()}
        entry["info_parser"].get_cve_id.return_value = ["CVE-2017-1234"]
        self.reader.vulnerability_manager = MagicMock()
        existing_vuln = Vulnerability(id="CVE-2017-1234", references=[Reference(type="cve", id="2017-1234")])
        self.reader._identify_from_cve = MagicMock()
        self.reader._identify_from_cve.return_value = "plugins/plugin0"

        target = self.reader.identify_target(entry)

        self.reader._identify_from_cve.assert_called_once_with(entry)
        self.assertEqual(target, "plugins/plugin0")

    def test_identify_plugin_from_url(self):
        entry = dict()
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/73931/references_tab.html"))
        info_parser = MagicMock()
        get_cve_method = MagicMock(return_value=[])
        info_parser.attach_mock(get_cve_method, "get_cve_id")
        entry['info_parser'] = info_parser
        entry['references_parser'] = parser
        self.assertEqual(self.reader.identify_target(entry), "plugins/wassup")

    def test_identify_theme_from_url(self):
        ref_parser = ReferenceTabParser()
        ref_parser.set_html_page(file_path(__file__, "samples/92142/references_tab.html"))
        info_parser = MagicMock()
        info_parser.get_cve_id.return_value = []
        entry = {
            'info_parser': info_parser,
            'references_parser': ref_parser
        }
        self.assertEqual(self.reader.identify_target(entry), "themes/colorway")

    def test_identify_plugin_from_title(self):
        storage = Storage(file_path(__file__, "samples/fake_data"))
        reader = SecurityFocusReader(storage)
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/73931/info_tab.html"))
        references_parser = MagicMock()
        get_references_function = MagicMock(return_value=list())
        references_parser.attach_mock(get_references_function, "get_references")
        entry = dict()
        entry['info_parser'] = info_parser
        entry['references_parser'] = references_parser
        self.assertEqual(reader.identify_target(entry), "plugins/wassup")

    def test_identify_from_title_validate_target_found_if_fallback_to_wordpress(self):
        entry = {'info_parser': MagicMock(), 'references_parser': MagicMock()}
        entry['references_parser'].get_references.return_value = []
        entry['info_parser'].get_title.return_value = \
            "WordPress WP Statistics CVE-2017-2136 HTML Injection Vulnerability"
        self.reader._validate_target = MagicMock(return_value=False)

        self.assertIsNone(self.reader._identify_from_title(entry))

        self.reader._validate_target.assert_called_once_with("wordpress", entry)

    def test_identify_plugin_from_meta(self):
        storage = Storage(file_path(__file__, "samples/fake_data"))
        reader = SecurityFocusReader(storage)
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/91405/info_tab.html"))
        references_parser = MagicMock()
        references_parser.get_references.return_value = []
        entry = {
            'id': "91405",
            'info_parser': info_parser,
            'references_parser': references_parser,
        }
        self.assertEqual(reader.identify_target(entry), "plugins/welcart")

    def test_identify_theme_from_title(self):
        storage = Storage(file_path(__file__, "samples/fake_data"))
        reader = SecurityFocusReader(storage)
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/92142/info_tab.html"))
        references_parser = MagicMock()
        get_references_function = MagicMock(return_value=list())
        references_parser.attach_mock(get_references_function, "get_references")
        entry = {
            'info_parser': info_parser,
            'references_parser': references_parser
        }
        self.assertEqual(reader.identify_target(entry), "themes/colorway")

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
        get_cve_id = MagicMock(return_value=[])
        get_title = MagicMock(return_value="Random title with no clear indication about a plugin name or wordpress")
        info_parser.attach_mock(get_cve_id, "get_cve_id")
        info_parser.attach_mock(get_title, "get_title")
        references_parser = MagicMock()
        get_references = MagicMock(return_value=list())
        references_parser.attach_mock(get_references, "get_references")
        entry=dict()
        entry["info_parser"] = info_parser
        entry["references_parser"] = references_parser
        self.assertIsNone(self.reader.identify_target(entry))

    def test_validate_target_return_false_if_fixed_in_is_not_a_valid_version_for_target(self):
        info_parser = MagicMock()
        info_parser.get_title.return_value = "WordPress WP Statistics CVE-2017-2136 HTML Injection Vulnerability"
        info_parser.get_vulnerable_versions.return_value = ["12.0", "12.0.1", "12.0.2", "12.0.4"]
        wordpress_versions = VersionList(key="key", producer="producer")
        wordpress_versions.get_version("4.7.5", create_missing=True)
        self.storage.read_versions.return_value = wordpress_versions
        entry = {'info_parser': info_parser}

        self.assertFalse(self.reader._validate_target("wordpress", entry))
        self.storage.read_versions.assert_called_once_with("wordpress")


class SecurityFocusReaderTest(unittest.TestCase):

    def setUp(self):
        self.storage = MagicMock()
        self.vulnerability_manager = MagicMock()
        self.reader = SecurityFocusReader(self.storage, self.vulnerability_manager)
        self.reader.cvss_mapper = MagicMock()

    def test_add_plugin_vuln_to_database(self):
        bugtraq_id = "73931"
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry = {"id": bugtraq_id, "info_parser": info_parser, "references_parser": references_parser}
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
        self.assertEqual(references[0].url, "http://www.securityfocus.com/bid/%s" % bugtraq_id)
        self.assertEqual(references[1].type, "other")
        self.assertEqual(references[1].url, "http://seclists.org/oss-sec/2015/q2/51")

    def test_add_vuln_to_database_allow_override(self):
        """Test if a more recent vuln entry allow to override an old one."""
        bugtraq_id = "73931"
        previous_vuln_entry = Vulnerability(id=bugtraq_id, title="WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability",
                                            reported_type="Input Validation Error", created_at=datetime(2009, 12, 7, 0, 0),
                                            updated_at=datetime(2016, 9, 2, 20, 0), references=[Reference(type="bugtraqid", id=bugtraq_id)])
        self.storage.list_vulnerabilities.return_value = [VulnerabilityList(producer="security-focus", key="plugins/wassup",
                                                                            vulnerabilities=[previous_vuln_entry])]
        reader = SecurityFocusReader(self.storage)
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab_fake_update_date.html"))
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry = {"id": bugtraq_id, "info_parser": info_parser, "references_parser": references_parser}
        vuln_entry = reader.read_one(entry)

        self.assertEqual(vuln_entry.id, bugtraq_id)
        self.assertEqual(vuln_entry.title, "WordPress WassUp Plugin 'main.php' Fake Title")
        self.assertEqual(vuln_entry.reported_type, "Input Validation Error")  # Reported type is not overwritten.
        self.assertEqual(vuln_entry.updated_at, datetime(2016, 9, 4, 20, 0))
        self.assertEqual(vuln_entry.created_at, datetime(2009, 12, 7, 0, 0))
        self.assertEqual(vuln_entry.affected_versions[0].fixed_in, "1.7.2.1")
        references = vuln_entry.references
        self.assertEqual(references[0].type, "bugtraqid")
        self.assertEqual(references[0].id, bugtraq_id)
        self.assertEqual(references[0].url, "http://www.securityfocus.com/bid/%s" % bugtraq_id)
        self.assertEqual(references[1].type, "other")
        self.assertEqual(references[1].url, "http://seclists.org/oss-sec/2015/q2/51")

    def test_add_vuln_to_database_no_override(self):
        """Test if a less recent vuln entry can't override a newer one."""
        bugtraq_id = "73931"
        previous_vuln_entry = Vulnerability(id=bugtraq_id,
                                            title="WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability",
                                            reported_type="Input Validation Error",
                                            created_at=datetime(2009, 12, 7, 0, 0),
                                            updated_at=datetime(2016, 9, 2, 20, 0),
                                            references=[Reference(type="bugtraqid", id=bugtraq_id)])
        self.storage.list_vulnerabilities.return_value = [VulnerabilityList(producer="security-focus", key="plugins/wassup", vulnerabilities=[previous_vuln_entry])]
        reader = SecurityFocusReader(self.storage)
        info_parser = InfoTabParser()
        info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab_older_update_date.html"))
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        entry = {"id": bugtraq_id, "info_parser": info_parser, "references_parser": references_parser}
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
        self.assertEqual(references[0].url, "http://www.securityfocus.com/bid/%s" % bugtraq_id)
        self.assertEqual(references[1].type, "other")
        self.assertEqual(references[1].url, "http://seclists.org/oss-sec/2015/q2/51")

    def test_add_multiple_vulnerabilities_to_database(self):
        """Test the security focus reader with a lot of samples."""
        self.storage.list_vulnerabilities.return_value = list()
        self.storage.read_vulnerabilities.side_effect = FileNotFoundError()
        self.storage.list_directories.return_value = {"wassup", "onelogin-saml-sso", "nofollow-links", "w3-total-cache"}
        reader = SecurityFocusReader(self.storage)
        bugtraq_id_list = ["73931", "82355", "91076", "92077", "92355", "92572", "92841", "93104"]
        for bugtraq_id in bugtraq_id_list:
            info_parser = InfoTabParser()
            info_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
            references_parser = ReferenceTabParser()
            references_parser.set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
            entry = {"id": bugtraq_id, "info_parser": info_parser, "references_parser": references_parser}
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
            self.assertEqual(references[0].url, "http://www.securityfocus.com/bid/%s" % bugtraq_id)
            reference_index = 1
            for cve_id in info_parser.get_cve_id():
                self.assertEqual(references[reference_index].type, "cve")
                self.assertEqual(references[reference_index].id, cve_id[4:])
                reference_index += 1

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

    def test_bugtraqid_reference_already_exists_as_other(self):
        """Test if the security focus reader finds vuln with a reference to security focus with type "other" and the url
        and replace it with the new bugtraqid reference."""
        path = file_path(__file__, "samples/fake_data")
        storage = Storage(path)
        vulnerability_manager = VulnerabilityManager(storage=storage)
        vuln_file_path = os.path.join(path, "wordpress/vuln-fakeproducer2.json")
        if os.path.isfile(vuln_file_path):
            os.remove(vuln_file_path)  # If the file already exists remove it to use a clean file for the test.
        with open(vuln_file_path, "wt") as file:
            file.write(json.dumps({"key": "wordpress", "producer": "fakeproducer2", "vulnerabilities": [{
                                   "id": "cve-2016-6897", "title": "Title", "references": [{"type": "other",
                                   "url": "http://www.securityfocus.com/bid/92572"}]}]}, indent=4, sort_keys=True))
        bugtraq_id = "92572"
        vuln_entry = {
            "id": bugtraq_id,
            "info_parser": InfoTabParser(),
            "references_parser": ReferenceTabParser(),
        }
        vuln_entry["info_parser"].set_html_page(file_path(__file__, "samples/" + bugtraq_id + "/info_tab.html"))
        vuln_entry["references_parser"].set_html_page(
            file_path(__file__, "samples/" + bugtraq_id + "/references_tab.html"))
        reader = SecurityFocusReader(storage, vulnerability_manager)
        vuln = reader.read_one(vuln_entry)
        self.assertEqual(os.path.isfile(os.path.join(path, "wordpress/vuln-securityfocus.json")), False)
        for ref in vuln.references:
            if ref.type == "bugtraqid" and ref.id == bugtraq_id:
                break
        else:
            self.fail("bugtraqid not added to vuln references.")
        for ref in vuln.references:
            if ref.type == "other" and ref.url is not None:
                self.assertNotIn("securityfocus", ref.url)

    def test_bugtraqid_reference_doesnt_overwrite_securityfocus_url_if_bugtraqid_doesnt_match(self):
        references = [Reference(url="http://www.securityfocus.com/bid/12345", type="other")]
        bugtraq_id = "98765"
        reference_manager = ReferenceManager()
        reference_manager.references = references
        reader = SecurityFocusReader(None, None)

        reader._add_bugtraqid_reference(reference_manager, bugtraq_id)

        self.assertEqual(len(references), 2)
        self.assertEqual(references[1].type, "bugtraqid")
        self.assertEqual(references[1].id, bugtraq_id)
        self.assertEqual(references[1].url, "http://www.securityfocus.com/bid/%s" % bugtraq_id)

    def test_get_lowest_version_when_multiple_fixed_in(self):
        """Test that the fixed_in version put in the vuln file by the reader is the lowest one when there is more than one not vuln version"""
        self.storage.list_directories.return_value = {"wassup"}
        self.vulnerability_manager.find_vulnerability.side_effect = VulnerabilityNotFound()
        self.vulnerability_manager.get_producer_list.return_value = VulnerabilityList(producer="security-focus", key="plugins/wassup")
        title = "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability"
        versions = ["WordPress WassUp 1.7.2", "WordPress WassUp 1.7.1", "WordPress WassUp 1.6.9"]
        entry = self.create_securityfocus_entry(id="12345", title=title, not_vulnerable_versions=versions)
        vuln = self.reader.read_one(entry)
        self.assertEqual(vuln.affected_versions[0].fixed_in, "1.6.9")

    def test_remove_useless_references(self):
        self.storage.list_directories.return_value = {"wassup"}
        self.vulnerability_manager.find_vulnerability.side_effect = VulnerabilityNotFound()
        self.vulnerability_manager.get_producer_list.return_value = VulnerabilityList(producer="security-focus",
                                                                                      key="plugins/wassup")
        info_parser = MagicMock()
        info_parser.get_title.return_value = "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability"
        references_parser = ReferenceTabParser()
        references_parser.set_html_page(file_path(__file__, "samples/securityfocus_references_tab_with_useless_references.html"))
        entry = {"id": "73931", "info_parser": info_parser, "references_parser": references_parser}

        vuln = self.reader.read_one(entry)

        self.assertEqual(len(vuln.references), 3)  # Only the bugtraqid and the first two references should be in the list.

    def test_apply_data_dont_override_updated_at_if_no_other_changes(self):
        created_at = datetime(2017, 1, 10)
        updated_at = datetime(2017, 1, 11, hour=8)
        bugtraq_id = "12345"
        vuln = Vulnerability(id=bugtraq_id, title="Title", updated_at=created_at, created_at=created_at)
        vuln.references.append(Reference(type="bugtraqid", id=bugtraq_id, url="http://www.securityfocus.com/bid/12345"))
        entry = self.create_securityfocus_entry(id=bugtraq_id, title="Title", update_date=updated_at,
                                                creation_date=created_at)
        reader = SecurityFocusReader(None)

        reader.apply_data(vuln, entry, allow_override=True)

        self.assertEqual(vuln.updated_at, created_at)

    def test_apply_data_override_updated_at_if_new_references(self):
        created_at = datetime(2017, 1, 10)
        updated_at = datetime(2017, 1, 11, hour=8)
        bugtraq_id = "12345"
        vuln = Vulnerability(id=bugtraq_id, title="Title", updated_at=created_at, created_at=created_at)

        entry = self.create_securityfocus_entry(id=bugtraq_id, title="Title", update_date=updated_at,
                                                creation_date=created_at,
                                                references=[{"url": "http://www.references.example/wordpress"}])
        reader = SecurityFocusReader(None)

        reader.apply_data(vuln, entry, allow_override=True)

        self.assertEqual(vuln.updated_at, updated_at)

    def test_apply_data_set_calculated_cvss_if_reported_type_in_cvss_mapping_but_no_cvss_and_no_cve(self):
        self.reader.cvss_mapper.get_cvss_from_vulnerability_type.return_value = 4.3
        date = datetime(2017, 1, 10)
        bugtraq_id = "12345"
        vuln = Vulnerability(id=bugtraq_id, title="Title", updated_at=date, created_at=date)
        entry = self.create_securityfocus_entry(id=bugtraq_id, title="Title", vuln_class="SQLI", update_date=date,
                                                creation_date=date)

        self.reader.apply_data(vuln, entry)

        self.assertEqual(vuln.cvss, 4.3)

    def test_apply_data_dont_set_calculated_cvss_if_cve_for_entry(self):
        self.reader.cvss_mapper.get_cvss_from_vulnerability_type.return_value = 4.3
        date = datetime(2017, 1, 10)
        bugtraq_id = "12345"
        vuln = Vulnerability(id=bugtraq_id, title="Title", updated_at=date, created_at=date)
        entry = self.create_securityfocus_entry(id=bugtraq_id, title="Title", vuln_class="SQLI", update_date=date,
                                                creation_date=date, cve_ids=["CVE-1234-1234"])

        self.reader.apply_data(vuln, entry)

        self.assertIsNone(vuln.cvss)

    @async_test()
    async def test_read_cve_entry_if_entry_has_cve_but_producer_is_not_cvereader(self):
        date = datetime(2017, 7, 25)
        security_focus_entry = self.create_securityfocus_entry(id="12345", title="Title", cve_ids=["CVE-2017-1234"],
                                                               update_date=date)
        self.reader.identify_target = MagicMock(return_value="plugins/plugin")
        self.reader.vulnerability_manager.find_vulnerability.return_value = None
        self.reader.vulnerability_manager.get_producer_list.return_value = VulnerabilityList(producer="securityfocus",
                                                                                             key="plugins/plugin")
        self.reader.cve_reader.read_one_from_api = make_mocked_coro()
        self.reader.fetcher.get_vulnerabilities = make_mocked_coro(return_value=[security_focus_entry])

        await self.reader.read_from_website()

        self.reader.cve_reader.read_one_from_api.assert_called_once_with("CVE-2017-1234")

    @async_test()
    async def test_dont_read_cve_entry_if_entry_has_cve_and_producer_is_cvereader(self):
        date = datetime(2017, 7, 25)
        entry = Vulnerability(id="CVE-2017-1234", title="Title", updated_at=date, created_at=date,
                              references=[Reference(type="bugtraqid", id="12345")])
        security_focus_entry = self.create_securityfocus_entry(id="12345", title="Title", cve_ids=["CVE-2017-1234"],
                                                               update_date=date)
        self.reader.identify_target = MagicMock(return_value="plugins/plugin")
        self.reader.vulnerability_manager.find_vulnerability.return_value = entry
        self.reader.vulnerability_manager.get_producer_list.return_value = VulnerabilityList(producer="CVEReader",
                                                                                             key="plugins/plugin")
        self.reader.cve_reader = MagicMock()
        self.reader.cve_reader.read_one_from_api = make_mocked_coro()
        self.reader.fetcher.get_vulnerabilities = make_mocked_coro(return_value=[security_focus_entry])

        await self.reader.read_from_website()

        self.reader.cve_reader.read_one_from_api.assert_not_called()

    def create_securityfocus_entry(self, *, id, title=None, cve_ids=None, references=None, creation_date=None,
                                   update_date=None, vuln_class=None, not_vulnerable_versions=None):
        info_parser = MagicMock()
        info_parser.get_title.return_value = title
        info_parser.get_cve_id.return_value = cve_ids or []
        info_parser.get_last_update_date.return_value = update_date
        info_parser.get_publication_date.return_value = creation_date
        info_parser.get_vuln_class.return_value = vuln_class
        info_parser.get_not_vulnerable_versions.return_value = not_vulnerable_versions or []
        ref_parser = MagicMock()
        ref_parser.get_references.return_value = references or []
        return {"id": id, "info_parser": info_parser, "references_parser": ref_parser}
