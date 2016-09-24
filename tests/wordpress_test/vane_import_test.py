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

from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch, call
from fixtures import file_path, freeze_time
from datetime import datetime, timedelta

from openwebvulndb.common import VulnerabilityManager
from openwebvulndb.common import Vulnerability, VersionRange, VersionList, Reference, VulnerabilityList, Meta
from openwebvulndb.wordpress import VaneImporter


class VaneImportTest(TestCase):

    def setUp(self):
        self.manager = VulnerabilityManager(storage=MagicMock())
        self.manager.storage.read_vulnerabilities.side_effect = FileNotFoundError()
        self.importer = VaneImporter(vulnerability_manager=self.manager, storage=self.manager.storage)

    def test_import_plugins_sample_file(self):
        self.importer.load_plugins(file_path(__file__, 'vane-plugin-vulnerability-sample.json'))

        theme_my_login = self.manager.files["VaneImporter"]["plugins/theme-my-login"]
        login_rebuilder = self.manager.files["VaneImporter"]["plugins/login-rebuilder"]

        self.assertEqual(theme_my_login.vulnerabilities[0].id, "6043")
        self.assertEqual(theme_my_login.vulnerabilities[0].title, "Theme My Login 6.3.9 - Local File Inclusion")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[1].url,
                         "http://packetstormsecurity.com/files/127302/")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[2].url,
                         "http://seclists.org/fulldisclosure/2014/Jun/172")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[3].url,
                         "http://www.securityfocus.com/bid/68254")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[4].url,
                         "https://security.dxw.com/advisories/lfi-in-theme-my-login/")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[0].url, None)
        self.assertEqual(theme_my_login.vulnerabilities[0].references[0].type, "osvdb")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[0].id, "108517")

        self.assertEqual(login_rebuilder.vulnerabilities[0].id, "6044")
        self.assertEqual(login_rebuilder.vulnerabilities[0].references[0].type, "cve")
        self.assertEqual(login_rebuilder.vulnerabilities[0].references[0].id, "2014-3882")
        self.assertEqual(login_rebuilder.vulnerabilities[0].references[0].url,
                         "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3882")

    def test_apply_check_exploitdb(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "exploitdb": [12345],
        })
        self.assertEqual(vuln.references[0].type, "exploitdb")
        self.assertEqual(vuln.references[0].id, "12345")

    def test_apply_check_exploitdb_as_int(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "exploitdb": 12345,
        })
        self.assertEqual(vuln.references[0].type, "exploitdb")
        self.assertEqual(vuln.references[0].id, "12345")

    def test_apply_check_metaspoit(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "metasploit": ["exploit/unix/webapp/php_wordpress_optimizepress"],
        })
        self.assertEqual(vuln.references[0].type, "metasploit")
        self.assertEqual(vuln.references[0].id, "exploit/unix/webapp/php_wordpress_optimizepress")
        self.assertTrue(vuln.dirty)

    def test_apply_check_metaspoit_as_string(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "metasploit": "exploit/unix/webapp/php_wordpress_optimizepress",
        })
        self.assertEqual(vuln.references[0].type, "metasploit")
        self.assertEqual(vuln.references[0].id, "exploit/unix/webapp/php_wordpress_optimizepress")
        self.assertTrue(vuln.dirty)

    def test_apply_dates(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "created_at": "2014-08-01T10:58:35.000Z",
            "updated_at": "2014-08-01T11:58:35.000Z",
        })

        self.assertEqual(vuln.created_at, datetime(year=2014, month=8, day=1,
                                                   hour=10, minute=58, second=35, microsecond=0))
        self.assertEqual(vuln.updated_at, datetime(year=2014, month=8, day=1,
                                                   hour=11, minute=58, second=35, microsecond=0))
        self.assertTrue(vuln.dirty)

    def test_vuln_type(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "vuln_type": "LFI",
        })

        self.assertEqual(vuln.reported_type, 'LFI')
        self.assertTrue(vuln.dirty)

    def test_vulnerability_only_has_fixed_fixed_in(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "fixed_in": "1.2.3.4",
        })

        self.assertTrue(vuln.dirty)
        self.assertEqual(vuln.affected_versions, [
            VersionRange(fixed_in="1.2.3.4"),
        ])

    def test_title_contains_introduction_date(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "title": "Some Plugin 1.2.0 - XSS",
            "fixed_in": "1.2.3.4",
        })

        self.assertTrue(vuln.dirty)
        self.assertEqual(vuln.affected_versions, [
            VersionRange(introduced_in="1.2.0", fixed_in="1.2.3.4"),
        ])

    def test_no_menttion_of_fixed_in(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "title": "Some Plugin 1.2.0.1 - XSS",
        })

        self.assertTrue(vuln.dirty)
        self.assertEqual(vuln.affected_versions, [
            VersionRange(introduced_in="1.2.0.1"),
        ])

    def test_version_was_already_present(self):
        vuln = Vulnerability(id=1)
        vuln.affected_versions.append(VersionRange(introduced_in="1.2"))
        self.importer.apply_data(vuln, {
            "title": "Some Plugin 1.2 - XSS",
        })

        self.assertTrue(vuln.dirty)
        self.assertEqual(vuln.affected_versions, [
            VersionRange(introduced_in="1.2"),
        ])

    def test_no_mention_of_fixed_in_but_data_was_already_present(self):
        vuln = Vulnerability(id=1)
        vuln.affected_versions.append(VersionRange(introduced_in="1.2", fixed_in="1.3.2"))
        self.importer.apply_data(vuln, {
            "title": "Some Plugin 1.2 - XSS",
        })

        self.assertTrue(vuln.dirty)
        self.assertEqual(vuln.affected_versions, [
            VersionRange(introduced_in="1.2", fixed_in="1.3.2"),
        ])

    def test_confusing_ranges(self):
        vuln = Vulnerability(id=1, title="Some Plugin 1.5 - XSS")
        vuln.affected_versions.append(VersionRange(introduced_in="1.2"))
        vuln.affected_versions.append(VersionRange(fixed_in="1.3"))
        vuln.clean()

        self.importer.apply_data(vuln, {
            "title": "Some Plugin 1.5 - XSS",
        })

        self.assertFalse(vuln.dirty)
        self.assertNotIn(VersionRange(introduced_in="1.5"), vuln.affected_versions)

    def test_consider_key_as_convention(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "title": "Some Plugin - XSS",
        }, key="1.4")

        self.assertEqual(vuln.affected_versions, [
            VersionRange(introduced_in="1.4", fixed_in="1.5"),
        ])

    def test_fixed_in_has_precedence(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "title": "Some Plugin 1.4.1 - XSS",
            "fixed_in": "1.4.2"
        }, key="1.4")

        self.assertEqual(vuln.affected_versions, [
            VersionRange(introduced_in="1.4", fixed_in="1.4.2"),
        ])

    def test_no_version_data_is_no_data(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "title": "Some Plugin - XSS",
        })

        self.assertEqual(vuln.affected_versions, [])

    def test_import_themes_sample_file(self):
        # Same sample file as plugins, same format
        self.importer.load_themes(file_path(__file__, 'vane-plugin-vulnerability-sample.json'))

        theme_my_login = self.manager.files["VaneImporter"]["themes/theme-my-login"]

        self.assertEqual(theme_my_login.vulnerabilities[0].id, "6043")

    def test_import_wp_vulnerabilities(self):
        self.importer.load_wordpress(file_path(__file__, 'vane-vulnerability-sample.json'))

        wordpress = self.manager.files["VaneImporter"]["wordpress"]

        self.assertEqual(wordpress.vulnerabilities[0].id, "5963")
        self.assertEqual(wordpress.vulnerabilities[-1].id, "5967")


class VaneGlobalTest(TestCase):

    def setUp(self):
        self.importer = VaneImporter(vulnerability_manager=MagicMock(), storage=MagicMock())

    def test_includes_plugin_vulnerabilities(self):
        self.importer.load_plugins = MagicMock()
        self.importer.load_themes = MagicMock()
        self.importer.load_wordpress = MagicMock()

        self.importer.load("/My/Path")
        self.importer.load_plugins.assert_called_with("/My/Path/plugin_vulns.json")
        self.importer.load_themes.assert_called_with("/My/Path/theme_vulns.json")
        self.importer.load_wordpress.assert_called_with("/My/Path/wp_vulns.json")

    def test_export(self):
        self.importer.dump_plugins = MagicMock()
        self.importer.dump_themes = MagicMock()
        self.importer.dump_wordpress = MagicMock()
        self.importer.dump_lists = MagicMock()

        self.importer.dump("/My/Path")
        self.importer.dump_plugins.assert_called_with("/My/Path/plugin_vulns.json")
        self.importer.dump_themes.assert_called_with("/My/Path/theme_vulns.json")
        self.importer.dump_wordpress.assert_called_with("/My/Path/wp_vulns.json")
        self.importer.dump_lists.assert_has_calls([
            call("plugins", "/My/Path/plugins.txt", "/My/Path/plugins_full.txt"),
            call("themes", "/My/Path/themes.txt", "/My/Path/themes_full.txt"),
        ])


class VaneExportTest(TestCase):

    def setUp(self):
        self.manager = VulnerabilityManager(storage=MagicMock())
        self.manager.storage.read_vulnerabilities.side_effect = FileNotFoundError()
        self.importer = VaneImporter(vulnerability_manager=self.manager, storage=self.manager.storage)

    def test_export_per_version(self):
        expect = """
[
    {
        "1.0": {
            "vulnerabilities": [
                "output for list a"
            ]
        }
    },
    {
        "10.0": {
            "vulnerabilities": [
                "output for list c"
            ]
        }
    }
]
""".strip()
        version_list = VersionList(key="wordpress", producer="Test")
        version_list.get_version("1.0", create_missing=True)
        version_list.get_version("1.2", create_missing=True)
        version_list.get_version("10.0", create_missing=True)

        self.importer.storage.read_versions.return_value = version_list
        self.importer.storage.list_vulnerabilities.return_value = ["lists of vulnerabilities"]
        self.importer.dump_wordpress_vulnerabilities_for_version = MagicMock()
        self.importer.dump_wordpress_vulnerabilities_for_version.side_effect = [
            ["output for list a"],
            [],
            ["output for list c"],
        ]

        m = mock_open()
        with patch('openwebvulndb.wordpress.vane.open', m, create=True):
            self.importer.dump_wordpress("/some/file/path/wp_vulns.json")

        m.assert_called_with("/some/file/path/wp_vulns.json", "w")
        handle = m()
        handle.write.assert_called_with(expect)

        self.importer.storage.read_versions.assert_called_with("wordpress")
        self.importer.storage.list_vulnerabilities.assert_called_with("wordpress")
        self.importer.dump_wordpress_vulnerabilities_for_version.assert_has_calls([
            call(["lists of vulnerabilities"], "1.0"),
            call(["lists of vulnerabilities"], "1.2"),
            call(["lists of vulnerabilities"], "10.0"),
        ], any_order=False)

    def test_test_collect_wordpress_vulnerabilities(self):
        self.importer.manager.filter_for_version = MagicMock()
        self.importer.manager.filter_for_version.return_value = [
            Vulnerability(id="1121"),
            Vulnerability(id="9920"),
            Vulnerability(id="1231"),
        ]

        obtained = self.importer.dump_wordpress_vulnerabilities_for_version("some input data", "2.1")

        self.assertEqual(["1121", "9920", "1231"], [x["id"] for x in obtained])

        self.importer.manager.filter_for_version.assert_called_with("2.1", "some input data")

    def test_dump_vulnerabilities_basic(self):
        v = Vulnerability(id="1234", title="Hello World")
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "title": "Hello World",
        })

    def test_vuln_type(self):
        v = Vulnerability(id="1234", reported_type="LFI")
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "vuln_type": "LFI",
        })

    def test_vuln_cvss(self):
        v = Vulnerability(id="1234", cvss=2.6)
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "cvss": 2.6,
        })

    @freeze_time("2016-08-12 10:31:22.123Z")
    def test_dump_vulnerabilities_dates(self):
        v = Vulnerability(id="1234",
                          created_at=datetime.now() - timedelta(days=2, hours=3),
                          updated_at=datetime.now())
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "updated_at": "2016-08-12T10:31:22.123Z",
            "created_at": "2016-08-10T07:31:22.123Z",
        })

    @freeze_time("2016-08-12 10:31:22.123Z")
    def test_dump_vulnerabilities_urls(self):
        v = Vulnerability(id="1234", references=[
            Reference(type="other", url="https://example.com/test123"),
            Reference(type="other", url="https://example.com/test456"),
        ])
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "url": ["https://example.com/test123", "https://example.com/test456"],
        })

    @freeze_time("2016-08-12 10:31:22.123Z")
    def test_dump_vulnerabilities_refs(self):
        v = Vulnerability(id="1234", references=[
            Reference(type="cve", id="2015-1234", url="https://example.com/test123"),
            Reference(type="osvdb", id="12345"),
        ])
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "cve": ["2015-1234"],
            "osvdb": ["12345"],
        })

    def test_dump_vulnerability_finds_appropriate_fixed_in(self):
        v = Vulnerability(id="1234", title="My Description", affected_versions=[
            VersionRange(fixed_in="1.7"),
            VersionRange(introduced_in="2.0", fixed_in="2.4"),
            VersionRange(introduced_in="3.0", fixed_in="3.3"),
        ])
        dumped = self.importer.dump_vulnerability(v, for_version="2.2")
        self.assertEqual(dumped, {
            "id": "1234",
            "title": "My Description (2.0+)",
            "fixed_in": "2.4",
        })

    def test_dump_vulnerability_finds_appropriate_fixed_in_in_lower_bound(self):
        v = Vulnerability(id="1234", title="My Description", affected_versions=[
            VersionRange(fixed_in="1.7"),
            VersionRange(introduced_in="2.0", fixed_in="2.4"),
            VersionRange(introduced_in="3.0", fixed_in="3.3"),
        ])
        dumped = self.importer.dump_vulnerability(v, for_version="1.5")
        self.assertEqual(dumped, {
            "id": "1234",
            "title": "My Description",
            "fixed_in": "1.7",
        })

    def test_dump_vulnerability_pick_highest_when_nothing_relative_specified(self):
        v = Vulnerability(id="1234", title="My Description", affected_versions=[
            VersionRange(fixed_in="1.7"),
            VersionRange(introduced_in="2.0", fixed_in="2.4"),
            VersionRange(introduced_in="3.0", fixed_in="3.3"),
        ])
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "title": "My Description",
            "fixed_in": "3.3",
        })

    def test_dump_vulnerability_pick_highest_when_nothing_relative_specified_with_closed_range(self):
        v = Vulnerability(id="1234", title="My Description", affected_versions=[
            VersionRange(introduced_in="2.0", fixed_in="2.4"),
            VersionRange(introduced_in="3.0", fixed_in="3.3"),
        ])
        self.assertEqual(self.importer.dump_vulnerability(v), {
            "id": "1234",
            "title": "My Description (2.0+)",
            "fixed_in": "3.3",
        })

    def test_dump_vulnerability_no_appropriate_fix(self):
        v = Vulnerability(id="1234")
        self.assertEqual(self.importer.dump_vulnerability(v, for_version="2.2"), {
            "id": "1234",
        })

    def test_dump_vulnerability_current_branch_not_fixed(self):
        v = Vulnerability(id="1234", affected_versions=[
            VersionRange(fixed_in="1.7"),
            VersionRange(introduced_in="2.0"),
        ])
        self.assertEqual(self.importer.dump_vulnerability(v, for_version="2.2"), {
            "id": "1234",
        })

    def test_export_per_plugin(self):
        expect = """
[
    {
        "better-wp-security": {
            "vulnerabilities": [
                "output for list a"
            ]
        }
    },
    {
        "a-plugin": {
            "vulnerabilities": [
                "output for list c"
            ]
        }
    }
]
""".strip()
        self.importer.storage.list_directories.return_value = ['better-wp-security', 'some-plugin', 'a-plugin']
        self.importer.dump_vulnerabilities = MagicMock()
        self.importer.dump_vulnerabilities.side_effect = [
            ["output for list a"],
            [],
            ["output for list c"],
        ]

        m = mock_open()
        with patch('openwebvulndb.wordpress.vane.open', m, create=True):
            self.importer.dump_plugins("/some/file/path/plugin_vulns.json")

        m.assert_called_with("/some/file/path/plugin_vulns.json", "w")
        handle = m()
        handle.write.assert_called_with(expect)

        self.importer.storage.list_directories.assert_called_with("plugins")
        self.importer.dump_vulnerabilities.assert_has_calls([
            call("plugins", "better-wp-security"),
            call("plugins", "some-plugin"),
            call("plugins", "a-plugin"),
        ], any_order=False)

    def test_export_per_theme(self):
        expect = """
[
    {
        "twentytwelve": {
            "vulnerabilities": [
                "output for list a"
            ]
        }
    },
    {
        "twentyfourteen": {
            "vulnerabilities": [
                "output for list c"
            ]
        }
    }
]
""".strip()
        self.importer.storage.list_directories.return_value = ['twentytwelve', 'twentythirteen', 'twentyfourteen']
        self.importer.dump_vulnerabilities = MagicMock()
        self.importer.dump_vulnerabilities.side_effect = [
            ["output for list a"],
            [],
            ["output for list c"],
        ]

        m = mock_open()
        with patch('openwebvulndb.wordpress.vane.open', m, create=True):
            self.importer.dump_themes("/some/file/path/theme_vulns.json")

        m.assert_called_with("/some/file/path/theme_vulns.json", "w")
        handle = m()
        handle.write.assert_called_with(expect)

        self.importer.storage.list_directories.assert_called_with("themes")
        self.importer.dump_vulnerabilities.assert_has_calls([
            call("themes", "twentytwelve"),
            call("themes", "twentythirteen"),
            call("themes", "twentyfourteen"),
        ], any_order=False)

    def test_dump_vulnerabilities(self):
        vlist_1 = VulnerabilityList(key="plugins/some-plugin", producer="Test1")
        vlist_1.get_vulnerability("123", create_missing=True)
        vlist_1.get_vulnerability("234", create_missing=True)
        vlist_2 = VulnerabilityList(key="plugins/some-plugin", producer="Test2")
        vlist_2.get_vulnerability("345", create_missing=True)

        self.importer.storage.list_vulnerabilities.return_value = [vlist_1, vlist_2]

        out = list(self.importer.dump_vulnerabilities("plugins", "some-plugin"))

        self.importer.storage.list_vulnerabilities.assert_called_with("plugins/some-plugin")
        self.assertEqual(["123", "234", "345"], [x["id"] for x in out])

    def test_dump_lists(self):
        meta_1 = Meta(key="plugins/popular-plugin", is_popular=True)
        meta_2 = Meta(key="plugins/a-plugin")
        self.importer.storage.list_meta.return_value = [meta_1, meta_2]

        m = mock_open()
        with patch('openwebvulndb.wordpress.vane.open', m, create=True):
            self.importer.dump_lists("plugins", "pop.txt", "full.txt")
            self.importer.storage.list_meta.assert_called_with("plugins")

            m.assert_has_calls([
                call("pop.txt", "w"),
                call("full.txt", "w"),
            ], any_order=True)
            handle = m()
            handle.write.assert_has_calls([
                call("popular-plugin"),
                call("a-plugin\npopular-plugin"),
            ])
