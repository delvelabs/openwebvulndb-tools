from unittest import TestCase
from unittest.mock import MagicMock
from fixtures import file_path
from datetime import datetime, timezone

from openwebvulndb.common import VulnerabilityManager, Vulnerability, VersionRange
from openwebvulndb.wordpress import VaneImporter


class VaneImportTest(TestCase):

    def setUp(self):
        self.manager = VulnerabilityManager(storage=MagicMock())
        self.manager.storage.read_vulnerabilities.side_effect = FileNotFoundError()
        self.importer = VaneImporter(vulnerability_manager=self.manager)

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
        self.assertEqual(login_rebuilder.vulnerabilities[0].references[0].url, "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-3882")

    def test_apply_check_exploitdb(self):
        vuln = Vulnerability(id=1)
        self.importer.apply_data(vuln, {
            "exploitdb": [12345],
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

    def test_import_themes_sample_file(self):
        # Same sample file as plugins, same format
        self.importer.load_themes(file_path(__file__, 'vane-plugin-vulnerability-sample.json'))

        theme_my_login = self.manager.files["VaneImporter"]["themes/theme-my-login"]
        login_rebuilder = self.manager.files["VaneImporter"]["themes/login-rebuilder"]

        self.assertEqual(theme_my_login.vulnerabilities[0].id, "6043")

    def test_apply_check_exploitdb(self):
        vuln = Vulnerability(id=1)


class VaneImportGlobalTest(TestCase):

    def setUp(self):
        self.importer = VaneImporter(vulnerability_manager=MagicMock())

    def test_includes_plugin_vulnerabilities(self):
        self.importer.load_plugins = MagicMock()
        self.importer.load_themes = MagicMock()

        self.importer.load("/My/Path")
        self.importer.load_plugins.assert_called_with("/My/Path/plugin_vulns.json")
        self.importer.load_themes.assert_called_with("/My/Path/theme_vulns.json")
