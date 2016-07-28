from unittest import TestCase
from unittest.mock import MagicMock
from fixtures import file_path
from datetime import datetime, timezone

from openwebvulndb.common import VulnerabilityManager, Vulnerability
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
