from unittest import TestCase
from unittest.mock import MagicMock
from fixtures import file_path

from openwebvulndb.common import VulnerabilityManager
from openwebvulndb.wordpress import VaneImporter


class VaneImportTest(TestCase):

    def setUp(self):
        self.manager = VulnerabilityManager(storage=MagicMock())
        self.manager.storage.read_vulnerabilities.side_effect = FileNotFoundError()

    def test_import_plugins_sample_file(self):
        importer = VaneImporter(vulnerability_manager=self.manager)
        importer.load_plugins(file_path(__file__, 'vane-plugin-vulnerability-sample.json'))

        theme_my_login = self.manager.files["VaneImporter"]["plugins/theme-my-login"]
        login_rebuilder = self.manager.files["VaneImporter"]["plugins/login-rebuilder"]

        self.assertEqual(theme_my_login.vulnerabilities[0].id, "6043")
        self.assertEqual(theme_my_login.vulnerabilities[0].title, "Theme My Login 6.3.9 - Local File Inclusion")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[0].url,
                         "http://packetstormsecurity.com/files/127302/")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[1].url,
                         "http://seclists.org/fulldisclosure/2014/Jun/172")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[2].url,
                         "http://www.securityfocus.com/bid/68254")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[3].url,
                         "https://security.dxw.com/advisories/lfi-in-theme-my-login/")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[4].url, None)
        self.assertEqual(theme_my_login.vulnerabilities[0].references[4].type, "osvdb")
        self.assertEqual(theme_my_login.vulnerabilities[0].references[4].id, "108517")


        self.assertEqual(login_rebuilder.vulnerabilities[0].id, "6044")
        self.assertEqual(login_rebuilder.vulnerabilities[0].references[0].type, "cve")
        self.assertEqual(login_rebuilder.vulnerabilities[0].references[0].id, "2014-3882")
