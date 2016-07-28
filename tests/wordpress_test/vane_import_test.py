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
        self.assertEqual(login_rebuilder.vulnerabilities[0].id, "6044")
