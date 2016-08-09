import uuid
from collections import OrderedDict
from unittest import TestCase
from unittest.mock import mock_open, patch, call
from fixtures import file_path

from openwebvulndb.common import Storage, Meta, VulnerabilityList, VersionList


META_FILE_DATA = """
{
    "key": "plugins/better-wp-security",
    "name": "iThemes Security"
}""".strip()

VULNERABILITIES_FILE_DATA = """
{
    "key": "plugins/better-wp-security",
    "producer": "VaneImporter",
    "vulnerabilities": [
        {
            "id": "12345",
            "title": "Multiple XSS"
        }
    ]
}""".strip()

VERSIONS_FILE_DATA = """
{
    "key": "plugins/better-wp-security",
    "producer": "SubversionFetcher",
    "versions": [
        {
            "version": "1.0",
            "signatures": {
                "wp-content/plugins/better-wp-security/readme.txt": "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "wp-content/plugins/better-wp-security/readme.html": "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
    ]
}""".strip()


class StorageTest(TestCase):

    def test_store_meta(self):
        m = mock_open()
        with \
                patch('openwebvulndb.common.storage.open', m, create=True), \
                patch('openwebvulndb.common.storage.makedirs') as makedirs:

            storage = Storage('/some/path')
            storage.write_meta(Meta(key="plugins/better-wp-security", name="iThemes Security"))

            makedirs.assert_called_once_with('/some/path/plugins/better-wp-security', mode=0o755, exist_ok=True)
            m.assert_called_once_with('/some/path/plugins/better-wp-security/META.json', 'w')
            handle = m()
            handle.write.assert_called_once_with(META_FILE_DATA)

    def test_read_meta_but_not_found(self):
        m = mock_open()
        with patch('openwebvulndb.common.storage.open', m, create=True):
            m.side_effect = FileNotFoundError()

            storage = Storage('/some/path')

            with self.assertRaises(FileNotFoundError):
                storage.read_meta("plugins/better-wp-security")

            m.assert_called_with('/some/path/plugins/better-wp-security/META.json', 'r')

    def test_read_is_found(self):
        m = mock_open(read_data=META_FILE_DATA)
        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')

            meta = storage.read_meta("plugins/better-wp-security")
            self.assertIsInstance(meta, Meta)
            self.assertEqual(meta.name, "iThemes Security")

            m.assert_called_with('/some/path/plugins/better-wp-security/META.json', 'r')

    def test_read_vulnerabilities(self):
        m = mock_open(read_data=VULNERABILITIES_FILE_DATA)

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')

            vlist = storage.read_vulnerabilities("plugins/better-wp-security", "Vaneimporter")
            self.assertIsInstance(vlist, VulnerabilityList)
            self.assertEqual(vlist.producer, "VaneImporter")

            m.assert_called_with('/some/path/plugins/better-wp-security/vuln-vaneimporter.json', 'r')

    def test_write_vulnerabilities(self):
        m = mock_open()

        with \
                patch('openwebvulndb.common.storage.open', m, create=True), \
                patch('openwebvulndb.common.storage.makedirs') as makedirs:
            storage = Storage('/some/path')

            vlist = VulnerabilityList(key="plugins/better-wp-security",
                                      producer="VaneImporter")
            vlist.get_vulnerability("12345", create_missing=True).title = "Multiple XSS"
            storage.write_vulnerabilities(vlist)

            makedirs.assert_called_once_with('/some/path/plugins/better-wp-security', mode=0o755, exist_ok=True)
            m.assert_called_with('/some/path/plugins/better-wp-security/vuln-vaneimporter.json', 'w')

            handle = m()
            handle.write.assert_called_once_with(VULNERABILITIES_FILE_DATA)

    def test_read_versions(self):
        m = mock_open(read_data=VERSIONS_FILE_DATA)

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')

            vlist = storage.read_versions("plugins/better-wp-security")
            self.assertIsInstance(vlist, VersionList)
            self.assertEqual(vlist.producer, "SubversionFetcher")

            m.assert_called_with('/some/path/plugins/better-wp-security/versions.json', 'r')

    def test_write_versions(self):
        m = mock_open()

        with \
                patch('openwebvulndb.common.storage.open', m, create=True), \
                patch('openwebvulndb.common.storage.makedirs') as makedirs:
            storage = Storage('/some/path')

            vlist = VersionList(key="plugins/better-wp-security",
                                producer="SubversionFetcher")
            vlist.get_version("1.0", create_missing=True).signatures = OrderedDict([
                ("wp-content/plugins/better-wp-security/readme.txt",
                 "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                ("wp-content/plugins/better-wp-security/readme.html",
                 "SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ])
            storage.write_versions(vlist)

            makedirs.assert_called_once_with('/some/path/plugins/better-wp-security', mode=0o755, exist_ok=True)
            m.assert_called_with('/some/path/plugins/better-wp-security/versions.json', 'w')

            handle = m()
            handle.write.assert_called_once_with(VERSIONS_FILE_DATA)

    def test_read_path_empty(self):
        empty = file_path(__file__, '')

        storage = Storage(empty)
        self.assertEqual(storage.list_directories('') - {'__pycache__'}, set())

    def test_read_path_with_data(self):
        empty = file_path(__file__, '')

        storage = Storage(empty)
        self.assertIn('common_test', storage.list_directories('..'))

    def test_read_path_does_not_exist(self):
        empty = file_path(__file__, '')

        storage = Storage(empty)
        self.assertEqual(storage.list_directories('plugins') - {'__pycache__'}, set())

    def test_append(self):
        m = mock_open()
        with \
                patch('openwebvulndb.common.storage.open', m, create=True), \
                patch('openwebvulndb.common.storage.makedirs') as makedirs:

            storage = Storage("/some/path")
            storage.append('subdir/a_file.txt', 'hello')
            storage.append('subdir/a_file.txt', 'world\n\n')

            makedirs.assert_called_once_with('/some/path/subdir', mode=0o755, exist_ok=True)
            m.assert_called_with('/some/path/subdir/a_file.txt', 'a+')
            fp = m()
            fp.write.assert_has_calls([
                call("hello\n"),
                call("world\n"),
            ])

    def test_read_lines(self):
        m = mock_open(read_data="hello\nworld\ntest")

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')

            lines = storage.read_lines("test.txt")

            self.assertEqual(["hello", "world", "test"], list(lines))
            m.assert_called_with('/some/path/test.txt', 'r')
