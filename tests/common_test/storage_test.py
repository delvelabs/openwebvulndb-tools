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
from unittest.mock import mock_open, patch, call, MagicMock, ANY

from fixtures import file_path

from openwebvulndb.common import Storage, Meta, VulnerabilityList, VersionList
from openwebvulndb.common.schemas import VersionListSchema
from openwebvulndb.common.models import File, FileList, FileSignature


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
    "hash_algo": "SHA256",
    "files": [
        {
            "path": "wp-content/plugins/better-wp-security/readme.txt",
            "signatures": [
                {
                    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "versions": [
                        "1.0"
                    ]
                },
                {
                    "hash": "266b841cbf4e462e1ddd6b8d59cb2e0678182f13525d6e16221676a9066cbd78",
                    "versions": [
                        "1.1"
                    ]
                }
            ]
        }
    ]
}""".strip()

OLD_VERSIONS_FILE_DATA = """
{
    "key": "plugins/better-wp-security",
    "producer": "SubversionFetcher",
    "versions": [
        {
            "version": "1.4",
            "signatures": [{"path":"path/to/file", "algo": "SHA256", "hash": "abcdef123456"}]
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

    def test_list_meta(self):
        with patch('openwebvulndb.common.storage.walk') as walk:
            walk.return_value = [
                ("/some/path/plugins", ["plugin-a", "plugin-b", "plugin-c"], []),
                ("/some/path/plugins/plugin-a", [], ["META.json"]),
                ("/some/path/plugins/plugin-b", [], ["otherfile.json"]),
                ("/some/path/plugins/plugin-c", [], ["versions.json", "META.json"]),
            ]

            storage = Storage('/some/path')
            storage.read_meta = MagicMock()
            storage.read_meta.return_value = 'hello'
            out = list(storage.list_meta("plugins"))

            storage.read_meta.assert_has_calls([
                call("plugins/plugin-a"),
                call("plugins/plugin-c"),
            ])
            walk.assert_called_with("/some/path/plugins")
            self.assertEqual(out, ['hello', 'hello'])

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

    def test_list_vulnerabilities(self):
        class DirEntry:
            def __init__(self, name, is_dir=False):
                self.name = name
                self.is_dir = lambda: is_dir

        with patch('openwebvulndb.common.storage.scandir') as scandir:
            scandir.return_value = [
                DirEntry(name="META.json"),
                DirEntry(name="versions.json"),
                DirEntry(name="vuln-vaneimporter.json"),
                DirEntry(name="vuln-manual.json"),
                DirEntry(name="test", is_dir=True),
            ]
            storage = Storage('/some/path')
            storage.read_vulnerabilities = MagicMock()
            storage.read_vulnerabilities.return_value = "a list"

            vlists = storage.list_vulnerabilities('wordpress')

            self.assertEqual(["a list", "a list"], list(vlists))
            storage.read_vulnerabilities.assert_has_calls([
                call("wordpress", "vaneimporter"),
                call("wordpress", "manual"),
            ])
            scandir.assert_called_with("/some/path/wordpress")

    def test_list_vulnerabilities_has_nothing(self):
        class DirEntry:
            def __init__(self, name, is_dir=False):
                self.name = name
                self.is_dir = lambda: is_dir

        with patch('openwebvulndb.common.storage.scandir') as scandir:
            scandir.return_value = [
                DirEntry(name="META.json"),
                DirEntry(name="versions.json"),
                DirEntry(name="test", is_dir=True),
            ]
            storage = Storage('/some/path')
            storage.read_vulnerabilities = MagicMock()
            storage.read_vulnerabilities.return_value = "a list"

            vlists = storage.list_vulnerabilities('wordpress')

            self.assertEqual([], list(vlists))
            storage.read_vulnerabilities.assert_not_called()
            scandir.assert_called_with("/some/path/wordpress")

    def test_read_versions(self):
        m = mock_open(read_data=VERSIONS_FILE_DATA)

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')
            storage._read_from_cache = MagicMock(side_effect=FileNotFoundError())

            vlist = storage.read_versions("plugins/better-wp-security")
            self.assertIsInstance(vlist, VersionList)
            self.assertEqual(vlist.producer, "SubversionFetcher")

            m.assert_called_with('/some/path/plugins/better-wp-security/versions.json', 'r')

    def test_read_versions_read_from_local_cache_if_file_exists(self):
        m = mock_open(read_data=VERSIONS_FILE_DATA)

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')

            vlist = storage.read_versions("plugins/better-wp-security")

            m.assert_called_with('/some/path/.cache/plugins/better-wp-security/versions_old.json', 'r')

    def test_read_versions_use_old_format_if_new_schema_failed_to_load(self):
        m = mock_open(read_data=OLD_VERSIONS_FILE_DATA)

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')
            storage._read_from_cache = MagicMock(side_effect=FileNotFoundError())

            vlist = storage.read_versions("plugins/better-wp-security")

            self.assertEqual(vlist.versions[0].signatures[0].hash, "abcdef123456")
            self.assertIsInstance(vlist, VersionList)
            self.assertEqual(vlist.producer, "SubversionFetcher")

            m.assert_called_with('/some/path/plugins/better-wp-security/versions.json', 'r')

    def test_write_versions(self):
        m = mock_open()

        with \
                patch('openwebvulndb.common.storage.open', m, create=True), \
                patch('openwebvulndb.common.storage.makedirs') as makedirs:
            storage = Storage('/some/path')
            storage._write_to_cache = MagicMock()
            storage._read = MagicMock(side_effect=FileNotFoundError())

            vlist = VersionList(key="plugins/better-wp-security",
                                producer="SubversionFetcher")
            v = vlist.get_version("1.0", create_missing=True)
            v.add_signature("wp-content/plugins/better-wp-security/readme.txt",
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            v = vlist.get_version("1.1", create_missing=True)
            v.add_signature("wp-content/plugins/better-wp-security/readme.txt",
                            "266b841cbf4e462e1ddd6b8d59cb2e0678182f13525d6e16221676a9066cbd78")
            storage.write_versions(vlist)

            makedirs.assert_called_once_with('/some/path/plugins/better-wp-security', mode=0o755, exist_ok=True)
            m.assert_called_with('/some/path/plugins/better-wp-security/versions.json', 'w')

            handle = m()
            handle.write.assert_called_once_with(VERSIONS_FILE_DATA)

    def test_write_versions_update_existing_file_list(self):
        version_builder_mock = MagicMock()
        file_list_schema = MagicMock()
        with patch("openwebvulndb.common.storage.VersionBuilder", MagicMock(return_value=version_builder_mock)), \
                patch("openwebvulndb.common.storage.FileListSchema", MagicMock(return_value=file_list_schema)):
            storage = Storage('/some/path')
            file_list = FileList(key="key", producer="producer",
                                 files=[File(path="file0", signatures=[FileSignature(hash="0", versions=["1.0"])])])
            storage._write_to_cache = MagicMock()
            storage._read = MagicMock(return_value=file_list)
            storage._write = MagicMock()
            vlist = VersionList(key="key", producer="producer")
            v = vlist.get_version("1.0", create_missing=True)
            v.add_signature("file0", "0"),
            v = vlist.get_version("1.1", create_missing=True)
            v.add_signature("file0", "1")
            v.add_signature("file1", "1")

            storage.write_versions(vlist)

            storage._read.assert_called_once_with(file_list_schema, "key", "versions.json")
            storage._write.assert_called_once_with(file_list_schema, file_list, "versions.json")
            version_builder_mock.update_file_list.assert_called_once_with(file_list, vlist)

    def test_write_versions_write_version_list_to_local_cache(self):
        storage = Storage('/some/path')
        storage._write_to_cache = MagicMock()
        storage._write = MagicMock()

        vlist = VersionList(key="plugins/better-wp-security",
                            producer="SubversionFetcher")
        storage.write_versions(vlist)

        storage._write_to_cache.assert_called_once_with(ANY, vlist, "versions_old.json")

    def test_read_path_empty(self):
        empty = file_path(__file__, '')

        storage = Storage(empty)
        self.assertEqual(storage.list_directories('securityfocus/samples') - {'__pycache__'}, set())

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

    def test_write_to_cache(self):
        m = mock_open()

        with \
                patch('openwebvulndb.common.storage.open', m, create=True), \
                patch('openwebvulndb.common.storage.makedirs') as makedirs:
            storage = Storage('/some/path')

            vlist = VersionList(key="plugins/better-wp-security", producer="SubversionFetcher")

            storage._write_to_cache(VersionListSchema(), vlist, "versions_old.json")

            makedirs.assert_called_once_with('/some/path/.cache/plugins/better-wp-security', mode=0o755, exist_ok=True)
            m.assert_called_with('/some/path/.cache/plugins/better-wp-security/versions_old.json', 'w')

            handle = m()
            handle.write.assert_called_once_with('{\n    "key": "plugins/better-wp-security",\n    '
                                                 '"producer": "SubversionFetcher"\n}')

    def test_read_from_cache_file_not_found(self):
        m = mock_open()
        m.side_effect = FileNotFoundError()

        with patch('openwebvulndb.common.storage.open', m, create=True):
            storage = Storage('/some/path')
            vlist = VersionList(key="plugins/better-wp-security", producer="SubversionFetcher")

            with self.assertRaises(FileNotFoundError):
                storage._read_from_cache(VersionListSchema(), vlist.key, "versions_old.json")

            m.assert_called_with('/some/path/.cache/plugins/better-wp-security/versions_old.json', 'r')
