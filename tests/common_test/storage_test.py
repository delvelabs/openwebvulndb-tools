import uuid
from unittest import TestCase
from unittest.mock import mock_open, patch, call
from fixtures import file_path

from openwebvulndb.common import Storage, Meta


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
            handle.write.assert_called_once_with("""
{
    "key": "plugins/better-wp-security",
    "name": "iThemes Security"
}""".strip())

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
