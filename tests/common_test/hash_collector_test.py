from unittest import TestCase
from unittest.mock import MagicMock, call, patch, mock_open

from openwebvulndb.common.hash import HashCollector, Hasher
from openwebvulndb.common.models import Signature


class HashCollectorTest(TestCase):

    def test_collect_files(self):
        with patch('openwebvulndb.common.hash.walk') as walk:
            walk.return_value = [
                ("/some/path/random1234", ["js", "css"], ["readme.txt", "license.txt"]),
                ("/some/path/random1234/js", [], ["index.js"]),
                ("/some/path/random1234/css", [], ["custom.css"]),
            ]
            collector = HashCollector(path="/some/path/random1234", hasher=MagicMock(), prefix="wp-content/plugins/my-plugin")
            collector.hasher.algo = "CONST"
            collector.hasher.hash.return_value = "12345"

            signatures = list(collector.collect())

            walk.assert_called_with("/some/path/random1234")

            collector.hasher.hash.assert_has_calls([
                call("/some/path/random1234/readme.txt"),
                call("/some/path/random1234/license.txt"),
                call("/some/path/random1234/css/custom.css"),
                call("/some/path/random1234/js/index.js"),
            ], any_order=True)

            self.assertIn(Signature(path="wp-content/plugins/my-plugin/readme.txt", hash="12345", algo="CONST"), signatures)
            self.assertIn(Signature(path="wp-content/plugins/my-plugin/css/custom.css", hash="12345", algo="CONST"), signatures)

    def test_exclude_php_files(self):
        with patch('openwebvulndb.common.hash.walk') as walk:
            walk.return_value = [
                ("/some/path/random1234", ["js", "css"], ["readme.txt", "license.txt", "index.php"]),
                ("/some/path/random1234/js", [], ["index.js", "index.php"]),
                ("/some/path/random1234/css", [], ["custom.css", "index.php"]),
            ]
            collector = HashCollector(path="/some/path/random1234", hasher=MagicMock(), prefix="wp-content/plugins/my-plugin")
            collector.hasher.algo = "CONST"
            collector.hasher.hash.return_value = "12345"

            signatures = list(collector.collect())

            walk.assert_called_with("/some/path/random1234")

            self.assertNotIn(Signature(path="wp-content/plugins/my-plugin/index.php", hash="12345", algo="CONST"), signatures)
            self.assertNotIn(Signature(path="wp-content/plugins/my-plugin/js/index.php", hash="12345", algo="CONST"), signatures)
            self.assertNotIn(Signature(path="wp-content/plugins/my-plugin/css/index.php", hash="12345", algo="CONST"), signatures)


class HasherTest(TestCase):

    def test_hash_sha256(self):
        m = mock_open(read_data=b"hello world")

        with patch('openwebvulndb.common.hash.open', m, create=True):
            hasher = Hasher('SHA256')
            self.assertEqual('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9', hasher.hash("/some/file.txt"))

    def test_hash_md5(self):
        m = mock_open(read_data=b"hello world")

        with patch('openwebvulndb.common.hash.open', m, create=True):
            hasher = Hasher('MD5')
            self.assertEqual('5eb63bbbe01eeed093cb22bb8f5acdc3', hasher.hash("/some/file.txt"))
