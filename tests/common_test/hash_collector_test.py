from unittest import TestCase
from unittest.mock import MagicMock, call, patch, mock_open

from openwebvulndb.common.hash import HashCollector, Hasher, VersionChecker
from openwebvulndb.common.models import Signature


class HashCollectorTest(TestCase):

    def test_collect_files(self):
        with patch('openwebvulndb.common.hash.walk') as walk:
            walk.return_value = [
                ("/some/path/random1234", ["js", "css"], ["readme.txt", "license.txt"]),
                ("/some/path/random1234/js", [], ["index.js"]),
                ("/some/path/random1234/css", [], ["custom.css"]),
            ]
            collector = HashCollector(path="/some/path/random1234", hasher=MagicMock(),
                                      prefix="wp-content/plugins/my-plugin")
            collector.hasher.algo = "CONST"
            collector.hasher.hash.return_value = "12345"

            signatures = list(collector.collect())

            walk.assert_called_with("/some/path/random1234")

            collector.hasher.hash.assert_has_calls([
                call("/some/path/random1234/readme.txt", chunk_cb=collector.version_checker),
                call("/some/path/random1234/license.txt", chunk_cb=collector.version_checker),
                call("/some/path/random1234/css/custom.css", chunk_cb=collector.version_checker),
                call("/some/path/random1234/js/index.js", chunk_cb=collector.version_checker),
            ], any_order=True)

            self.assertIn(Signature(path="wp-content/plugins/my-plugin/readme.txt", hash="12345", algo="CONST"),
                          signatures)
            self.assertIn(Signature(path="wp-content/plugins/my-plugin/css/custom.css", hash="12345", algo="CONST"),
                          signatures)

    def test_exclude_php_files(self):
        with patch('openwebvulndb.common.hash.walk') as walk:
            walk.return_value = [
                ("/some/path/random1234", ["js", "css"], ["readme.txt", "license.txt", "index.php"]),
                ("/some/path/random1234/js", [], ["index.js", "index.php"]),
                ("/some/path/random1234/css", [], ["custom.css", "index.php"]),
            ]
            collector = HashCollector(path="/some/path/random1234", hasher=MagicMock(),
                                      prefix="wp-content/plugins/my-plugin")
            collector.hasher.algo = "CONST"
            collector.hasher.hash.return_value = "12345"

            signatures = list(collector.collect())

            walk.assert_called_with("/some/path/random1234")

            self.assertNotIn(Signature(path="wp-content/plugins/my-plugin/index.php", hash="12345", algo="CONST"),
                             signatures)
            self.assertNotIn(Signature(path="wp-content/plugins/my-plugin/js/index.php", hash="12345", algo="CONST"),
                             signatures)
            self.assertNotIn(Signature(path="wp-content/plugins/my-plugin/css/index.php", hash="12345", algo="CONST"),
                             signatures)

    def test_flag_as_containing_version(self):
        class FakeHasher:
            algo = "CUST"

            def hash(hasher, file_path, chunk_cb):
                if file_path == "/some/path/random1234/readme.txt":
                    chunk_cb(b"Readme for version 1.2.3 test")
                    chunk_cb(b"weird chunk")
                elif file_path == "/some/path/random1234/license.txt":
                    chunk_cb(b"MIT...")
                else:
                    raise FileNotFoundError()
                return "12345"

        with patch('openwebvulndb.common.hash.walk') as walk:
            walk.return_value = [
                ("/some/path/random1234", [], ["readme.txt", "license.txt", "index.php"]),
            ]
            collector = HashCollector(path="/some/path/random1234", hasher=FakeHasher(),
                                      prefix="wp-content/plugins/my-plugin", lookup_version="1.2.3")

            signatures = list(collector.collect())

            self.assertIn(Signature(path="wp-content/plugins/my-plugin/readme.txt",
                                    hash="12345", algo="CUST", contains_version=True), signatures)
            self.assertIn(Signature(path="wp-content/plugins/my-plugin/license.txt", hash="12345", algo="CUST"),
                          signatures)


class HasherTest(TestCase):

    def test_hash_sha256(self):
        m = mock_open(read_data=b"hello world")

        with patch('openwebvulndb.common.hash.open', m, create=True):
            hasher = Hasher('SHA256')
            self.assertEqual('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9',
                             hasher.hash("/some/file.txt"))

    def test_hash_md5(self):
        m = mock_open(read_data=b"hello world")

        with patch('openwebvulndb.common.hash.open', m, create=True):
            hasher = Hasher('MD5')
            self.assertEqual('5eb63bbbe01eeed093cb22bb8f5acdc3', hasher.hash("/some/file.txt"))

    def test_callback_applied_to_chunks(self):
        m = mock_open(read_data=b"hello world")

        with patch('openwebvulndb.common.hash.open', m, create=True):
            check_chunk = MagicMock()

            hasher = Hasher('SHA256')
            hasher.hash("/some/file.txt", chunk_cb=check_chunk)

            check_chunk.assert_called_with(b"hello world")


class VersionCheckerTest(TestCase):

    def test_checker_no_version(self):
        checker = VersionChecker(None)
        checker(b"hello world")
        self.assertIsNone(checker.contains_version)

    def test_checker_version_not_found(self):
        checker = VersionChecker("1.2")
        checker(b"hello world")
        self.assertIsNone(checker.contains_version)

    def test_checker_version_found(self):
        checker = VersionChecker("1.2")
        checker(b"hello world 1.2")
        self.assertTrue(checker.contains_version)

    def test_checker_version_found_multichunk(self):
        checker = VersionChecker("1.2")
        checker(b"hello world")
        checker(b"hello world 1.2")
        checker(b"hello world")
        self.assertTrue(checker.contains_version)

    def test_checker_version_found_but_resets(self):
        checker = VersionChecker("1.2")
        checker(b"hello world 1.2")
        checker.reset()
        self.assertIsNone(checker.contains_version)
