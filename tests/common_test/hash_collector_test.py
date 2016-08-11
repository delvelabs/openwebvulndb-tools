from unittest import TestCase
from unittest.mock import MagicMock, call, patch, mock_open
from contextlib import contextmanager

from fixtures import async_test

from openwebvulndb.common.errors import ExecutionFailure
from openwebvulndb.common.hash import HashCollector, Hasher, VersionChecker, RepositoryHasher
from openwebvulndb.common.models import Signature, VersionList, Meta, Repository


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
            self.assertTrue(signatures[0].dirty)

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

    def test_exclude_version_control_files(self):
        with patch('openwebvulndb.common.hash.walk') as walk:
            walk.return_value = [
                ("/some/path/random1234", ["hidden", ".git"], ["readme.txt", "license.txt", "index.php"]),
                ("/some/path/random1234/.git", [], ["HEAD"]),
                ("/some/path/random1234/hidden", [".svn"], []),
                ("/some/path/random1234/hidden/.svn", ["pristine"], []),
                ("/some/path/random1234/hidden/.svn/pristine", ["da"], []),
                ("/some/path/random1234/hidden/.svn/pristine/da", [], ["da9d42e33e31a89b8e43713fdf6d481a90346b3b.svn-base"]),  # noqa
            ]
            collector = HashCollector(path="/some/path/random1234", hasher=MagicMock(),
                                      prefix="wp-content/plugins/my-plugin")
            collector.hasher.algo = "CONST"
            collector.hasher.hash.return_value = "12345"

            signatures = list(collector.collect())

            walk.assert_called_with("/some/path/random1234")

            self.assertEqual(2, len(signatures))

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


class RepositoryHasherTest(TestCase):

    @async_test()
    async def test_collect_from_meta(self, fake_future):
        workspace = MagicMock()
        workspace.prepare.return_value = fake_future(None)

        @contextmanager
        def workspace_provider(repository):
            self.assertEqual(repository, "https://svn.example.com")
            yield workspace

        subversion = MagicMock()
        subversion.workspace = workspace_provider

        meta = Meta(key="wordpress", name="WordPress", repositories=[
            Repository(type="subversion", location="https://svn.example.com"),
        ])
        hasher = RepositoryHasher(storage=MagicMock(), hasher=MagicMock(), subversion=subversion)
        hasher.collect_for_workspace = MagicMock()
        hasher.collect_for_workspace.return_value = fake_future(None)
        await hasher.collect_from_meta(meta)

        workspace.prepare.assert_called_once_with()
        hasher.collect_for_workspace.assert_called_with("wordpress", workspace, prefix="")

    @async_test()
    async def test_with_multiple_repos(self, fake_future):
        workspace = MagicMock()
        workspace.prepare.return_value = fake_future(None)

        @contextmanager
        def workspace_provider(repository):
            self.assertEqual(repository, "https://svn.example.com")
            yield workspace

        subversion = MagicMock()
        subversion.workspace = workspace_provider

        meta = Meta(key="wordpress", name="WordPress", repositories=[
            Repository(type="cvs", location="1990s"),
            Repository(type="subversion", location="https://svn.example.com"),
            Repository(type="subversion", location="https://mirror.example.com"),
        ])
        hasher = RepositoryHasher(storage=MagicMock(), hasher=MagicMock(), subversion=subversion)
        hasher.collect_for_workspace = MagicMock()
        hasher.collect_for_workspace.return_value = fake_future(None)
        self.assertTrue(await hasher.collect_from_meta(meta))

        workspace.prepare.assert_called_once_with()

    @async_test()
    async def test_collect_from_meta_for_plugin(self, fake_future):
        workspace = MagicMock()
        workspace.prepare.return_value = fake_future(None)

        @contextmanager
        def workspace_provider(repository):
            self.assertEqual(repository, "https://svn.example.com/a-plugin")
            yield workspace

        subversion = MagicMock()
        subversion.workspace = workspace_provider

        meta = Meta(key="plugins/a-plugin", name="A Plugin", repositories=[
            Repository(type="subversion", location="https://svn.example.com/a-plugin"),
        ])
        hasher = RepositoryHasher(storage=MagicMock(), hasher=MagicMock(), subversion=subversion)
        hasher.collect_for_workspace = MagicMock()
        hasher.collect_for_workspace.return_value = fake_future(None)
        self.assertTrue(await hasher.collect_from_meta(meta, prefix_pattern="wp-content/{meta.key}"))

        workspace.prepare.assert_called_once_with()
        hasher.collect_for_workspace.assert_called_with("plugins/a-plugin", workspace,
                                                        prefix="wp-content/plugins/a-plugin")

    @async_test()
    async def test_brand_new_file(self, fake_future):
        workspace = MagicMock()
        workspace.list_versions.return_value = fake_future(["1.0", "10.1", "2.0"])

        hasher = RepositoryHasher(storage=MagicMock(), hasher=MagicMock())
        hasher.collect_for_version = MagicMock()
        hasher.collect_for_version.return_value = fake_future([
            Signature(path="wp-content/plugins/a-plugin/readme.txt", hash="12345")])

        hasher.storage.read_versions.side_effect = FileNotFoundError()

        await hasher.collect_for_workspace("plugins/a-plugin", workspace, prefix="wp-content/plugins/a-plugin")

        hasher.storage.read_versions.assert_called_with("plugins/a-plugin")
        hasher.collect_for_version.assert_has_calls([
            call(workspace, "1.0", prefix="wp-content/plugins/a-plugin"),
            call(workspace, "2.0", prefix="wp-content/plugins/a-plugin"),
            call(workspace, "10.1", prefix="wp-content/plugins/a-plugin"),
        ], any_order=False)

        expect = VersionList(producer="RepositoryHasher", key="plugins/a-plugin")
        v1 = expect.get_version("1.0", create_missing=True)
        v1.add_signature("wp-content/plugins/a-plugin/readme.txt", hash="12345")
        v2 = expect.get_version("2.0", create_missing=True)
        v2.add_signature("wp-content/plugins/a-plugin/readme.txt", hash="12345")
        v10 = expect.get_version("10.1", create_missing=True)
        v10.add_signature("wp-content/plugins/a-plugin/readme.txt", hash="12345")

        hasher.storage.write_versions.assert_called_with(expect)

    @async_test()
    async def test_execution_failures(self, fake_future):
        workspace = MagicMock()
        workspace.list_versions.return_value = fake_future(["1.0", "10.1", "2.0"])

        hasher = RepositoryHasher(storage=MagicMock(), hasher=MagicMock())
        hasher.collect_for_version = MagicMock()
        hasher.collect_for_version.side_effect = ExecutionFailure()

        hasher.storage.read_versions.side_effect = FileNotFoundError()

        await hasher.collect_for_workspace("plugins/a-plugin", workspace, prefix="wp-content/plugins/a-plugin")

        hasher.storage.read_versions.assert_called_with("plugins/a-plugin")
        hasher.collect_for_version.assert_has_calls([
            call(workspace, "1.0", prefix="wp-content/plugins/a-plugin"),
        ], any_order=False)

        expect = VersionList(producer="RepositoryHasher", key="plugins/a-plugin")

        hasher.storage.write_versions.assert_called_with(expect)

    @async_test()
    async def test_skip_loaded_versions(self, fake_future):
        workspace = MagicMock()
        workspace.list_versions.return_value = fake_future(["1.0", "10.1", "2.0"])

        hasher = RepositoryHasher(storage=MagicMock(), hasher=MagicMock())
        hasher.collect_for_version = MagicMock()
        hasher.collect_for_version.return_value = fake_future([
            Signature(path="wp-content/plugins/a-plugin/readme.txt", hash="12345")])

        stored = VersionList(producer="RepositoryHasher", key="plugins/a-plugin")
        stored.get_version("1.0", create_missing=True)
        stored.get_version("2.0", create_missing=True)

        hasher.storage.read_versions.return_value = stored

        await hasher.collect_for_workspace("plugins/a-plugin", workspace, prefix="wp-content/plugins/a-plugin")

        hasher.storage.read_versions.assert_called_with("plugins/a-plugin")
        hasher.collect_for_version.assert_called_once_with(workspace, "10.1", prefix="wp-content/plugins/a-plugin")

    @async_test()
    async def test_collect_for_one_version(self, fake_future):
        with patch("openwebvulndb.common.hash.HashCollector") as HashCollector:
            workspace = MagicMock()
            workspace.workdir = "/my/workspace/path"
            workspace.to_version.return_value = fake_future(None)

            collector = MagicMock()
            collector.collect.return_value = ["Hello"]
            HashCollector.return_value = collector

            hasher = RepositoryHasher(storage=MagicMock(), hasher=Hasher("SHA256"))
            out = await hasher.collect_for_version(workspace, "2.1", prefix="test-prefix")

            self.assertEqual(["Hello"], out)

            HashCollector.assert_called_with(path="/my/workspace/path", hasher=hasher.hasher,
                                             prefix="test-prefix", lookup_version="2.1")

            collector.collect.assert_called_with()

            workspace.to_version.assert_called_with("2.1")
