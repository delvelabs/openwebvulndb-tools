from unittest import TestCase
from unittest.mock import MagicMock, call
from fixtures import async_test, fake_future, file_path

from openwebvulndb.common import RepositoryChecker, Repository
from openwebvulndb.common.vcs import Subversion


class VersionControlTest(TestCase):
    svnrepo = Repository(type="subversion", location="http://example.com/")

    @async_test()
    async def test_check_repository_content_empty_svn(self, loop):
        checker = RepositoryChecker(subversion=MagicMock())
        checker.subversion.ls.side_effect = [
            fake_future([], loop),
        ]

        self.assertFalse(await checker.has_content(self.svnrepo))
        checker.subversion.ls.assert_has_calls([
            call("http://example.com/"),
        ])

    @async_test()
    async def test_check_repository_has_classic_structure_but_empty_tags(self, loop):
        checker = RepositoryChecker(subversion=MagicMock())
        checker.subversion.ls.side_effect = [
            fake_future(['branches/', 'tags/', 'trunk/', 'somefile.txt'], loop),
            fake_future([], loop),
        ]

        self.assertFalse(await checker.has_content(self.svnrepo))
        checker.subversion.ls.assert_has_calls([
            call("http://example.com/"),
            call("http://example.com/tags"),
        ])

    @async_test()
    async def test_check_repository_has_classic_structure_and_data(self, loop):
        checker = RepositoryChecker(subversion=MagicMock())
        checker.subversion.ls.side_effect = [
            fake_future(['branches/', 'tags/', 'trunk/', 'somefile.txt'], loop),
            fake_future(['1.0/', '1.1/', '1.2/'], loop),
        ]

        self.assertTrue(await checker.has_content(self.svnrepo))
        checker.subversion.ls.assert_has_calls([
            call("http://example.com/"),
            call("http://example.com/tags"),
        ])

    @async_test()
    async def test_straight_version_listing(self, loop):
        checker = RepositoryChecker(subversion=MagicMock())
        checker.subversion.ls.side_effect = [
            fake_future(['1.0/', '1.1/', '1.2/'], loop),
        ]

        self.assertTrue(await checker.has_content(self.svnrepo))
        checker.subversion.ls.assert_has_calls([
            call("http://example.com/"),
        ])


class SubversionTest(TestCase):

    @async_test()
    async def test_build_command(self, loop):
        svn = Subversion(loop=loop)
        self.assertEqual(["svn", "ls", "http://example.com"], svn.build_ls("http://example.com"))

    @async_test()
    async def test_execute_ls(self, loop):
        svn = Subversion(loop=loop)
        svn.build_ls = MagicMock()
        svn.build_ls.return_value = ["cat", file_path(__file__, "svn.ls.empty.txt")]

        out = await svn.ls("foobar")
        self.assertEqual([], out)

        svn.build_ls.assert_called_once_with("foobar")

    @async_test()
    async def test_execute_ls(self, loop):
        svn = Subversion(loop=loop)
        svn.build_ls = MagicMock()
        svn.build_ls.return_value = ["cat", file_path(__file__, "svn.ls.standard.txt")]

        out = await svn.ls("foobar")
        self.assertEqual(['branches/', 'tags/', 'trunk/'], out)

        svn.build_ls.assert_called_once_with("foobar")
