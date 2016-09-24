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

import asyncio
from unittest import TestCase
from unittest.mock import MagicMock, call, patch
from fixtures import async_test, fake_future, file_path

from openwebvulndb.common import RepositoryChecker, Repository
from openwebvulndb.common.vcs import Subversion, SubversionWorkspace
from openwebvulndb.common.errors import ExecutionFailure, DirectoryExpected


class VersionControlTest(TestCase):
    svnrepo = Repository(type="subversion", location="http://example.com/")
    badrepo = Repository(type="cvs", location="http://example.com/")

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
    async def test_check_unsupported_repository(self, loop):
        checker = RepositoryChecker(subversion=MagicMock())

        self.assertFalse(await checker.has_content(self.badrepo))

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
    async def test_execute_checkout(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future((b"out", b"err"), loop=loop)
            proc.returncode = 0
            cse.return_value = fake_future(proc, loop=loop)

            svn = Subversion(loop=loop)
            await svn.checkout("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")

            cse.assert_called_with("svn", "checkout", "https://svn.example.com/tags/1.2.3", ".",
                                   cwd="/tmp/foobar",
                                   loop=loop,
                                   stdout=asyncio.subprocess.PIPE,
                                   stdin=asyncio.subprocess.PIPE,
                                   stderr=asyncio.subprocess.PIPE)

            proc.communicate.assert_called_with()

    @async_test()
    async def test_execute_handle_error(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future((b"out", b"err"), loop=loop)
            proc.returncode = 1
            cse.return_value = fake_future(proc, loop=loop)

            svn = Subversion(loop=loop)
            with self.assertRaises(ExecutionFailure):
                await svn.checkout("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")

            cse.assert_called_with("svn", "checkout", "https://svn.example.com/tags/1.2.3", ".",
                                   cwd="/tmp/foobar",
                                   loop=loop,
                                   stdout=asyncio.subprocess.PIPE,
                                   stdin=asyncio.subprocess.PIPE,
                                   stderr=asyncio.subprocess.PIPE)

            proc.communicate.assert_called_with()

    @async_test()
    async def test_execute_switch(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future((b"out", b"err"), loop=loop)
            proc.returncode = 0
            cse.return_value = fake_future(proc, loop=loop)

            svn = Subversion(loop=loop)
            await svn.switch("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")

            cse.assert_called_with("svn", "switch", "--ignore-ancestry", "https://svn.example.com/tags/1.2.3",
                                   cwd="/tmp/foobar",
                                   loop=loop,
                                   stdout=asyncio.subprocess.PIPE,
                                   stdin=asyncio.subprocess.PIPE,
                                   stderr=asyncio.subprocess.PIPE)

            proc.communicate.assert_called_with()

    @async_test()
    async def test_execute_switch(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future(("out", b"svn: E200007: some file refers to a file, not a directory\n"), loop=loop)
            proc.returncode = 1
            cse.return_value = fake_future(proc, loop=loop)

            svn = Subversion(loop=loop)
            with self.assertRaises(DirectoryExpected):
                await svn.switch("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")


class SubversionWorkspaceTest(TestCase):

    @async_test()
    async def test_create_and_destroy_workspace(self, loop):

        with \
                patch('openwebvulndb.common.vcs.uuid4') as uuid4, \
                patch('openwebvulndb.common.vcs.rmdir') as rmdir, \
                patch('openwebvulndb.common.vcs.remove') as remove, \
                patch('openwebvulndb.common.vcs.walk') as walk, \
                patch('openwebvulndb.common.vcs.mkdir') as mkdir:

            uuid4.return_value = "1234-1234"
            svn = Subversion(loop=loop, svn_base_dir="/temp/")
            walk.return_value = [
                ("/temp/1234-1234/foo", [], ["test.txt"]),
                ("/temp/1234-1234", ["foo"], ["test.html", "index.html"]),
            ]

            with svn.workspace(repository="https://svn.example.com/") as workspace:
                self.assertEqual(workspace.workdir, "/temp/1234-1234")
                self.assertEqual(workspace.repository, "https://svn.example.com/")

                mkdir.assert_called_with("/temp/1234-1234", mode=0o755)
                rmdir.assert_not_called()

            walk.assert_called_with("/temp/1234-1234", topdown=False)
            remove.assert_has_calls([
                call("/temp/1234-1234/foo/test.txt"),
                call("/temp/1234-1234/test.html"),
                call("/temp/1234-1234/index.html"),
            ])
            rmdir.assert_has_calls([
                call("/temp/1234-1234/foo"),
                call("/temp/1234-1234"),
            ])

    @async_test()
    async def test_classic_structure(self, loop):

        svn = Subversion(loop=loop, svn_base_dir="/temp/")
        svn.ls = lambda p: fake_future(['tags/', 'trunk/', 'branches/'], loop=loop)

        workspace = SubversionWorkspace(workdir="/tmp/foo", subversion=svn, repository="https://svn.example.com/")
        self.assertEqual(workspace.repository, "https://svn.example.com/")

        await workspace.prepare()

        svn.ls = lambda p: fake_future(['1.2/', '2.0/', '2.1/'], loop=loop)
        self.assertEqual(workspace.repository, "https://svn.example.com/tags/")
        self.assertEqual(["1.2", "2.0", "2.1"], await workspace.list_versions())

    @async_test()
    async def test_flat_structure(self, loop):

        svn = Subversion(loop=loop, svn_base_dir="/temp/")
        svn.ls = lambda p: fake_future(['1.0/', '1.1/'], loop=loop)

        workspace = SubversionWorkspace(workdir="/tmp/foo", subversion=svn, repository="https://svn.example.com/")
        self.assertEqual(workspace.repository, "https://svn.example.com/")

        await workspace.prepare()

        self.assertEqual(workspace.repository, "https://svn.example.com/")

        self.assertEqual(["1.0", "1.1"], await workspace.list_versions())

    @async_test()
    async def test_flat_does_not_alter_repo(self, loop):

        svn = Subversion(loop=loop, svn_base_dir="/temp/")
        svn.ls = lambda p: fake_future(['1.0/', '1.1/'], loop=loop)

        workspace = SubversionWorkspace(workdir="/tmp/foo", subversion=svn, repository="https://svn.example.com/")
        self.assertEqual(workspace.repository, "https://svn.example.com/")

        await workspace.prepare()

        self.assertEqual(workspace.repository, "https://svn.example.com/")

    @async_test()
    async def test_checkout_and_switch(self, fake_future):
        svn = MagicMock()
        svn.checkout.return_value = fake_future(None)
        svn.switch.return_value = fake_future(None)

        workspace = SubversionWorkspace(workdir="/tmp/foo", subversion=svn, repository="https://svn.example.com/")

        await workspace.to_version("1.0")

        svn.checkout.assert_called_with("https://svn.example.com/1.0", workdir="/tmp/foo")
        svn.reset_mock()

        await workspace.to_version("1.1")

        svn.switch.assert_called_with("https://svn.example.com/1.1", workdir="/tmp/foo")
