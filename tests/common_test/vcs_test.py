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
from fixtures import async_test, fake_future, file_path, freeze_time
from datetime import date

from openwebvulndb.common import RepositoryChecker, Repository
from openwebvulndb.common.vcs import Subversion, SubversionWorkspace
from openwebvulndb.common.errors import ExecutionFailure


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
            cse.return_value = proc
            svn = Subversion(loop=loop)
            svn.has_recursive_externals = MagicMock(return_value=fake_future(False, loop))

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
            cse.return_value = proc
            svn = Subversion(loop=loop)
            svn.has_recursive_externals = MagicMock(return_value=fake_future(False, loop))

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
            cse.return_value = proc
            svn = Subversion(loop=loop)
            svn.has_recursive_externals = MagicMock(return_value=fake_future(False, loop))

            await svn.switch("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")

            cse.assert_called_with("svn", "switch", "--ignore-ancestry", "https://svn.example.com/tags/1.2.3",
                                   cwd="/tmp/foobar",
                                   loop=loop,
                                   stdout=asyncio.subprocess.PIPE,
                                   stdin=asyncio.subprocess.PIPE,
                                   stderr=asyncio.subprocess.PIPE)

            proc.communicate.assert_called_with()

    @async_test()
    async def test_checkout_ignore_externals_if_any_recursive_external(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future((b"out", b"err"), loop=loop)
            proc.returncode = 0
            cse.return_value = proc
            svn = Subversion(loop=loop)
            svn.has_recursive_externals = MagicMock(return_value=fake_future(True, loop))

            await svn.checkout("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")

            cse.assert_called_with("svn", "checkout", "--ignore-externals", "https://svn.example.com/tags/1.2.3", ".",
                                   cwd="/tmp/foobar", loop=loop, stdout=asyncio.subprocess.PIPE,
                                   stdin=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            proc.communicate.assert_called_with()

    @async_test()
    async def test_switch_ignore_externals_if_any_recursive_external(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future((b"out", b"err"), loop=loop)
            proc.returncode = 0
            cse.return_value = proc
            svn = Subversion(loop=loop)
            svn.has_recursive_externals = MagicMock(return_value=fake_future(True, loop))

            await svn.switch("https://svn.example.com/tags/1.2.3", workdir="/tmp/foobar")

            cse.assert_called_with("svn", "switch", "--ignore-ancestry", "--ignore-externals",
                                   "https://svn.example.com/tags/1.2.3", cwd="/tmp/foobar", loop=loop,
                                   stdout=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE,
                                   stderr=asyncio.subprocess.PIPE)
            proc.communicate.assert_called_with()

    @async_test()
    async def test_has_recursive_externals(self, loop):
        svn = Subversion(loop=loop)
        svn.list_externals = MagicMock(side_effect=[
            fake_future([{"name": "plugin", "url": "https://plugins.svn.wordpress.org/plugin"}], loop),
            fake_future([{"name": "valid-external", "url": "https://plugins.svn.wordpress.org/external"}], loop)
        ])

        self.assertTrue(await svn.has_recursive_externals("https://plugins.svn.wordpress.org/plugin/tags/1.0", workdir=None))
        self.assertFalse(await svn.has_recursive_externals("https://plugins.svn.wordpress.org/plugin/tags/1.0", workdir=None))

        svn.list_externals.assert_has_calls([call("https://plugins.svn.wordpress.org/plugin/tags/1.0", workdir=None),
                                             call("https://plugins.svn.wordpress.org/plugin/tags/1.0", workdir=None)])

    @async_test()
    async def test_list_externals(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            out = b"https://plugins.svn.wordpress.org/plugin/tags/1.0 - https://www.some-external.example external\n\n" \
                  b"https://plugins.svn.wordpress.org/plugin/tags/1.0/class - https://www.some-external.example external\n\n" \
                  b"https://plugins.svn.wordpress.org/plugin/tags/1.0/css - external https://www.some-external.example\n\n" \
                  b"https://plugins.svn.wordpress.org/plugin/tags/1.0/languages - external https://www.some-external.example\n\n"
            proc.communicate.return_value = fake_future((out, b""), loop=loop)
            proc.returncode = 0
            cse.return_value = proc

            svn = Subversion(loop=loop)
            svn.info = MagicMock(return_value=fake_future({"url": "https://plugins.svn.wordpress.org/plugin/tags/1.0",
                                                           "root": "https://plugins.svn.wordpress.org/"}, loop=loop))

            externals = await svn.list_externals("https://plugins.svn.wordpress.org/plugin/tags/1.0",
                                                 workdir="/tmp/plugin")

            cse.assert_called_once_with(*("svn", "propget", "-R", "svn:externals",
                                          "https://plugins.svn.wordpress.org/plugin/tags/1.0"),
                                        cwd="/tmp/plugin", loop=loop, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE)
            self.assertEqual(externals, [{"name": "external", "url": "https://www.some-external.example"}]*4)

    @async_test()
    async def test_list_externals_with_relative_path(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            out = b"https://svn.example.com/plugins/plugin/tags/1.0/subdir0 - //svn.example.com/external external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir1 - /external external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir2 - ^/external external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir3 - external ../external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir3 - external ../../external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir3 - ../../../../../external external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir4 - external ^/../repo/external\n\n" \
                  b"https://svn.example.com/plugins/plugin/tags/1.0/subdir4 - external ^/../../../repo/external\n\n"
            proc.communicate.return_value = fake_future((out, b""), loop=loop)
            proc.returncode = 0
            cse.return_value = proc

            svn = Subversion(loop=loop)
            svn.info = MagicMock(return_value=fake_future({"url": "https://svn.example.com/plugins/plugin/tags/1.0",
                                                           "root": "https://svn.example.com/plugins"}, loop=loop))

            externals = await svn.list_externals("https://svn.example.com/plugins/plugin/tags/1.0",
                                                 workdir="/tmp/plugin")

            cse.assert_called_once_with(*("svn", "propget", "-R", "svn:externals",
                                          "https://svn.example.com/plugins/plugin/tags/1.0"),
                                        cwd="/tmp/plugin", loop=loop, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE)
            self.assertEqual(externals, [{"name": "external", "url": "https://svn.example.com/external"},
                                         {"name": "external", "url": "https://svn.example.com/external"},
                                         {"name": "external", "url": "https://svn.example.com/plugins/external"},
                                         {"name": "external",
                                          "url": "https://svn.example.com/plugins/plugin/tags/external"},
                                         {"name": "external",
                                          "url": "https://svn.example.com/plugins/plugin/external"},
                                         {"name": "external", "url": "https://svn.example.com/external"},
                                         {"name": "external", "url": "https://svn.example.com/repo/external"},
                                         {"name": "external", "url": "https://svn.example.com/repo/external"}])

    @async_test()
    async def test_list_externals_no_external(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.return_value = fake_future(
                (b"", b""), loop=loop)
            proc.returncode = 0
            cse.return_value = proc
            svn = Subversion(loop=loop)

            externals = await svn.list_externals("https://plugins.svn.wordpress.org/plugin/tags/1.0",
                                                 workdir="/tmp/plugin")

            cse.assert_called_once_with(*("svn", "propget", "-R", "svn:externals",
                                          "https://plugins.svn.wordpress.org/plugin/tags/1.0"),
                                        cwd="/tmp/plugin", loop=loop, stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.PIPE)
            self.assertEqual(externals, [])

    @async_test()
    async def test_svn_info(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.communicate.side_effect = [fake_future((b"https://plugins.svn.wordpress.org/plugin/tags/1.0\n", b""),
                                                        loop=loop),
                                            fake_future((b"https://plugins.svn.wordpress.org\n", b""), loop=loop)]
            proc.returncode = 0
            cse.return_value = proc
            svn = Subversion(loop=loop)

            info = await svn.info("https://plugins.svn.wordpress.org/plugin/tags/1.0", workdir="/tmp/plugin")

            cse.assert_has_calls(
                [call(*("svn", "info", "--show-item", "url", "https://plugins.svn.wordpress.org/plugin/tags/1.0"),
                      cwd="/tmp/plugin", loop=loop, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                      stdin=asyncio.subprocess.PIPE),
                 call().communicate(),
                 call(*("svn", "info", "--show-item", "repos-root-url", "https://plugins.svn.wordpress.org/plugin/tags/1.0"),
                      cwd="/tmp/plugin", loop=loop, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                      stdin=asyncio.subprocess.PIPE)])

            self.assertEqual(info, {"url": "https://plugins.svn.wordpress.org/plugin/tags/1.0",
                                    "root": "https://plugins.svn.wordpress.org"})

    @async_test()
    async def test_svn_get_last_release_date_of_components_return_last_modification_date_of_tags_folder(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.stdout.readline.side_effect = [
                fake_future(b"svn: warning: W160013: URL 'http://themes.svn.wordpress.org/tags' non-existent in revision 83065", loop=loop),
                fake_future(b"1749964 user1               Oct 20 11:15 ./\n", loop=loop),
                fake_future(b"1077807 user 2              Jan 28  2015 plugin-1/\n", loop=loop),
                fake_future(b"1385952 user.3              Apr 04  2016 plugin-2/", loop=loop),
                fake_future(b"svn: E200009: Could not list all targets because some targets don't exist", loop=loop)]
            proc.stdout.at_eof.side_effect = [False, False, False, False, False, True]
            proc.wait.return_value = fake_future(0, loop=loop)
            cse.return_value = proc
            svn = Subversion(loop=loop)

            plugins = await svn._get_last_release_date_of_components("plugins", "http://plugins.svn.wordpress.org/")

            cse.assert_has_calls([call(*("svn", "ls", "-v", "^/tags", "http://plugins.svn.wordpress.org/"), loop=loop,
                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                                       stdin=asyncio.subprocess.DEVNULL)])
            self.assertEqual(plugins, {"plugins/plugin-1": date(year=2015, month=1, day=28),
                                       "plugins/plugin-2": date(year=2016, month=4, day=4)})

    @async_test()
    async def test_svn_get_last_release_date_of_components_replace_hours_with_current_year(self, loop):
        with patch('openwebvulndb.common.vcs.create_subprocess_exec') as cse:
            proc = MagicMock()
            proc.stdout.readline.return_value = \
                fake_future(b"1749964 user1               Oct 20 11:15 plugin-1/\n", loop=loop)
            proc.stdout.at_eof.side_effect = [False, True]
            proc.wait.return_value = fake_future(0, loop=loop)
            cse.return_value = proc
            svn = Subversion(loop=loop)

            plugins = await svn._get_last_release_date_of_components("plugins", "http://plugins.svn.wordpress.org/")

            self.assertEqual(plugins, {"plugins/plugin-1": date(year=date.today().year, month=10, day=20)})

    @freeze_time(date(year=2017, day=22, month=10))
    @async_test()
    async def test_svn_get_components_with_new_release(self, loop):
        themes = {"themes/theme-0": date(year=2017, month=10, day=20),
                   "themes/theme-1": date(year=2016, month=4, day=4),
                   "themes/theme-2": date(year=2015, month=10, day=21),
                   "themes/theme-3": date(year=2017, month=10, day=6)}
        svn = Subversion(loop=None)
        svn._get_last_release_date_of_components = MagicMock(return_value=fake_future(themes, loop=loop))

        recently_updated = await svn.get_components_with_new_release("themes", "http://themes.svn.wordpress.org/",
                                                                     date(year=2017, day=6, month=10))

        self.assertEqual(recently_updated, {"themes/theme-0", "themes/theme-3"})

    @async_test()
    async def test_svn_get_components_with_new_release_return_empty_set_if_command_timeout(self, loop):
        svn = Subversion(loop=None)
        fut = asyncio.Future(loop=loop)
        fut.set_exception(ExecutionFailure("Timeout reached"))
        svn._get_last_release_date_of_components = MagicMock(return_value=fut)

        result = await svn.get_components_with_new_release("plugins", "http://plugins.svn.example.com/", date.today())

        self.assertEqual(result, set())


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

    @async_test()
    async def test_list_versions_skip_versions_without_digit(self, fake_future):
        svn = MagicMock()
        svn.ls.return_value = fake_future(["1.0/", "1.1/", "trunk/"])

        workspace = SubversionWorkspace(workdir="/tmp/foo", subversion=svn, repository="https://svn.test.com/")

        versions = await workspace.list_versions()

        self.assertEqual(versions, ["1.0", "1.1"])
