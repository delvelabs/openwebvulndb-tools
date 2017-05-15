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
from unittest.mock import MagicMock, patch, ANY, call
from openwebvulndb.wordpress.vane2.release import compress_exported_files, GitHubRelease
from os.path import join
from fixtures import async_test
from aiohttp.test_utils import make_mocked_coro


class TestGitHubRelease(TestCase):

    def test_set_repository_settings_merge_api_url_with_repo_owner_and_name(self):
        release = GitHubRelease()

        release.set_repository_settings("Owner", "repository_name")

        self.assertEqual(release.url, "https://api.github.com/repos/Owner/repository_name")

    @async_test()
    async def test_get_latest_release_version_request_latest_release_as_json_to_github_api(self, loop):
        release = GitHubRelease()
        release.aiohttp_session = MagicMock()
        response = MagicMock()
        response.json = make_mocked_coro(return_value={"tag_name": "1.0"})
        release.aiohttp_session.get = make_mocked_coro(return_value=response)
        release.set_repository_settings("Owner", "repository_name")

        await release.get_latest_release_version()

        release.aiohttp_session.get.assert_called_once_with(
            "https://api.github.com/repos/Owner/repository_name/releases/latest")

    @async_test()
    async def test_get_latest_release_version_return_tag_name_from_response(self, loop):
        release = GitHubRelease()
        release.aiohttp_session = MagicMock()
        response = MagicMock()
        response.json = make_mocked_coro(return_value={"tag_name": "1.0"})
        release.aiohttp_session.get = make_mocked_coro(return_value=response)
        release.set_repository_settings("Owner", "repository_name")

        version = await release.get_latest_release_version()

        self.assertEqual(version, "1.0")


class TestRelease(TestCase):

    def setUp(self):
        self.files_in_dir = ["file1.txt", "file2.txt"]
        self.dir_path = "files/to/compress"
        self.fake_glob = MagicMock(return_value=[join(self.dir_path, self.files_in_dir[0]),
                                                 join(self.dir_path, self.files_in_dir[1])])
        glob_patch = patch("openwebvulndb.wordpress.vane2.release.glob", self.fake_glob)
        glob_patch.start()
        self.addCleanup(glob_patch.stop)

    def test_compress_exported_files_create_tar_archives_with_all_files_in_directory(self):
        dir_path = "files/to/compress"
        fake_tarfile_obj = MagicMock()
        fake_tarfile_open = MagicMock()
        fake_tarfile_open.return_value = fake_tarfile_obj

        with(patch("openwebvulndb.wordpress.vane2.release.tarfile.open", fake_tarfile_open)):
            compress_exported_files(dir_path)

            fake_tarfile_open.assert_called_once_with(ANY, "w:gz")
            fake_tarfile_obj.add.assert_has_calls([call(join(dir_path, self.files_in_dir[0]), self.files_in_dir[0]),
                                                   call(join(dir_path, self.files_in_dir[1]), self.files_in_dir[1])],
                                                  any_order=True)

    def test_compress_exported_files_use_version_to_release_in_archive_name(self):
        dir_path = "files/to/compress"
        fake_tarfile_open = MagicMock()
        fake_get_release_version = MagicMock()
        fake_get_release_version.return_value = "1.3"

        with(patch("openwebvulndb.wordpress.vane2.release.tarfile.open", fake_tarfile_open)):
            with(patch("openwebvulndb.wordpress.vane2.release.get_release_version", fake_get_release_version)):
                compress_exported_files(dir_path)

                fake_get_release_version.assert_called_once_with(ANY)
                fake_tarfile_open.assert_called_once_with(dir_path + "/vane2_data_1.3.tar.gz", ANY)

    def test_get_release_version_request_latest_release_from_repository(self):
        pass
