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
from openwebvulndb.wordpress.vane2.release import GitHubRelease
from os.path import join
from fixtures import async_test, ClientSessionMock
from aiohttp.test_utils import make_mocked_coro
import json
from aiohttp import BasicAuth


class TestGitHubRelease(TestCase):

    def setUp(self):
        self.release = GitHubRelease()
        self.release.set_repository_settings("Owner", "password", "repository_name")

        self.release.aiohttp_session = ClientSessionMock()

        self.files_in_dir = ["file1.json", "file2.json"]
        self.dir_path = "files/to/compress"
        self.fake_glob = MagicMock(return_value=[join(self.dir_path, self.files_in_dir[0]),
                                            join(self.dir_path, self.files_in_dir[1])])
        glob_patch = patch("openwebvulndb.wordpress.vane2.release.glob", self.fake_glob)
        glob_patch.start()
        self.addCleanup(glob_patch.stop)

    def test_set_repository_settings_merge_api_url_with_repo_owner_and_name(self):
        self.release.set_repository_settings("Owner", None, "repository_name")

        self.assertEqual(self.release.url, "https://api.github.com/repos/Owner/repository_name")

    @async_test()
    async def test_get_latest_release_request_latest_release_as_json_to_github_api(self):
        await self.release.get_latest_release()

        self.release.aiohttp_session.get.assert_called_once_with(self.release.url + "/releases/latest")

    @async_test()
    async def test_get_latest_release_return_response_as_json(self):
        response = MagicMock()
        response.json = make_mocked_coro(return_value={"tag_name": "1.0"})
        self.release.aiohttp_session.get_response = response

        release = await self.release.get_latest_release()

        response.json.assert_called_once_with()
        self.assertEqual(release, {"tag_name": "1.0"})

    def test_get_release_version_return_tag_name_of_release(self):
        release = {"tag_name": "1.0"}

        version = self.release.get_release_version(release)

        self.assertEqual(version, "1.0")

    def test_get_release_version_return_version_none_if_no_release_found(self):
        release = {"message": "Not Found"}

        version = self.release.get_release_version(release)

        self.assertIsNone(version)

    @async_test()
    async def test_release_data_raise_value_error_if_no_release_exists_and_create_release_is_false(self):
        self.release.get_latest_release = make_mocked_coro(return_value={})

        with self.assertRaises(ValueError):
            await self.release.release_data(self.dir_path, "filename_", create_release=False)

    @async_test()
    async def test_release_data_raise_value_error_if_create_release_is_true_but_commit_number_is_none(self):
        self.release.get_latest_release = make_mocked_coro(return_value={})

        with self.assertRaises(ValueError):
            await self.release.release_data(self.dir_path, "filename_", create_release=True, commit_number=None)

    @async_test()
    async def test_release_data_raise_value_error_if_create_release_is_true_but_release_version_is_none(self):
        self.release.get_latest_release = make_mocked_coro(return_value={})

        with self.assertRaises(ValueError):
            await self.release.release_data(self.dir_path, "filename_", create_release=True, commit_number='123abc',
                                            release_version=None)

    @async_test()
    async def test_release_data_create_a_new_release_if_create_release_is_true(self):
        self.release.create_release = make_mocked_coro(return_value={'tag_name': '1.0', 'id': '12345'})
        self.release.compress_exported_files = MagicMock()
        self.release.upload_compressed_data = make_mocked_coro()

        await self.release.release_data(self.dir_path, "filename_", create_release=True, commit_number='123abc',
                                        release_version="1.0")

        self.release.create_release.assert_called_once_with("123abc", "1.0")

    @async_test()
    async def test_release_data_calls_compressed_exported_data_with_version_appended_to_filename(self):
        self.release.get_latest_release = make_mocked_coro(return_value={'tag_name': '1.0', 'id': '12345'})
        self.release.compress_exported_files = MagicMock()
        self.release.upload_compressed_data = make_mocked_coro()

        await self.release.release_data(self.dir_path, "filename_")

        self.release.compress_exported_files.assert_called_once_with(self.dir_path, "filename_1.0")

    @async_test()
    async def test_release_data_calls_upload_compressed_data(self):
        self.release.get_latest_release = make_mocked_coro(return_value={'tag_name': '1.0', 'id': '12345'})
        self.release.compress_exported_files = MagicMock(return_value="filename_1.0.tar.gz")
        self.release.upload_compressed_data = make_mocked_coro()

        await self.release.release_data(self.dir_path, "filename_")

        self.release.upload_compressed_data.assert_called_once_with(self.dir_path, "filename_1.0.tar.gz", "12345")

    @async_test()
    async def test_create_release_create_release_with_name_if_not_none(self):
        await self.release.create_release('123abc', '1.0', name='release name')

        data = {'tag_name': '1.0', 'target_commitish': '123abc', 'name': 'release name'}
        self.release.aiohttp_session.post.assert_called_once_with("https://api.github.com/repos/Owner/repository_name/"
                                                                  "releases", data=json.dumps(data), auth=ANY)

    @async_test()
    async def test_create_release_create_release_from_commit_number(self):
        await self.release.create_release('abc123', '1.0')

        data = {'tag_name': '1.0', 'target_commitish': 'abc123', 'name': '1.0'}
        self.release.aiohttp_session.post.assert_called_once_with("https://api.github.com/repos/Owner/repository_name/"
                                                                  "releases", data=json.dumps(data), auth=ANY)

    @async_test()
    async def test_create_release_send_credential_with_post_request(self):
        self.release.set_repository_settings("Owner", "password", "repository_name")

        await self.release.create_release('abc123', '1.0')

        self.release.aiohttp_session.post.assert_called_once_with(ANY, data=ANY,
                                                                  auth=BasicAuth("Owner", password="password"))

    @async_test()
    async def test_create_release_return_new_release(self):
        response = MagicMock()
        response.status = 201
        response.json = make_mocked_coro(return_value={'tag_name': '1.0', 'id': '12345'})
        self.release.aiohttp_session.post_response = response
        release = await self.release.create_release('123abc', "1.0")

        self.assertEqual(release, {'tag_name': '1.0', 'id': '12345'})

    @async_test()
    async def test_upload_compressed_data_upload_data_as_asset_of_latest_release(self):
        release_id = "12345"
        asset_name = "asset.tar.gz"
        asset_raw_data = b'compressed data...'
        self.release.load_file = MagicMock(return_value=asset_raw_data)

        await self.release.upload_compressed_data(asset_name, asset_name, release_id)

        asset_upload_url = "https://uploads.github.com/repos/{0}/{1}/releases/{2}/assets?name={3}"\
            .format(self.release.repository_owner, self.release.repository_name, release_id, asset_name)
        headers = {'Content-Type': "application/gzip"}
        self.release.aiohttp_session.post.assert_called_once_with(asset_upload_url, headers=headers, auth=ANY,
                                                                  data=asset_raw_data)

    def test_get_asset_upload_url(self):
        release_id = "12345"
        asset_name = "test.tar.gz"

        url = self.release.get_assets_upload_url(release_id, asset_name)

        self.assertEqual(url, "https://uploads.github.com/repos/{0}/{1}/releases/{2}/assets?name={3}".format(
            self.release.repository_owner, self.release.repository_name, release_id, asset_name))

    def test_compress_exported_files_create_tar_archive_with_all_json_files_in_directory_by_default(self):
        fake_tarfile_obj = MagicMock()
        fake_tarfile_open = MagicMock()
        fake_tarfile_open.return_value.__enter__.return_value = fake_tarfile_obj
        self.files_in_dir.append("file.txt")
        self.fake_glob.return_value = [join(self.dir_path, file) for file in self.files_in_dir]

        with(patch("openwebvulndb.wordpress.vane2.release.tarfile.open", fake_tarfile_open)):
            self.release.compress_exported_files(self.dir_path, "1.0")

            fake_tarfile_open.assert_called_once_with(ANY, "w:gz")
            fake_tarfile_obj.add.assert_has_calls(
                [call(self.fake_glob.return_value[0], self.files_in_dir[0]),
                 call(self.fake_glob.return_value[1], self.files_in_dir[1])], any_order=True)

    def test_compress_exported_files_create_tar_archive_with_all_files_in_directory_that_match_pattern(self):
        fake_tarfile_obj = MagicMock()
        fake_tarfile_open = MagicMock()
        fake_tarfile_open.return_value.__enter__.return_value = fake_tarfile_obj
        files_in_dir = ["file1.json", "file2.json", "file.txt"]
        self.fake_glob.return_value = [join(self.dir_path, file) for file in files_in_dir]
        file_pattern = ["*.json", "*.txt"]

        with(patch("openwebvulndb.wordpress.vane2.release.tarfile.open", fake_tarfile_open)):
            self.release.compress_exported_files(self.dir_path, "filename", file_pattern=file_pattern)

            self.fake_glob.assert_has_calls([call(self.dir_path + "/" + file_pattern[0]),
                                             call(self.dir_path + "/" + file_pattern[1])])
            fake_tarfile_open.assert_called_once_with(ANY, "w:gz")
            fake_tarfile_obj.add.assert_has_calls(
                [call(self.fake_glob.return_value[0], files_in_dir[0]),
                 call(self.fake_glob.return_value[1], files_in_dir[1]),
                 call(self.fake_glob.return_value[2], files_in_dir[2])], any_order=True)

    def test_compress_exported_files_use_filename_and_targz_extension_for_archive_name(self):
        dir_path = "files/to/compress"
        filename = "vane2_data_1.3"
        fake_tarfile_open = MagicMock()

        with(patch("openwebvulndb.wordpress.vane2.release.tarfile.open", fake_tarfile_open)):
            self.release.compress_exported_files(dir_path,  filename)

            fake_tarfile_open.assert_called_once_with(join(dir_path, filename + ".tar.gz"), ANY)

    def test_compress_exported_files_return_archive_filename(self):
        dir_path = "files/to/compress"
        filename = "vane2_data_1.3"
        fake_tarfile_open = MagicMock()

        with(patch("openwebvulndb.wordpress.vane2.release.tarfile.open", fake_tarfile_open)):
            filename = self.release.compress_exported_files(dir_path, filename)

            self.assertEqual(filename, "vane2_data_1.3.tar.gz")
