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

import tarfile
from os.path import join
from glob import glob
from aiohttp import BasicAuth
import json


class GitHubRelease:

    def __init__(self, aiohttp_session=None):
        self.aiohttp_session = aiohttp_session
        self.url = None
        self.repository_password = None
        self.repository_owner = None
        self.repository_name = None

    def set_repository_settings(self, repository_owner, repository_password, repository_name):
        base_url = "https://api.github.com/repos/{0}/{1}"
        self.url = base_url.format(repository_owner, repository_name)
        self.repository_name = repository_name
        self.repository_owner = repository_owner
        self.repository_password = repository_password

    async def release_data(self, directory_path, filename, create_release=False, target_commitish=None,
                           release_version=None):
        if create_release:
            if target_commitish is None:
                raise ValueError("Cannot create a release if target_commitish is none.")
            if release_version is None:
                raise ValueError("Cannot create a release if release_version is none.")
            latest_release = await self.create_release(target_commitish, release_version)
        else:
            latest_release = await self.get_latest_release()
            release_version = self.get_release_version(latest_release)
            if release_version is None:
                raise ValueError("Cannot add an asset to release if no previous release exists.")
        archive_name = self.compress_exported_files(directory_path, filename + release_version)
        await self.upload_compressed_data(directory_path, archive_name, latest_release['id'])

    async def get_latest_release(self):
        url = self.url + "/releases/latest"
        async with self.aiohttp_session.get(url) as response:
            data = await response.json()
            return data

    def get_release_version(self, release):
        try:
            latest_version = release['tag_name']
        except KeyError:
            latest_version = None
        return latest_version

    async def create_release(self, target_commitish, version, name=None):
        url = self.url + "/releases"
        data = {'tag_name': version, 'target_commitish': target_commitish, 'name': name or version}
        authentication = BasicAuth(self.repository_owner, password=self.repository_password)
        async with self.aiohttp_session.post(url, data=json.dumps(data), auth=authentication) as response:
            if response.status != 201:
                error_message = "Error while creating release, response status code: {0}, response message: {1}"
                raise Exception(error_message.format(response.status, await response.json()))
            return await response.json()

    async def upload_compressed_data(self, directory_path, filename, release_id):
        url = self.get_assets_upload_url(release_id, filename)
        data = self.load_file(join(directory_path, filename))
        headers = {'Content-Type': "application/gzip"}
        authentication = BasicAuth(self.repository_owner, password=self.repository_password)
        async with self.aiohttp_session.post(url, headers=headers, data=data, auth=authentication) as response:
            if response.status != 201:
                error_message = "Error while uploading data, response status code: {0}, response message: {1}"
                raise Exception(error_message.format(response.status, await response.read()))

    def get_assets_upload_url(self, release_id, asset_name):
        upload_url = "https://uploads.github.com/repos/{0}/{1}/releases/{2}/assets?name={3}"
        return upload_url.format(self.repository_owner, self.repository_name, release_id, asset_name)

    def load_file(self, filename):
        with open(filename, 'rb') as file:
            data = file.read()
            return data

    def compress_exported_files(self, directory_path, filename, file_pattern=None):
        file_pattern = file_pattern or ["*.json"]
        archive_name = "%s.tar.gz" % filename
        with tarfile.open(join(directory_path, archive_name), "w:gz") as tar_archive:
            for pattern in file_pattern:
                files_to_compress = glob(join(directory_path, pattern))
                for file_path in files_to_compress:
                    file_name = file_path[len(directory_path + "/"):]
                    tar_archive.add(file_path, file_name)
            return archive_name
