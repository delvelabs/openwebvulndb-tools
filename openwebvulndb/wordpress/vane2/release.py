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
from os.path import join, dirname
from glob import glob
import json
from aiohttp import BasicAuth
from subprocess import run
from os import chdir


class GitHubRelease:

    def __init__(self, aiohttp_session=None):
        self.aiohttp_session = aiohttp_session
        self.url = None
        self.repository_path = None
        self.repository_password = None
        self.repository_owner = None
        self.repository_name = None

    def set_repository_settings(self, repository_owner, repository_password, repository_name):
        base_url = "https://api.github.com/repos/{0}/{1}"
        self.url = base_url.format(repository_owner, repository_name)
        self.repository_name = repository_name
        self.repository_owner = repository_owner
        self.repository_password = repository_password

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

    def get_release_id(self, release):
        return release['id']

    async def create_release(self):
        self.commit_data()
        release_version = await self.get_release_version()
        url = self.url + "/releases"
        data = {'tag_name': release_version, 'target_commitish': 'master', 'name': release_version}
        authentication = BasicAuth(self.repository_owner, password=self.repository_password)

        async with self.aiohttp_session.post(url, data=json.dumps(data), auth=authentication) as response:
            pass

    def commit_data(self):
        chdir(self.repository_path)
        run("./commit_data.sh")

    async def release_vane_data(self, dir_path):
        latest_release = await self.get_latest_release()
        latest_release_version = self.get_release_version(latest_release)
        if latest_release_version is None:
            raise ValueError("Cannot add exported Vane data if no previous release exists.")
        filename = self.compress_exported_files(dir_path, latest_release_version)
        #await self.upload_compressed_data(dir_path, filename)

    async def upload_compressed_data(self, dir_path, filename):
        latest_release = await self.get_latest_release()
        latest_release_id = self.get_release_id(latest_release)
        url = self.get_assets_upload_url(latest_release_id, filename)
        data = self.load_compressed_file(join(dir_path, filename))
        headers = {'Content-Type': "application/gzip"}
        async with self.aiohttp_session.post(url, headers=headers, data=data,
                                             auth=BasicAuth(self.repository_owner, password=self.repository_password)) as response:
            if response.status != 201:
                raise Exception("Error while uploading data, response status code: {0}, response message: {1}"\
                                .format(response.status, await response.read()))

    def get_assets_upload_url(self, release_id, asset_name):
        upload_url = "https://uploads.github.com/repos/{0}/{1}/releases/{2}/assets?name={3}"
        return upload_url.format(self.repository_owner, self.repository_name, release_id, asset_name)

    def load_compressed_file(self, filename):
        with open(filename, 'rb') as file:
            data = file.read()
            return data

    def compress_exported_files(self, dir_path, release_version):
        archive_name = "vane2_data_{0}.tar.gz".format(release_version)
        with tarfile.open(join(dir_path, archive_name), "w:gz") as tar_archive:
            files_to_compress = glob(join(dir_path, "*.json"))
            for file_path in files_to_compress:
                file_name = file_path[len(dir_path + "/"):]
                tar_archive.add(file_path, file_name)
            return archive_name
