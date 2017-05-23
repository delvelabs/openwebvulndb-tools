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
from openwebvulndb.common.version import VersionCompare
import json
from aiohttp import BasicAuth
from subprocess import run
from os import chdir, system


class GitHubRelease:

    def __init__(self, aiohttp_session=None):
        self.aiohttp_session = aiohttp_session
        self.url = None
        self.repository_path = None
        self.repository_password = None
        self.repository_owner = None

    def set_repository_settings(self, repository_owner, repository_password, repository_name, repository_path):
        base_url = "https://api.github.com/repos/{0}/{1}"
        self.url = base_url.format(repository_owner, repository_name)
        self.repository_path = repository_path
        self.repository_owner = repository_owner
        self.repository_password = repository_password

    async def get_latest_release_version(self):
        url = self.url + "/releases/latest"
        response = await self.aiohttp_session.get(url)
        data = await response.json()
        try:
            latest_version = data['tag_name']
        except KeyError:
            latest_version = "0.0"
        return latest_version

    async def get_release_version(self):
        latest_version = await self.get_latest_release_version()
        new_version = VersionCompare.next_minor(latest_version)
        return new_version

    async def create_release(self):
        self.commit_data()
        release_version = await self.get_release_version()
        url = self.url + "/releases"
        data = {'tag_name': release_version, 'target_commitish': 'master', 'name': release_version}
        authentication =BasicAuth(self.repository_owner, password=self.repository_password)

        response = await self.aiohttp_session.post(url, data=json.dumps(data), auth=authentication)

        #response.close()

    def commit_data(self):
        chdir(self.repository_path)
        run("./commit_data.sh")


def compress_exported_files(dir_path):
    release_version = get_release_version(None)
    archive_name = "vane2_data_{0}.tar.gz".format(release_version)
    tar_archive = tarfile.open(join(dir_path, archive_name), "w:gz")
    files_to_compress = glob(join(dir_path, "*"))
    for file in files_to_compress:
        file = file[len(dirname(file) + "/"):]
        tar_archive.add(join(dir_path, file), file)


def get_release_version(repository_url):
    return ""


def create_release(repository_url):
    pass
