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


class GitHubRelease:

    def __init__(self, aiohttp_session=None):
        self.aiohttp_session = aiohttp_session
        self.url = None

    def set_repository_settings(self, repository_owner, repository_name):
        base_url = "https://api.github.com/repos/{0}/{1}"
        self.url = base_url.format(repository_owner, repository_name)

    async def get_latest_release_version(self):
        url = self.url + "/releases/latest"
        response = await self.aiohttp_session.get(url)
        data = await response.json()
        return data['tag_name']


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
