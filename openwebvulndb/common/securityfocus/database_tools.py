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

from openwebvulndb.common.securityfocus.fetcher import SecurityFocusFetcher
from openwebvulndb.common.securityfocus.reader import SecurityFocusReader
import aiohttp
import json


securityfocus_base_url = "http://www.securityfocus.com/bid/"


def update_securityfocus_database(loop, storage, vulnerability_manager, cve_reader=None, bugtraq_id=None):
    async def update_database():
        async with aiohttp.ClientSession(loop=loop) as aiohttp_session:
            fetcher = SecurityFocusFetcher(aiohttp_session)
            reader = SecurityFocusReader(storage, vulnerability_manager)
            if bugtraq_id is None:
                vulnerability_list = await fetcher.get_list_of_vuln_on_first_page()
            else:
                vulnerability_list = [securityfocus_base_url + bugtraq_id]
            for vuln_url in vulnerability_list:
                vuln_entry = await fetcher.get_vulnerability_entry(url=vuln_url)
                if vuln_entry is not None:
                    entry = reader.read_one(vuln_entry)
                    if cve_reader is not None and entry is not None:
                        for ref in entry.references:
                            if ref.type == "cve":
                                await augment_with_cve_entry(ref.id, aiohttp_session, cve_reader)

    loop.run_until_complete(update_database())


def create_securityfocus_database(loop, storage, vulnerability_manager):
    async def create_database():
        async with aiohttp.ClientSession(loop=loop) as aiohttp_session:
            fetcher = SecurityFocusFetcher(aiohttp_session)
            reader = SecurityFocusReader(storage, vulnerability_manager)
            vulnerability_list = await fetcher.get_list_of_vuln_on_all_pages()
            for vuln_url in vulnerability_list:
                vuln_entry = await fetcher.get_vulnerability_entry(url=vuln_url)
                reader.read_one(vuln_entry)

    loop.run_until_complete(create_database())


def download_vulnerability_entry(loop, dest_folder, bugtraq_id):
    async def download_entry():
        async with aiohttp.ClientSession(loop=loop) as aiohttp_session:
            fetcher = SecurityFocusFetcher(aiohttp_session)
            await fetcher.get_vulnerability_entry(bugtraq_id=bugtraq_id, dest_folder=dest_folder)

    if not dest_folder:
        raise Exception("Option required: dest_folder")
    if not bugtraq_id:
        raise Exception("Option required: bugtraq_id")
    loop.run_until_complete(download_entry())


async def augment_with_cve_entry(cve_id, aiohttp_session, cve_reader):
    cve_entry = await fetch_cve_entry(aiohttp_session, "CVE-" + cve_id)
    if cve_entry is None:
        return
    try: # When fetching a single cve entry from the cve api, the vulnerable configuration is a list of dict instead of a list of string
        vulnerable_configuration = cve_entry["vulnerable_configuration"]
        cve_entry["vulnerable_configuration"] = []
        for config in vulnerable_configuration:
            if isinstance(config, dict):
                cve_entry["vulnerable_configuration"].append(config["id"])
            elif isinstance(config, str):
                cve_entry["vulnerable_configuration"].append(config)
    except KeyError:
        return
    cve_reader.read_one(cve_entry)


async def fetch_cve_entry(aiohttp_session, cve_id):
    url = "https://cve.circl.lu/api/cve/" + cve_id
    async with aiohttp_session.get(url) as response:
        return json.loads(await response.text())
