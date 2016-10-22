from openwebvulndb.common.securityfocus.securityfocusfetcher import SecurityFocusFetcher
from openwebvulndb.common.securityfocus.securityfocus import SecurityFocusReader
import aiohttp


def update_securityfocus_database(loop, storage, vulnerability_manager):
    async def update_database(fetcher, reader):
        vulnerability_list = await fetcher.get_list_of_vuln_on_first_page()
        for vuln_url in vulnerability_list:
            vuln_entry = await fetcher.get_vulnerability_entry(url=vuln_url)
            reader.read_one(vuln_entry)
    with aiohttp.ClientSession(loop=loop) as aiohttp_session:
        fetcher = SecurityFocusFetcher(aiohttp_session, vulnerability_manager)
        reader = SecurityFocusReader(storage, vulnerability_manager, aiohttp_session)
        loop.run_until_complete(update_database(fetcher, reader))


def create_securityfocus_database(loop, storage, vulnerability_manager):
    async def create_database(fetcher, reader):
        vulnerability_list = await fetcher.get_list_of_vuln_on_all_pages()
        for vuln_url in vulnerability_list:
            vuln_entry = await fetcher.get_vulnerability_entry(url=vuln_url)
            reader.read_one(vuln_entry)
    with aiohttp.ClientSession(loop=loop) as aiohttp_session:
        fetcher = SecurityFocusFetcher(aiohttp_session, vulnerability_manager)
        reader = SecurityFocusReader(storage, vulnerability_manager, aiohttp_session)
        loop.run_until_complete(create_database(fetcher, reader))

def download_vulnerability_entry(loop, dest_folder, bugtraq_id):
    if not dest_folder:
        raise Exception("Option required: dest_folder")
    if not bugtraq_id:
        raise Exception("Option required: bugtraq_id")
    with aiohttp.ClientSession(loop=loop) as aiohttp_session:
        fetcher = SecurityFocusFetcher(aiohttp_session)
        loop.run_until_complete(fetcher.get_vulnerability_entry(bugtraq_id=bugtraq_id, dest_folder=dest_folder))
