from openwebvulndb.common.securityfocus.securityfocusfetcher import SecurityFocusFetcher
from openwebvulndb.common.securityfocus.securityfocus import SecurityFocusReader
import aiohttp


def update_securityfocus_database(loop, storage, vulnerability_manager):
    session = aiohttp.ClientSession(loop=loop)
    fetcher = SecurityFocusFetcher(session, vulnerability_manager)
    reader = SecurityFocusReader(storage, vulnerability_manager, session)
    vulnerability_list = loop.run_until_complete(fetcher.get_list_of_vuln_on_first_page())
    for vuln in vulnerability_list:
        vuln_entry = loop.run_until_complete(fetcher.get_vulnerability_entry(vuln))
        reader.read_one(vuln_entry)
    session.close()
    loop.close()

def create_securityfocus_database(loop, storage, vulnerability_manager):
    session = aiohttp.ClientSession(loop=loop)
    fetcher = SecurityFocusFetcher(session, vulnerability_manager)
    reader = SecurityFocusReader(storage, vulnerability_manager, session)
    vulnerability_list = loop.run_until_complete(fetcher.get_list_of_vuln_on_all_pages())
    for vuln in vulnerability_list:
        vuln_entry = loop.run_until_complete(fetcher.get_vulnerability_entry())
        reader.read_one(vuln_entry)
    session.close()
    loop.close()
