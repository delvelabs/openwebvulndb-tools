import asyncio
import aiohttp
import json
from lxml import etree
import re
from .securityfocusparsers import InfoTabParser, ReferenceTabParser, DiscussionTabParser, ExploitTabParser, SolutionTabParser
from .securityfocus import SecurityFocusReader
from openwebvulndb.common.storage import Storage
from io import StringIO
from .securityfocus_vuln_entry_fetcher import SecurityFocusVulnerabilityFetcher


async def get_securityfocus_first_page_of_wordpress_vuln(session, dest_file_name=None):
    response = await session.post("http://www.securityfocus.com/bid", data={'op': 'display_list', 'c': 12, 'vendor': 'WordPress'})
    data = await response.content.text()
    if dest_file_name is not None:
        file = open(dest_file_name, 'wt')
        file.write(data)
        file.close()
    output_string = StringIO()
    output_string.write(data)
    return output_string


def parse_page_with_vuln_entry_list(html_page, dest_file_name=None):
    parser = etree.HTMLParser(recover=True)
    html_tree = etree.parse(html_page, parser)
    div_tag_with_vuln_list = html_tree.xpath('//div[@id="article_list"]/div')[1]
    vuln_list = list()
    vuln_entry = {'title': None, 'url': None, 'date': None}
    for child in div_tag_with_vuln_list:
        if child.tag == 'a':
            if len(child) > 0:
                vuln_entry['title'] = child[0].text
            else:
                vuln_entry['url'] = child.text
        elif child.tag == 'span':
            vuln_entry['date'] = child.text
        if vuln_entry['url'] is not None and vuln_entry['title'] is not None and vuln_entry['date'] is not None:
            vuln_list.append(vuln_entry)
            vuln_entry = {'title': None, 'url': None, 'date': None}  # Create a new empty entry for the next vuln.
    json_output = StringIO()
    json_output.write(json.dumps(vuln_list, indent=4))
    if dest_file_name is not None:
        file = open(dest_file_name, 'w')
        file.write(json_output.getvalue())
        file.close()
    return json_output


async def get_vulnerabilities_entry_from_list(vuln_list, http_session, reader):
    vuln_fetcher = SecurityFocusVulnerabilityFetcher(http_session)
    for vuln in vuln_list:
        bugtraq_id = get_bugtraq_id_from_url(vuln['url'])
        entry = await vuln_fetcher.get_vulnerability_entry(bugtraq_id)
        reader.read_one(entry)


def get_bugtraq_id_from_url(url):
    return url[url.find("bid/") + 4:]


def test_securityfocus(loop, storage):
    storage.base_path = "/home/nicolas/delve-labs/openwebvulndb-tools/data"
    reader = SecurityFocusReader(storage)
    session = aiohttp.ClientSession(loop=loop)
    fetcher = SecurityFocusVulnerabilityFetcher(session)
    entry = loop.run_until_complete(fetcher.get_vulnerability_entry("92355", "/home/nicolas/delve-labs/openwebvulndb-tools/tests/common_test/samples/92355"))
    session.close()
    reader.read_one(entry)
    loop.close()
