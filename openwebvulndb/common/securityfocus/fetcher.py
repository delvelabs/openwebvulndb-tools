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

from io import StringIO
from lxml import etree
from openwebvulndb.common.securityfocus.parsers import InfoTabParser, ReferenceTabParser, \
    DiscussionTabParser, SolutionTabParser, ExploitTabParser
import re
from openwebvulndb.common.logs import logger
import os
from aiohttp import ClientResponseError


class SecurityFocusFetcher:

    def __init__(self, http_session=None):
        self.http_session = http_session

    async def get_list_of_vuln_on_first_page(self, file=None):
        if file is not None:
            return self._parse_page_with_vuln_list(file)
        else:
            async with self.http_session.post("http://www.securityfocus.com/bid",
                                              data={'op': 'display_list', 'c': 12, 'vendor': 'WordPress'}) as response:
                assert response.status == 200
                html_page = await response.text()
                output_string = StringIO(html_page)
                vuln_list = self._parse_page_with_vuln_list(output_string)
                output_string.close()
                return vuln_list

    async def get_list_of_vuln_on_all_pages(self):
        complete_vuln_list = []
        vuln_index = 0  # The number of the first vuln on the next page to fetch. Increment by 30 to change page because there is 30 vuln per page.
        while True:
            async with self.http_session.post("http://www.securityfocus.com/bid",
                                              data={'op': 'display_list', 'o': vuln_index, 'c': 12, 'vendor': 'WordPress'}) as response:
                assert response.status == 200
                vuln_index += 30
                html_page = await response.text()
                output_string = StringIO(html_page)
                vuln_list = self._parse_page_with_vuln_list(output_string)
                if len(vuln_list) == 0:  # The last page has been reached, no more vuln to get.
                    break
                complete_vuln_list += vuln_list
                output_string.close()
        return complete_vuln_list

    async def get_vulnerability_entry(self, bugtraq_id=None, url=None, dest_folder=None):
        """Fetch and return the vulnerability entry with the bugtraq id or the url from the security focus database.

        If dest_folder is not None, the html pages are save in dest_folder. If a page already exists, it is not overwritten.
        A vuln entry is a dict with the following keys/values:
            id: The bugtraq id of the vulnerability.
            info_parser: An InfoTabParser object containing the info tab html page of the vulnerability.
            references_parser: A ReferenceTabParser object containing the info tab html page of the vulnerability.
            discussion_parser: A DiscussionTabParser object containing the info tab html page of the vulnerability.
            exploit_parser: An ExploitTabParser object containing the info tab html page of the vulnerability.
            solution_parser: A SolutionTabParser object containing the info tab html page of the vulnerability.
        """
        if url is None:
            url = "http://www.securityfocus.com/bid/" + bugtraq_id
        if bugtraq_id is None:
            bugtraq_id = re.search("\d+", url).group()
        pages_to_fetch = ["info", "references", "discuss", "solution", "exploit"]
        parsers_name = ["info_parser", "references_parser", "discussion_parser", "solution_parser", "exploit_parser"]
        vuln_entry = {
            "id": bugtraq_id,
            "info_parser": InfoTabParser(),
            "references_parser": ReferenceTabParser(url=url),
            "discussion_parser": DiscussionTabParser(),
            "exploit_parser": ExploitTabParser(),
            "solution_parser": SolutionTabParser()
        }
        for page, parser_name in zip(pages_to_fetch, parsers_name):
            try:
                async with self.http_session.get(url + '/' + page) as html_response:
                    if html_response.status != 200:
                        logger.info("Error when getting {0}. Skipping to next page.".format(url + '/' + page))
                        continue
                    raw_html_page = await html_response.text()
                    vuln_entry[parser_name].set_html_page(StringIO(raw_html_page))
                    # If the file doesn't already exists, save it in dest_folder.
                    if dest_folder is not None and not os.path.isfile(os.path.join(dest_folder, page + "tab.html")):
                        with open(os.path.join(dest_folder, page + "_tab.html"), 'wt') as file:
                            file.write(raw_html_page)
            except ClientResponseError:
                logger.info("Error when getting vuln {0}, page {1}.".format(bugtraq_id, page))
                return None
        return vuln_entry

    def _parse_page_with_vuln_list(self, html_page):
        """Return a list with the url of all the vuln listed in html_page."""
        parser = etree.HTMLParser(recover=True)
        html_tree = etree.parse(html_page, parser)
        div_tag_with_vuln_list = html_tree.xpath('//div[@id="article_list"]/div')[1]
        vuln_list = []
        for child in div_tag_with_vuln_list:
            if child.tag == 'a' and child.text is not None and "http" in child.text:
                vuln_list.append(child.text)
        return vuln_list
