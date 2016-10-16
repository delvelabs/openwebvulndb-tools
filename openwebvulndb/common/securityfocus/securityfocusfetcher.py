from io import StringIO
from lxml import etree
from openwebvulndb.common.securityfocus.securityfocusparsers import InfoTabParser, ReferenceTabParser, \
    DiscussionTabParser, SolutionTabParser, ExploitTabParser


class SecurityFocusFetcher:

    def __init__(self, http_session=None, vulnerability_manager=None):
        self.http_session = http_session
        self.vulnerability_manager = vulnerability_manager

    async def get_list_of_vuln_on_first_page(self, file=None):
        if file is not None:
            return self._parse_page_with_vuln_list(file)
        else:
            response = await self.http_session.post("http://www.securityfocus.com/bid", data={'op': 'display_list',
                                                                                              'c': 12, 'vendor': 'WordPress'})
            html_page = await response.text()
            output_string = StringIO(html_page)
            vuln_list = self._parse_page_with_vuln_list(output_string)
            response.close()
            output_string.close()
            return vuln_list

    async def get_list_of_vuln_on_all_pages(self):
        complete_vuln_list = list()
        vuln_index = 0  # The number of the first vuln on the next page to fetch. Increment by 30 to change page because there is 30 vuln per page.
        while True:
            response = await self.http_session.post("http://www.securityfocus.com/bid",
                                                    data={'op': 'display_list', 'o': vuln_index, 'c': 12, 'vendor': 'WordPress'})
            vuln_index += 30
            html_page = await response.text()
            output_string = StringIO(html_page)
            vuln_list = self._parse_page_with_vuln_list(output_string)
            if len(vuln_list) == 0:  # The last page has been reached, no more vuln to get.
                break
            complete_vuln_list += vuln_list
            response.close()
            output_string.close()
        return complete_vuln_list

    async def get_vulnerability_entry(self, vuln_to_fetch):
        url = vuln_to_fetch["url"]
        pages_to_fetch = ["info", "references", "discuss", "solution", "exploit"]
        parsers_name = ["info_parser", "references_parser", "discussion_parser", "solution_parser", "exploit_parser"]
        vuln_entry = dict()
        vuln_entry["info_parser"] = InfoTabParser()
        vuln_entry["references_parser"] = ReferenceTabParser()
        vuln_entry["discussion_parser"] = DiscussionTabParser()
        vuln_entry["exploit_parser"] = ExploitTabParser()
        vuln_entry["solution_parser"] = SolutionTabParser()
        for page, parser_name in zip(pages_to_fetch, parsers_name):
            html_response = await self.http_session.get(url + '/' + page)
            raw_html_page = await html_response.text()
            vuln_entry[parser_name].set_html_page(StringIO(raw_html_page))
            html_response.close()
        vuln_entry["id"] = vuln_entry["info_parser"].get_bugtraq_id()
        return vuln_entry

    def _parse_page_with_vuln_list(self, html_page):
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
        return vuln_list