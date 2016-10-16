from io import StringIO
from lxml import etree

class SecurityFocusFetcher:

    def __init__(self, http_session=None):
        self.http_session = http_session

    async def get_list_of_vuln_on_first_page(self, file=None):
        if file is not None:
            return self._parse_page_with_vuln_list(file)
        else:
            response = await self.http_session.post("http://www.securityfocus.com/bid", data={'op': 'display_list',
                                                                                              'c': 12, 'vendor': 'WordPress'})
            data = await response.content.text()
            output_string = StringIO()
            output_string.write(data)
            vuln_list = self._parse_page_with_vuln_list(output_string)
            response.close()
            output_string.close()
            return vuln_list

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