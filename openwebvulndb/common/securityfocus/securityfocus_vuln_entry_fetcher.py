from .securityfocusparsers import InfoTabParser, ReferenceTabParser, DiscussionTabParser, SolutionTabParser, ExploitTabParser
from io import StringIO
import os


class SecurityFocusVulnerabilityFetcher:

    def __init__(self, http_session):
        self.http_session = http_session

    async def get_vulnerability_data(self, bugtraq_id, dest_folder=None):  # Set dest_folder to store the html_pages and the entry in files for tests.
        base_url = "http://www.securityfocus.com/bid/" + bugtraq_id
        pages_to_fetch = ["info", "references", "discuss", "solution", "exploit"]
        tabs_names = ["info", "references", "discussion", "solution", "exploit"]
        vuln_data = dict()
        vuln_data['id'] = bugtraq_id
        vuln_data["info_parser"] = InfoTabParser()
        vuln_data["references_parser"] = ReferenceTabParser()
        vuln_data["discussion_parser"] = DiscussionTabParser()
        vuln_data["exploit_parser"] = ExploitTabParser()
        vuln_data["solution_parser"] = SolutionTabParser()
        for page, tab in zip(pages_to_fetch, tabs_names):
            print("getting " + base_url + '/' + page)
            if dest_folder is not None and os.path.isfile(dest_folder + '/' + tab + "_tab.html"):
                print("file already exists, skip to the next file...")
            else:
                html_response = await self.http_session.get(base_url + '/' + page)
                raw_html_page = await html_response.text()
                vuln_data[tab + "_parser"].set_html_page(StringIO(raw_html_page))
                if dest_folder is not None:
                    file = open(dest_folder + '/' + tab + "_tab.html", 'wt')
                    file.write(raw_html_page)
                    file.close()
                html_response.close()
        print("done getting html pages.")
        return vuln_data


