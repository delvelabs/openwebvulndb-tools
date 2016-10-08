from .securityfocusparsers import InfoTabParser, ReferenceTabParser, DiscussionTabParser, SolutionTabParser, ExploitTabParser
import json


class SecurityFocusVulnerabilityFetcher:

    def __init__(self, http_session):
        self.http_session = http_session

    async def get_vulnerability_entry(self, bugtraq_id, dest_folder=None):  # Set dest_folder to store the html_pages and the entry in files for tests.
        base_url = "http://www.securityfocus.com/bid/" + bugtraq_id
        print("getting " + base_url + "/info")
        info_tab = await self.http_session.get(base_url + "/info")
        print("getting " + base_url + "/references")
        reference_tab = await self.http_session.get(base_url + "/references")
        print("getting " + base_url + "/discuss")
        discussion_tab = await self.http_session.get(base_url + "/discuss")
        print("getting " + base_url + "/solution")
        solution_tab = await self.http_session.get(base_url + "/solution")
        print("getting " + base_url + "/exploit")
        exploit_tab = await self.http_session.get(base_url + "/exploit")
        print("done getting html pages.")
        if dest_folder is not None:
            file_info = open(dest_folder + "/info_tab.html", 'wt')
            file_reference = open(dest_folder + "/references_tab.html", 'wt')
            file_discussion = open(dest_folder + "/discussion_tab.html", 'wt')
            file_solution = open(dest_folder + "/solution_tab.html", 'wt')
            file_exploit = open(dest_folder + "/exploit_tab.html", 'wt')
            file_info.write(info_tab.content.text())
            file_reference.write(reference_tab.content.text())
            file_discussion.write(discussion_tab.content.text())
            file_solution.write(solution_tab.content.text())
            file_exploit.write(exploit_tab.content.text())
            file_info.close()
            file_reference.close()
            file_discussion.close()
            file_solution.close()
            file_exploit.close()
        entry = dict()
        info_tab_parser = InfoTabParser()
        info_tab_parser.set_html_page(info_tab)
        reference_tab_parser = ReferenceTabParser()
        reference_tab_parser.set_html_page(reference_tab)
        discussion_tab_parser = DiscussionTabParser()
        discussion_tab_parser.set_html_page(discussion_tab)
        exploit_tab_parser = ExploitTabParser()
        exploit_tab_parser.set_html_page(exploit_tab)
        solution_tab_parser = SolutionTabParser()
        solution_tab_parser.set_html_page(solution_tab)
        entry['id'] = bugtraq_id
        entry['info_parser'] = info_tab_parser
        entry['references_parser'] = reference_tab_parser
        entry['discussion_parser'] = discussion_tab_parser
        entry['exploit_parser'] = exploit_tab_parser
        entry['solution_parser'] = solution_tab_parser
        if dest_folder is not None:
            file_entry = open(dest_folder + "/vuln-entry-" + bugtraq_id + ".json", 'wt')
            file_entry.write(json.dumps(entry, indent=4))
        return entry
