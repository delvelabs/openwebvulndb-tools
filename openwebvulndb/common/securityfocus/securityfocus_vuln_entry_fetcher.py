from .securityfocusparsers import InfoTabParser, ReferenceTabParser, DiscussionTabParser, SolutionTabParser, ExploitTabParser
import json
import os


class SecurityFocusVulnerabilityFetcher:

    def __init__(self, http_session):
        self.http_session = http_session

    async def get_vulnerability_entry(self, bugtraq_id, dest_folder=None):  # Set dest_folder to store the html_pages and the entry in files for tests.
        base_url = "http://www.securityfocus.com/bid/" + bugtraq_id
        print("getting " + base_url + "/info")
        if dest_folder is not None and os.path.isfile(dest_folder + "/info_tab.html"):
            print("file already exists, skip to the next file...")
        else:
            info_tab = await self.http_session.get(base_url + "/info")
            info_tab_data = await info_tab.text()
            if dest_folder is not None and os.path.isfile(dest_folder + "/info_tab.html"):
                file_info = open(dest_folder + "/info_tab.html", 'wt')
                file_info.write(info_tab_data)
                file_info.close()
        print("getting " + base_url + "/references")
        if dest_folder is not None and os.path.isfile(dest_folder + "/references_tab.html"):
            print("file already exists, skip to the next file...")
        else:
            reference_tab = await self.http_session.get(base_url + "/references")
            if dest_folder is not None:
                reference_tab_data = await reference_tab.text()
                file_reference = open(dest_folder + "/references_tab.html", 'wt')
                file_reference.write(reference_tab_data)
                file_reference.close()
        print("getting " + base_url + "/discuss")
        if dest_folder is not None and os.path.isfile(dest_folder + "/discussion_tab.html"):
            print("file already exists, skip to the next file...")
        else:
            discussion_tab = await self.http_session.get(base_url + "/discuss")
            if dest_folder is not None:
                discussion_tab_data = await discussion_tab.text()
                file_discussion = open(dest_folder + "/discussion_tab.html", 'wt')
                file_discussion.write(discussion_tab_data)
                file_discussion.close()
        print("getting " + base_url + "/solution")
        if dest_folder is not None and os.path.isfile(dest_folder + "/solution_tab.html"):
            print("file already exists, skip to the next file...")
        else:
            solution_tab = await self.http_session.get(base_url + "/solution")
            if dest_folder is not None:
                solution_tab_data = await solution_tab.text()
                file_solution = open(dest_folder + "/solution_tab.html", 'wt')
                file_solution.write(solution_tab_data)
                file_solution.close()
        print("getting " + base_url + "/exploit")
        if dest_folder is not None and os.path.isfile(dest_folder + "/exploit_tab.html"):
            print("file already exists, skip to the next file...")
        else:
            exploit_tab = await self.http_session.get(base_url + "/exploit")
            if dest_folder is not None:
                exploit_tab_data = await exploit_tab.text()
                file_exploit = open(dest_folder + "/exploit_tab.html", 'wt')
                file_exploit.write(exploit_tab_data)
                file_exploit.close()
        print("done getting html pages.")
        entry = dict()
        info_tab_parser = InfoTabParser()
        info_tab_parser.set_html_page(info_tab_data)
        reference_tab_parser = ReferenceTabParser()
        reference_tab_parser.set_html_page(reference_tab_data)
        discussion_tab_parser = DiscussionTabParser()
        discussion_tab_parser.set_html_page(discussion_tab_data)
        exploit_tab_parser = ExploitTabParser()
        exploit_tab_parser.set_html_page(exploit_tab_data)
        solution_tab_parser = SolutionTabParser()
        solution_tab_parser.set_html_page(solution_tab_data)
        info_tab.close()
        reference_tab.close()
        solution_tab.close()
        discussion_tab.close()
        exploit_tab.close()
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
