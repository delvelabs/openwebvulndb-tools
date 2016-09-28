from lxml import etree
from datetime import datetime

# %b = abbreviated month (Jan), %d = zero-padded day of month, %Y = year with century (2016), %I = hour in 12h format, %M = zero-padded minutes, %p = AM or PM.
securityfocus_date_format = "%b %d %Y %I:%M%p"


class InfoTabParser:
    """The parser for the info tab of a vulnerability entry in the security focus database.

    The info tab can contain the following data about a vulnerability:
    -Title (often takes the form of a short description)
    -Bugtraq ID (Security focus' ID system for vulnerability)
    -Class (type of vulnerability eg: Input validation error)
    -CVE ID (if it has one)
    -Remote (yes or no, if the vulnerability can be exploited remotly)
    -Local (see remote)
    -Publication date
    -Last update date
    -Credit
    -Vulnerable versions
    -not vulnerable versions
    """

    def __init__(self):
        self.html_tree = None
        
    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)

    def _parse_element(self, element_name):
        """Parse the elements in the info page that are contained in the <tr><td><span>element name</span></td><td>element
        value</td></tr> pattern. This is the pattern for all elements except the title.
        """
        element_value = self.html_tree.xpath('//span[text() = "' + element_name + '"]/../../td[2]/text()')
        # removes the white spaces around the value in the <td> (the whitespaces not preceded by a non-whitespace char
        # to preserve the white space between the word in the value.)
        element_value = element_value[0].strip()
        if len(element_value) == 0:
            return None
        else:
            return element_value

    # FIXME precision about versions (like the Gentoo linux in wordpress_vuln_no_cve.html) are not parsed.
    def _parse_vulnerable_versions(self):
        vuln_versions_list = self.html_tree.xpath('//span[text() = "Vulnerable:"]/../../td[2]/text()')
        for i in range(len(vuln_versions_list)):
            vuln_versions_list[i] = vuln_versions_list[i].strip()
            # removes the empty string add at the end of the versions list because of the <br> tag.
        for string in vuln_versions_list:
            if len(string) == 0:
                vuln_versions_list.remove(string)
        return vuln_versions_list

    def _parse_not_vulnerable_versions(self):
        versions_list = self.html_tree.xpath('//span[text() = "Not Vulnerable:"]/../../td[2]/text()')
        for i in range(len(versions_list)):
            versions_list[i] = versions_list[i].strip()
            # removes the empty string add at the end of the versions list because of the <br> tag.
            if len(versions_list[i]) == 0:
                del versions_list[i]
        return versions_list

    def get_title(self):
        # return le text dans tous les elements span avec l'attribut class ayant la valeur "title"
        title = self.html_tree.xpath('//span[@class="title"]/text()')
        return title[0]
        
    def get_bugtraq_id(self):
        return self._parse_element("Bugtraq ID:")
        
    def get_vuln_class(self):
        return self._parse_element("Class:")
        
    def get_cve_id(self):
        # Get the td element with the cve id:
        td_element = self.html_tree.xpath('//span[text() = "' + "CVE:" + '"]/../../td[2]')
        td_element = td_element[0]
        cve = td_element.text.strip()
        if len(cve) == 0:
            return None
        cve_ids = []
        cve_ids.append(cve)
        for br_tag in td_element:
            cve = br_tag.tail
            if cve is not None:
                cve = cve.strip()
                if len(cve) != 0:
                    cve_ids.append(cve)
        if len(cve_ids) == 1:
            return cve_ids[0]
        else:
            return cve_ids
        
    def is_vuln_remote(self):
        return self._parse_element("Remote:")
        
    def is_vuln_local(self):
        return self._parse_element("Local:")
        
    def get_publication_date(self):
        string_date = self._parse_element("Published:")
        date = datetime.strptime(string_date, securityfocus_date_format)
        return date

    def get_last_update_date(self):
        string_date = self._parse_element("Updated:")
        date = datetime.strptime(string_date, securityfocus_date_format)
        return date
        
    def get_credit(self):
        return self._parse_element("Credit:")

    def get_vulnerable_versions(self):
        vuln_versions_list = self._parse_vulnerable_versions()
        if len(vuln_versions_list) == 0:
            return None
        return vuln_versions_list
        
    def get_not_vulnerable_versions(self):
        not_vuln_versions_list = self._parse_not_vulnerable_versions()
        if len(not_vuln_versions_list) == 0:
            return None
        return not_vuln_versions_list


class ReferenceTabParser:
    """The parser for the reference tab of vulnerability entry in the security focus database.

    The reference tab contains external references about the vulnerability. A reference is a description with an URL.
    """

    def __init__(self):
        self.html_tree = None

    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)

    def _get_reference_parent_tag(self):
        return self.html_tree.xpath('//div[@id="vulnerability"]/ul')[0]  # returns the first ul tag in div vulnerability

    def get_references(self):
        references_list = []
        parent_ul_tag = self._get_reference_parent_tag()
        for li in list(parent_ul_tag):  # create a list with all the li elements.
            a_tag = list(li)[0]
            description = a_tag.text + a_tag.tail
            url = li.xpath('a/@href')[0]
            references_list.append((description, url))
        return references_list


class DiscussionTabParser:
    """The parser for the discussion tab of the vulnerability entry in the security focus database."""

    def __init__(self):
        self.html_tree = None

    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)

    def get_discussion(self):
        div_tag = self.html_tree.xpath('//div[@id="vulnerability"]')[0]  # The div that contains the discussion text.
        discussion_text = ""
        for br_tag in div_tag:  # the text of the discussion is contained after <br> tags in the div.
            if br_tag.tag == 'br':
                br_text = br_tag.tail
                if br_text is not None:
                    discussion_text += br_text.strip()
        return discussion_text


class ExploitTabParser:
    """The parser for the exploit tab of the vulnerability entry in the security focus database."""

    def __init__(self):
        self.html_tree = None

    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)

    def get_exploit_description(self):
        div_tag = self.html_tree.xpath('//div[@id="vulnerability"]')[0]  # the div that contains the exploit description
        exploit_description = ''
        for br_tag in div_tag:  # the description of the exploit is contained after <br> tags in the div.
            if br_tag.tag == 'br':
                text = br_tag.tail
                if text is not None:
                    if "Currently, we are not aware of any working exploits." in text:
                        return None
                    exploit_description += text.strip()
        return exploit_description


class SolutionTabParser:
    """The parser for the solution tab of the vulnerability entry in the security focus database."""

    def __init__(self):
        self.html_tree = None

    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)

    def get_solution(self):
        div_tag = self.html_tree.xpath('//div[@id="vulnerability"]')[0]  # The div that contains the text of the solution.
        solution_description = ''
        for br_tag in div_tag:  # the description of the solution is contained after <br> tags in the div.
            if br_tag.tag == 'br':
                text = br_tag.tail
                if text is not None:
                    if "Currently we are not aware of any" in text:
                        return None
                    solution_description += text.strip()
        return solution_description
