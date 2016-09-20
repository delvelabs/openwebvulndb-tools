from lxml import etree
from datetime import datetime

# %b = abbreviated month (Jan), %d = zero-padded day of month, %Y = year with century (2016), %I = hour in 12h format, %M = zero-padded minutes, %p = AM or PM.
securityfocus_date_format = "%b %d %Y %I:%M%p"

"""The parser for the info tab of vulnerabilities in the security focus database."""
class InfoTabParser:
    
    def __init__(self):
        self.html_tree = None
        
    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)

    """
       Parse the elements in the info page that are contained in the <tr><td><span>element name</span></td><td>element
       value</td></tr> pattern. This is the pattern for all elements except the title.
    """
    def _parse_element(self, element_name):
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
        return self._parse_element("CVE:")
        
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
        return vuln_versions_list
        
    def get_not_vulnerable_versions(self):
        not_vuln_versions_list = self._parse_not_vulnerable_versions()
        return not_vuln_versions_list


"""The parser for the reference tab of vulnerabilities in the security focus database."""
class ReferenceTabParser:

    def __init__(self):
        self.html_tree = None

    def set_html_page(self, filename):
        parser = etree.HTMLParser()
        self.html_tree = etree.parse(filename, parser)
