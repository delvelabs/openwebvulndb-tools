import re
from lxml import etree

class InfoTabParser:
    
    def __init__(self):
        self.filename = None
        self.title = None
        self.bugtraqID = None
        self.vulnClass = None
        self.cveID = None
        self.vulnRemote = None
        self.vulnLocal = None
        self.publicationDate = None
        self.lastUpdateDate = None
        self.credit = None
        self.introducedIn = None
        self.fixedIn = None
        
    def set_html_page(self, filename):
        self.filename = filename
        
    def parse_page(self):
        parser = etree.HTMLParser()
        tree = etree.parse(self.filename, parser)
        self.parse_title(tree)
        self.bugtraqID = self.parse_element("Bugtraq ID:", tree)
        self.vulnClass = self.parse_element("Class:", tree)
        self.cveID = self.parse_element("CVE:", tree)
        self.vulnRemote = self.parse_element("Remote:", tree)
        self.vulnLocal = self.parse_element("Local:", tree)
        self.publicationDate = self.parse_element("Published:", tree)
        self.lastUpdateDate = self.parse_element("Updated:", tree)
        self.credit = self.parse_element("Credit:", tree)
        # TODO introduced_in and fixed_in in another method because many versions can be listed. Method should find the first vulnerable version or list all the versions?

    def parse_title(self, tree):
        title = tree.xpath('//span[@class="title"]/text()') # return le text dans tous les elements span avec l'attribut class ayant la valeur "title"
        title = title[0]
        self.title = title
        
    """
       Parse the elements in the info page that are contained in the <tr><td><span>element name</span></td><td>element value</td></tr> pattern.
       This is the pattern for all elements except the title.
    """
    def parse_element(self, element_name, html_tree):
        element_value = html_tree.xpath('//span[text() = "' + element_name + '"]/../../td[2]/text()')
        # removes the white spaces around the value in the <td> (the whitespaces not preceded by a non-whitespace char to preserve the white space between the word in the value.)
        element_value = element_value[0].strip()
        if len(element_value) == 0:
            return None
        else:
            return element_value
        
    def get_title(self):
        return self.title
        
    def get_bugtraq_id(self):
        return self.bugtraqID
        
    def get_vuln_class(self):
        return self.vulnClass
        
    def get_cve_id(self):
        return self.cveID
        
    def is_vuln_remote(self):
        return self.vulnRemote
        
    def is_vuln_local(self):
        return self.vulnLocal
        
    def get_publication_date(self):
        return self.publicationDate
        
    def get_last_update_date(self):
        return self.lastUpdateDate
        
    def get_credit(self):
        return self.credit
        
    def get_introduced_in(self):
        return self.introducedIn
        
    def get_fixed_in(self):
        return self.fixedIn


class ReferenceTabParser:

    def __init__(self):
        self.filename = None
