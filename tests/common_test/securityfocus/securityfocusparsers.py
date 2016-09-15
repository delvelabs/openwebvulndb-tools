from lxml import etree
from datetime import datetime


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

    """Convert a month represented by a 3 letter string (ex: "Dec" for december) to its number (ex: "Dec" return 12)."""
    def _month_str_to_month_number(self, month_str):
        if month_str == "Jan":
            return 1
        elif month_str == "Feb":
            return 2
        elif month_str == "Mar":
            return 3
        elif month_str == "Apr":
            return 4
        elif month_str == "May":
            return 5
        elif month_str == "Jun":
            return 6
        elif month_str == "Jul":
            return 7
        elif month_str == "Aug":
            return 8
        elif month_str == "Sep":
            return 9
        elif month_str == "Oct":
            return 10
        elif month_str == "Nov":
            return 11
        elif month_str == "Dec":
            return 12
        else:
            return 0

    """Convert the date in the string str_date into a datetime.datetime object. The format for the input string is:
        'Mmm dd yyyy hh:mmAP', where Mmm is the first three letters of the month (first one is uppercase), dd is the day
         in two digit, yyyy is the year, hh::mm is the hour and the minutes and AP is 'AM' or 'PM'."""
    def _string_date_to_datetime_object(self, str_date):
        date_elements = str_date.split(' ')
        str_month = date_elements[0]
        str_day = date_elements[1]
        str_year = date_elements[2]
        hour_elements = date_elements[3].split(':')
        str_hour = hour_elements[0]
        str_min = (hour_elements[1])[0:2]
        if (hour_elements[1])[2:4] == "PM":
            pm = True
        else:
            pm = False
        month = self._month_str_to_month_number(str_month)
        day = int(str_day)
        year = int(str_year)
        hour = int(str_hour)
        if pm:
            if hour < 12:
                hour += 12
        elif hour == 12:
            hour = 0
        minutes = int(str_min)
        date = datetime(year, month, day, hour, minutes)
        return date

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
        return self._string_date_to_datetime_object(string_date)

    def get_last_update_date(self):
        string_date = self._parse_element("Updated:")
        return self._string_date_to_datetime_object(string_date)
        
    def get_credit(self):
        return self._parse_element("Credit:")

    def get_vulnerable_versions(self):
        vuln_versions_list = self._parse_vulnerable_versions()
        return vuln_versions_list
        
    def get_not_vulnerable_versions(self):
        not_vuln_versions_list = self._parse_not_vulnerable_versions()
        return not_vuln_versions_list
