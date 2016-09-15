import unittest
from securityfocusparsers import InfoTabParser
from datetime import datetime


"""The unit tests for the InfoTabParser class in securityfocusparsers.py. Uses 4 samples for the test."""
class TestInfoTabParser(unittest.TestCase):
    
    def test_parse_wordpress_vuln_no_cve(self):
        parser = InfoTabParser()
        parser.set_html_page("samples/wordpress_vuln_no_cve.html")
        self.assertEqual(parser.get_title(), "WordPress Cross Site Scripting And Directory Traversal Vulnerabilities")
        self.assertEqual(parser.get_bugtraq_id(), "92841")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), None)
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 9, 7, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 9, 7, 0, 0))
        self.assertEqual(parser.get_credit(), "SumOfPwn researcher Cengiz Han Sahin and Dominik Schilling of WordPress.")
        """ self.assertEqual(parser.get_introduced_in(), "0.6.2")
        self.assertEqual(parser.get_fixed_in(), "4.6.1")"""
        
    def test_parse_plugin_vuln_no_cve(self):
        parser = InfoTabParser()
        parser.set_html_page("samples/plugin_vuln_no_cve.html")
        self.assertEqual(parser.get_title(), "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "73931")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), None)
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2009, 12, 7, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 9, 2, 20, 0))
        self.assertEqual(parser.get_credit(), "Henri Salo")
        """self.assertEqual(parser.get_introduced_in(), "1.7.2")
        self.assertEqual(parser.get_fixed_in(), "1.7.2.1")"""
        
    def test_parse_wordpress_vuln_with_cve(self):
        parser = InfoTabParser()
        parser.set_html_page("samples/wordpress_vuln_with_cve.html")
        self.assertEqual(parser.get_title(), "WordPress CVE-2016-6897 Cross Site Request Forgery Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "92572")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), "CVE-2016-6897")
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 8, 20, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 8, 20, 0, 0))
        self.assertEqual(parser.get_credit(), "Yorick Koster")
        """self.assertEqual(parser.get_introduced_in(), "4.5.3")
        self.assertEqual(parser.get_fixed_in(), "4.6")"""
    
    def test_parse_plugin_vuln_with_cve(self):
        parser = InfoTabParser()
        parser.set_html_page("samples/plugin_vuln_with_cve.html")
        self.assertEqual(parser.get_title(), "WordPress Nofollow Links Plugin 'nofollow-links.php' Cross Site Scripting Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "92077")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), "CVE-2016-4833")
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 7, 20, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 7, 20, 0, 0))
        self.assertEqual(parser.get_credit(), "Gen Sato of TRADE WORKS Co.,Ltd. Security Dept.")
        """self.assertEqual(parser.get_introduced_in(), "1.0.10")
        self.assertEqual(parser.get_fixed_in(), "1.0.11")"""

        
unittest.main()
