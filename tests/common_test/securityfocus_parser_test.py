import unittest
from datetime import datetime
from openwebvulndb.common.securityfocus.securityfocusparsers import InfoTabParser, ReferenceTabParser
from fixtures import file_path

"""The unit tests for the InfoTabParser class in securityfocusparsers.py. Uses 4 samples for the test."""
class InfoTabParserTest(unittest.TestCase):
    
    def test_parse_wordpress_vuln_no_cve(self):
        parser = InfoTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_no_cve.html"))
        self.assertEqual(parser.get_title(), "WordPress Cross Site Scripting And Directory Traversal Vulnerabilities")
        self.assertEqual(parser.get_bugtraq_id(), "92841")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), None)
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 9, 7, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 9, 7, 0, 0))
        self.assertEqual(parser.get_credit(), "SumOfPwn researcher Cengiz Han Sahin and Dominik Schilling of WordPress.")
        # TODO add tests for vulnerable versions.
        self.assertEqual(parser.get_not_vulnerable_versions(), ["WordPress WordPress 4.6.1"])
        
    def test_parse_plugin_vuln_no_cve(self):
        parser = InfoTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_no_cve.html"))
        self.assertEqual(parser.get_title(), "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "73931")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), None)
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2009, 12, 7, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 9, 2, 20, 0))
        self.assertEqual(parser.get_credit(), "Henri Salo")
        self.assertEqual(parser.get_vulnerable_versions(), ["WordPress WassUp  1.7.2"])
        self.assertEqual(parser.get_not_vulnerable_versions(), ["WordPress WassUp  1.7.2.1"])
        
    def test_parse_wordpress_vuln_with_cve(self):
        parser = InfoTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_with_cve.html"))
        self.assertEqual(parser.get_title(), "WordPress CVE-2016-6897 Cross Site Request Forgery Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "92572")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), "CVE-2016-6897")
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 8, 20, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 8, 20, 0, 0))
        self.assertEqual(parser.get_credit(), "Yorick Koster")
        self.assertEqual(parser.get_vulnerable_versions(), ['WordPress WordPress  4.5.3'])
        self.assertEqual(parser.get_not_vulnerable_versions(), ['WordPress WordPress  4.6'])
    
    def test_parse_plugin_vuln_with_cve(self):
        parser = InfoTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_with_cve.html"))
        self.assertEqual(parser.get_title(), "WordPress Nofollow Links Plugin 'nofollow-links.php' Cross Site Scripting Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "92077")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), "CVE-2016-4833")
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 7, 20, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 7, 20, 0, 0))
        self.assertEqual(parser.get_credit(), "Gen Sato of TRADE WORKS Co.,Ltd. Security Dept.")
        self.assertEqual(parser.get_vulnerable_versions(), ["WordPress Nofollow Links 1.0.10"])
        self.assertEqual(parser.get_not_vulnerable_versions(), ["WordPress Nofollow Links 1.0.11"])


class ReferenceTabParserTest(unittest.TestCase):

    def test_parse_plugin_no_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_no_cve_references.html"))
        self.assertEqual(parser.get_references(), [["CVE request: WordPress plugin wassup cross-site scripting vulnerability (Henri Salo)",
                                                    "http://seclists.org/oss-sec/2015/q2/51"],
                                                   ["WassUp Changelog (WordPress)", "http://wordpress.org/extend/plugins/wassup/changelog/"],
                                                   ["WassUp Homepage (WordPress)", "http://wordpress.org/extend/plugins/wassup/"]])

    def test_parse_plugin_with_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_with_cve_references.html"))
        self.assertEqual(parser.get_references(), [["Nofollow Links Changelog Page (WordPress)",
                                                    "https://wordpress.org/plugins/nofollow-links/changelog/"],
                                                   ["WordPress HomePage (WordPress)", "http://wordpress.com/"],
                                                   ["JVN#13582657 WordPress plugin 'Nofollow Links' vulnerable to cross-site scriptin (JPCERT/CC and IPA)",
                                                    "https://jvn.jp/en/jp/JVN13582657/index.html"]])

    def test_parse_wordpress_no_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_no_cve_references.html"))
        self.assertEqual(parser.get_references(), [["Media: Sanitize upload filename.  (WordPress)",
                                                    "https://github.com/WordPress/WordPress/commit/c9e60dab176635d4bfaaf431c0ea891e4726d6e0"],
                                                   ["WordPress HomePage (WordPress)", "http://wordpress.org/"],
                                                   ["Upgrade/Install: Sanitize file name in `File_Upload_Upgrader`. (WordPress)",
                                                    "https://github.com/WordPress/WordPress/commit/54720a14d85bc1197ded7cb09bd3ea790caa0b6e"],
                                                   ["WordPress 4.6.1 Security and Maintenance Release (WordPress)",
                                                    "https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/"]])

    def test_parse_wordpress_with_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_with_cve_references.html"))
        self.assertEqual(parser.get_references(), [[" Improve capability checks in wp_ajax_update_plugin() and wp_ajax_delete_plugin( (WordPress)",
                                                    "https://core.trac.wordpress.org/ticket/37490"],
                                                   ["Path traversal vulnerability in WordPress Core Ajax handlers (sumofpwn.nl)",
                                                    "https://sumofpwn.nl/advisory/2016/path_traversal_vulnerability_in_wordpress_core_ajax_handlers.html"],
                                                   ["WordPress HomePage (WordPress)", "http://wordpress.com/"]])
