import unittest
from datetime import datetime
from openwebvulndb.common.securityfocus.parsers import InfoTabParser, ReferenceTabParser, \
    DiscussionTabParser, ExploitTabParser, SolutionTabParser
from fixtures import file_path


class InfoTabParserTest(unittest.TestCase):
    """The unit tests for the InfoTabParser class in parsers.py. Uses 5 samples for the test."""
    
    def test_parse_wordpress_vuln_no_cve(self):
        parser = InfoTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_no_cve.html"))
        self.assertEqual(parser.get_title(), "WordPress Cross Site Scripting And Directory Traversal Vulnerabilities")
        self.assertEqual(parser.get_bugtraq_id(), "92841")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), [])
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
        self.assertEqual(parser.get_cve_id(), [])
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
        self.assertEqual(parser.get_cve_id(), ["CVE-2016-6897"])
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
        self.assertEqual(parser.get_cve_id(), ["CVE-2016-4833"])
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 7, 20, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 7, 20, 0, 0))
        self.assertEqual(parser.get_credit(), "Gen Sato of TRADE WORKS Co.,Ltd. Security Dept.")
        self.assertEqual(parser.get_vulnerable_versions(), ["WordPress Nofollow Links 1.0.10"])
        self.assertEqual(parser.get_not_vulnerable_versions(), ["WordPress Nofollow Links 1.0.11"])

    def test_parse_plugin_vuln_multiple_identical_cve(self):
        parser = InfoTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_multiple_cve.html"))
        self.assertEqual(parser.get_title(),
                         "WordPress Connections Business Directory Plugin 2016-0770 Cross Site Scripting Vulnerability")
        self.assertEqual(parser.get_bugtraq_id(), "82355")
        self.assertEqual(parser.get_vuln_class(), "Input Validation Error")
        self.assertEqual(parser.get_cve_id(), ["CVE-2016-0770"])
        self.assertEqual(parser.is_vuln_remote(), "Yes")
        self.assertEqual(parser.is_vuln_local(), "No")
        self.assertEqual(parser.get_publication_date(), datetime(2016, 2, 1, 0, 0))
        self.assertEqual(parser.get_last_update_date(), datetime(2016, 7, 6, 12, 13))
        self.assertEqual(parser.get_credit(), "Larry Cashdollar.")
        self.assertEqual(parser.get_vulnerable_versions(), [])
        self.assertEqual(parser.get_not_vulnerable_versions(), [])


class ReferenceTabParserTest(unittest.TestCase):

    def test_parse_plugin_no_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_no_cve_references.html"))
        references_list = parser.get_references()
        self.assertEqual(len(references_list), 3)
        reference = references_list[0]
        self.assertEqual(reference["description"], "CVE request: WordPress plugin wassup cross-site scripting vulnerability (Henri Salo)")
        self.assertEqual(reference["url"], "http://seclists.org/oss-sec/2015/q2/51")
        reference = references_list[1]
        self.assertEqual(reference["description"], "WassUp Changelog (WordPress)")
        self.assertEqual(reference["url"], "http://wordpress.org/extend/plugins/wassup/changelog/")
        reference = references_list[2]
        self.assertEqual(reference["description"], "WassUp Homepage (WordPress)")
        self.assertEqual(reference["url"], "http://wordpress.org/extend/plugins/wassup/")

    def test_parse_plugin_with_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_plugin_vuln_with_cve_references.html"))
        references_list = parser.get_references()
        self.assertEqual(len(references_list), 3)
        reference = references_list[0]
        self.assertEqual(reference["description"], "Nofollow Links Changelog Page (WordPress)")
        self.assertEqual(reference["url"], "https://wordpress.org/plugins/nofollow-links/changelog/")
        reference = references_list[1]
        self.assertEqual(reference["description"], "WordPress HomePage (WordPress)")
        self.assertEqual(reference["url"], "http://wordpress.com/")
        reference = references_list[2]
        self.assertEqual(reference["description"], "JVN#13582657 WordPress plugin 'Nofollow Links' vulnerable to cross-site scriptin (JPCERT/CC and IPA)")
        self.assertEqual(reference["url"], "https://jvn.jp/en/jp/JVN13582657/index.html")

    def test_parse_wordpress_no_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_no_cve_references.html"))
        references_list = parser.get_references()
        self.assertEqual(len(references_list), 4)
        reference = references_list[0]
        self.assertEqual(reference["description"], "Media: Sanitize upload filename.  (WordPress)")
        self.assertEqual(reference["url"], "https://github.com/WordPress/WordPress/commit/c9e60dab176635d4bfaaf431c0ea891e4726d6e0")
        reference = references_list[1]
        self.assertEqual(reference["description"], "WordPress HomePage (WordPress)")
        self.assertEqual(reference["url"], "http://wordpress.org/")
        reference = references_list[2]
        self.assertEqual(reference["description"], "Upgrade/Install: Sanitize file name in `File_Upload_Upgrader`. (WordPress)")
        self.assertEqual(reference["url"], "https://github.com/WordPress/WordPress/commit/54720a14d85bc1197ded7cb09bd3ea790caa0b6e")
        reference = references_list[3]
        self.assertEqual(reference["description"], "WordPress 4.6.1 Security and Maintenance Release (WordPress)")
        self.assertEqual(reference["url"], "https://wordpress.org/news/2016/09/wordpress-4-6-1-security-and-maintenance-release/")

    def test_parse_wordpress_with_cve(self):
        parser = ReferenceTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_wordpress_vuln_with_cve_references.html"))
        references_list = parser.get_references()
        self.assertEqual(len(references_list), 3)
        reference = references_list[0]
        self.assertEqual(reference["description"], " Improve capability checks in wp_ajax_update_plugin() and wp_ajax_delete_plugin( (WordPress)")
        self.assertEqual(reference["url"], "https://core.trac.wordpress.org/ticket/37490")
        reference = references_list[1]
        self.assertEqual(reference["description"], "Path traversal vulnerability in WordPress Core Ajax handlers (sumofpwn.nl)")
        self.assertEqual(reference["url"], "https://sumofpwn.nl/advisory/2016/path_traversal_vulnerability_in_wordpress_core_ajax_handlers.html")
        reference = references_list[2]
        self.assertEqual(reference["description"], "WordPress HomePage (WordPress)")
        self.assertEqual(reference["url"], "http://wordpress.com/")


class DiscussionTabParserTest(unittest.TestCase):

    def test_parse_discussion_2_paragraphs(self):
        parser = DiscussionTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_discussion_2_paragraphs.html"))
        self.assertEqual(parser.get_discussion(), "OneLogin SAML SSO Plugin for WordPress is prone to an authentication "
                                                  "bypass vulnerability. An attacker can exploit this issue to bypass "
                                                  "the authentication mechanism and perform unauthorized actions .")

    def test_parse_discussion_3_paragraphs(self):
        parser = DiscussionTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_discussion_3_paragraphs.html"))
        self.assertEqual(parser.get_discussion(), "W3 Total Cache plugin for WordPress is prone to a cross-site scripting"
                                                  " vulnerability because it fails to properly sanitize user-supplied "
                                                  "input. An attacker may leverage this issue to execute arbitrary script"
                                                  " code in the browser of an unsuspecting user in the context of the "
                                                  "affected site. This can allow the attacker to steal cookie-based "
                                                  "authentication credentials and to launch other attacks. W3 Total "
                                                  "Cache 0.9.4.1 and prior are vulnerable.")


class ExploitTabParserTest(unittest.TestCase):

    def test_parse_exploit_description_1_paragraph(self):
        parser = ExploitTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_exploit_description_1_paragraph.html"))
        self.assertEqual(parser.get_exploit_description(), "To exploit this issue an attacker must entice an unsuspecting"
                                                           " victim to follow a malicious URI.")

    def test_parse_exploit_description_2_paragraphs(self):
        parser = ExploitTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_exploit_description_2_paragraphs.html"))
        self.assertEqual(parser.get_exploit_description(), "The following exploit URL is available: https://www.example"
                                                           ".com/wordpress/wp-admin/admin.php?page=w3tc_support&amp;"
                                                           "request_type=bug_report&amp;payment&amp;url=http://"
                                                           "example1.com&amp;name=test&amp;email=test%40example2"
                                                           ".com&amp;twitter&amp;phone&amp;subject=test&"
                                                           "amp;description=test&amp;forum_url&amp;wp_login&"
                                                           "amp;wp_password&amp;ftp_host&amp;ftp_login&amp;"
                                                           "ftp_password&amp;subscribe_releases&amp;subscribe_"
                                                           "customer&amp;w3tc_error=support_request&amp;request"
                                                           "_id=&lt;XSS&gt;")

    def test_parse_exploit_no_exploit(self):
        parser = ExploitTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_exploit_no_exploit.html"))
        self.assertEqual(parser.get_exploit_description(), None)


class SolutionTabParserTest(unittest.TestCase):

    def test_parse_solution(self):
        parser = SolutionTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_solution.html"))
        self.assertEqual(parser.get_solution(), "Updates are available. Please see the references or vendor advisory "
                                                "for more information.")

    def test_parse_solution_no_solution(self):
        parser = SolutionTabParser()
        parser.set_html_page(file_path(__file__, "samples/securityfocus_solution_no_solution.html"))
        self.assertEqual(parser.get_solution(), None)
