import unittest
from fixtures import file_path
import asyncio
from openwebvulndb.common.securityfocus.securityfocusfetcher import SecurityFocusFetcher

class SecurityFocusFetcherTest(unittest.TestCase):

    def test_fetch_list_of_first_page_vuln(self):
        fetcher = SecurityFocusFetcher()
        try:
            loop = asyncio.new_event_loop()
            html_page = open(file_path(__file__, "samples/first_page_of_wordpress_vuln.html"), "rt")
            list_of_vuln = loop.run_until_complete(fetcher.get_list_of_vuln_on_first_page(file=html_page))
            html_page.close()
            loop.close()
            self.assertEqual(list_of_vuln, [
                {
                    "date": "2016-09-23",
                    "title": "WordPress W3 Total Cache Plugin 'admin.php' Cross Site Scripting Vulnerability",
                    "url": "http://www.securityfocus.com/bid/93104"
                },
                {
                    "date": "2016-09-07",
                    "title": "WordPress Cross Site Scripting And Directory Traversal Vulnerabilities",
                    "url": "http://www.securityfocus.com/bid/92841"
                },
                {
                    "date": "2016-09-02",
                    "title": "WordPress WassUp Plugin 'main.php' Cross Site Scripting Vulnerability",
                    "url": "http://www.securityfocus.com/bid/73931"
                },
                {
                    "date": "2016-08-20",
                    "title": "WordPress CVE-2016-6897 Cross Site Request Forgery Vulnerability",
                    "url": "http://www.securityfocus.com/bid/92572"
                },
                {
                    "date": "2016-07-20",
                    "title": "WordPress Nofollow Links Plugin 'nofollow-links.php' Cross Site Scripting Vulnerability",
                    "url": "http://www.securityfocus.com/bid/92077"
                },
                {
                    "date": "2016-07-06",
                    "title": "WordPress Connections Business Directory Plugin 2016-0770 Cross Site Scripting Vulnerability",
                    "url": "http://www.securityfocus.com/bid/82355"
                },
                {
                    "date": "2016-07-06",
                    "title": "Wordpress Welcart e-Commerce Plugin CVE-2016-4825 PHP Object Injection Vulnerability",
                    "url": "http://www.securityfocus.com/bid/91405"
                },
                {
                    "date": "2016-07-06",
                    "title": "WordPress OneLogin SAML SSO Plugin Authentication Bypass Vulnerability",
                    "url": "http://www.securityfocus.com/bid/91076"
                }
            ])
        except OSError:
            self.fail("Error when trying to open the file.")
