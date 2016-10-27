import unittest
from fixtures import file_path, async_test
from openwebvulndb.common.securityfocus.fetcher import SecurityFocusFetcher


class SecurityFocusFetcherTest(unittest.TestCase):

    @async_test()
    async def test_fetch_list_of_first_page_vuln(self):
        fetcher = SecurityFocusFetcher()
        with open(file_path(__file__, "samples/first_page_of_wordpress_vuln.html"), "rt") as html_page:
            list_of_vuln = await fetcher.get_list_of_vuln_on_first_page(file=html_page)
            self.assertEqual(list_of_vuln, [
                                            "http://www.securityfocus.com/bid/93104",
                                            "http://www.securityfocus.com/bid/92841",
                                            "http://www.securityfocus.com/bid/73931",
                                            "http://www.securityfocus.com/bid/92572",
                                            "http://www.securityfocus.com/bid/92077",
                                            "http://www.securityfocus.com/bid/82355",
                                            "http://www.securityfocus.com/bid/91405",
                                            "http://www.securityfocus.com/bid/91076",
                                           ])
