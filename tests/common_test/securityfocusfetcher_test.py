# openwebvulndb-tools: A collection of tools to maintain vulnerability databases
# Copyright (C) 2016-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import unittest
from unittest.mock import MagicMock
from fixtures import file_path, async_test, ClientSessionMock
from aiohttp.test_utils import make_mocked_coro
from openwebvulndb.common.securityfocus.fetcher import SecurityFocusFetcher
import asyncio


class SecurityFocusFetcherTest(unittest.TestCase):

    @async_test()
    async def test_fetch_list_of_first_page_vuln(self):
        fetcher = SecurityFocusFetcher()
        with open(file_path(__file__, "samples/first_page_of_wordpress_vuln.html"), "rt") as html_page:
            list_of_vuln = await fetcher.get_vulnerability_list(file=html_page)
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
    @async_test()
    async def test_get_vulnerabilities(self):
        fake_get_response = MagicMock()
        fake_get_response.status = 200
        fake_get_response.text = make_mocked_coro(return_value="<html><head></head><body></body></html>")
        fetcher = SecurityFocusFetcher(aiohttp_session=ClientSessionMock(get_response=fake_get_response))
        fetcher.get_vulnerability_list = make_mocked_coro(return_value=["http://www.securityfocus.com/bid/93104",
                                                                        "http://www.securityfocus.com/bid/92841"])

        vuln_entries = await fetcher.get_vulnerabilities()
        self.assertEqual(vuln_entries[0]["id"], "93104")
        self.assertEqual(vuln_entries[1]["id"], "92841")

    @async_test()
    async def test_get_vulnerability_entry_return_none_if_page_request_raise_exception(self):
        fetcher = SecurityFocusFetcher(aiohttp_session=ClientSessionMock(get_exception=asyncio.TimeoutError))

        self.assertIsNone(await fetcher.get_vulnerability_entry("12345"))

    @async_test()
    async def test_get_vulnerability_entry_return_none_if_page_request_response_status_is_not_200(self):
        fake_get_response = MagicMock()
        fake_get_response.status = 503
        fetcher = SecurityFocusFetcher(aiohttp_session=ClientSessionMock(get_response=fake_get_response))

        self.assertIsNone(await fetcher.get_vulnerability_entry("12345"))
