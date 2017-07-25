from unittest import TestCase
from unittest.mock import MagicMock, patch, ANY
from datetime import datetime
from aiohttp.test_utils import make_mocked_coro, loop_context
from fixtures import async_test, ClientSessionMock

from openwebvulndb.common.securityfocus.database_tools import update_securityfocus_database, fetch_cve_entry
from openwebvulndb.common.models import Vulnerability, Reference
from openwebvulndb.common.cve import CVEReader


class TestSecurityFocusTools(TestCase):

    def test_read_cve_entry_if_cve_exists_for_vulnerability(self):
        date = datetime(2017, 7, 25)
        entry = Vulnerability(id="12345", title="Title", updated_at=date, created_at=date,
                              references=[Reference(type="cve", id="2017-1234")])
        # cve entries fetched individually have a dict for the cpe.
        cve_entry = {"id": "CVE-2017-1234", "cvss": 4.3, "vulnerable_configuration": [{
            "id": "cpe:2.3:a:plugin:plugin:0.1.1:-:-:-:-:wordpress"
        }]}
        fake_fetcher = MagicMock()
        fake_fetcher.get_list_of_vuln_on_first_page = make_mocked_coro(return_value=["vuln_url"])
        fake_fetcher.get_vulnerability_entry = make_mocked_coro(return_value="vuln_entry")
        fake_reader = MagicMock()
        fake_reader.read_one.return_value = entry
        vuln_manager = MagicMock()
        vuln_manager.find_vulnerability.return_value = entry
        cve_reader = CVEReader(storage=None, vulnerability_manager=vuln_manager)
        cve_reader.range_guesser = MagicMock()
        cve_reader.identify_target = MagicMock()

        with patch(self.patch_path("SecurityFocusFetcher"), MagicMock(return_value=fake_fetcher)), \
            patch(self.patch_path("SecurityFocusReader"), MagicMock(return_value=fake_reader)), \
            patch(self.patch_path("fetch_cve_entry"), make_mocked_coro(return_value=cve_entry)) as _fetch_cve_entry:

            with loop_context() as loop:
                update_securityfocus_database(loop, None, None, cve_reader, bugtraq_id=None)

                _fetch_cve_entry.assert_called_once_with(ANY, cve_entry["id"])
                # Make sure the cve entry has been converted to the usual format for the vulnerable configuration.
                cve_reader.identify_target.assert_called_once_with(
                    {"id": "CVE-2017-1234", "cvss": 4.3,
                     "vulnerable_configuration": ["cpe:2.3:a:plugin:plugin:0.1.1:-:-:-:-:wordpress"]})
                self.assertEqual(entry.cvss, 4.3)

    @async_test()
    async def test_fetch_cve_entry(self):
        aiohttp_session = ClientSessionMock()
        aiohttp_session.get_response.text = make_mocked_coro(return_value='{"id": "CVE-1234-5678"}')

        entry = await fetch_cve_entry(aiohttp_session, "CVE-1234-5678")

        aiohttp_session.get.assert_called_once_with("https://cve.circl.lu/api/cve/CVE-1234-5678")
        self.assertEqual(entry, {"id": "CVE-1234-5678"})

    def patch_path(self, path):
        return "openwebvulndb.common.securityfocus.database_tools." + path
