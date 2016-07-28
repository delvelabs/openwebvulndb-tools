from unittest import TestCase
from openwebvulndb.common.manager import ReferenceManager


class ReferenceManagerTest(TestCase):

    def test_references_only_exist_once(self):
        my_list = []
        manager = ReferenceManager.for_list(my_list)
        manager.include_cve("2014-1234")
        manager.include_cve("2014-1234")

        self.assertEqual(len(my_list), 1)

        manager.include_url("http://example.com")

        self.assertEqual(len(my_list), 2)
