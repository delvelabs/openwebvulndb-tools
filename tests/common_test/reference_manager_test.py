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

from unittest import TestCase
from openwebvulndb.common.manager import ReferenceManager


class ReferenceManagerTest(TestCase):

    def test_references_only_exist_once(self):
        my_list = []
        manager = ReferenceManager.for_list(my_list)
        manager.include_normalized("cve", "2014-1234")
        manager.include_normalized("cve", "2014-1234")

        self.assertEqual(len(my_list), 1)

        manager.include_url("http://example.com")

        self.assertEqual(len(my_list), 2)
