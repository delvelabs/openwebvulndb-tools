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
from tests.fixtures import file_path

from openwebvulndb.common.models import VersionList
from openwebvulndb.wordpress.vane import VaneVersionRebuild


class VaneVersionRebuildTest(TestCase):

    def setUp(self):
        self.rebuild = VaneVersionRebuild(file_path(__file__, "wp_versions.xml"))

    def test_load_files(self):
        self.assertIn("wp-includes/js/wp-ajax.js", self.rebuild.files)
        self.assertIn("readme.html", self.rebuild.files)

    def test_get_hash_for_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            self.rebuild.get_hash("foobar.ext", "12.2")

    def test_read_hash_exists(self):
        self.assertEqual("dfb2d2be1648ee220bf9bd3c03694ed8",
                         self.rebuild.get_hash("readme.html", "3.9.2").attrib["md5"])

    def test_read_hash_creates_new(self):
        self.assertEqual({},
                         self.rebuild.get_hash("readme.html", "4.6.2").attrib)

        self.assertIs(self.rebuild.get_hash("readme.html", "4.6.2"), self.rebuild.get_hash("readme.html", "4.6.2"))

    def test_write_parts(self):
        hash = self.rebuild.get_hash("readme.html", "3.9.2")
        hash.attrib["sha256"] = "deadbeef"

        self.assertIn("deadbeef", self.rebuild.dump(self.rebuild.tree.getroot()))

    def test_clean_node_strips_duplicate_hashes(self):
        input = VaneVersionRebuild.load("""
            <file src="hello.txt">
                <hash sha256="1234" md5="1111"><version>1.2.2</version></hash>
                <hash sha256="1234"><version>1.2.3</version></hash>
                <hash sha256="1234"><version>1.2.4</version></hash>
                <hash md5="1111"><version>1.2.4.1</version></hash>
                <hash sha256="2345"><version>1.2.5</version></hash>
            </file>
        """)
        expect = VaneVersionRebuild.load("""
            <file src="hello.txt">
                <hash sha256="2345"><version>1.2.5</version></hash>
            </file>
        """)

        VaneVersionRebuild.clean(input)
        self.assertEqual(VaneVersionRebuild.dump(input), VaneVersionRebuild.dump(expect))

    def test_update_hashes(self):
        version_list = VersionList(key="wordpress", producer="Test")
        v392 = version_list.get_version("3.9.2", create_missing=True)
        v392.add_signature("readme.html", "1234")
        v392.add_signature("randomfile", "1234")

        v466 = version_list.get_version("4.6.6", create_missing=True)
        v466.add_signature("readme.html", "12345")

        self.rebuild.update(version_list)

        self.assertEqual(self.rebuild.get_hash("readme.html", "3.9.2").attrib["sha256"], "1234")
        self.assertEqual(self.rebuild.get_hash("readme.html", "4.6.6").attrib["sha256"], "12345")
