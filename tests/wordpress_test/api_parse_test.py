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
from openwebvulndb.wordpress.parser import PluginParser, ThemeParser
from openwebvulndb.wordpress.errors import PluginNotFound, ThemeNotFound
from openwebvulndb.common import Meta, Repository

from tests.fixtures import read_file


class PluginApiParseTest(TestCase):

    def setUp(self):
        self.parser = PluginParser()

    def test_no_response(self):
        with self.assertRaises(PluginNotFound):
            self.parser.parse(None)

    def test_null_response(self):
        with self.assertRaises(PluginNotFound):
            self.parser.parse('null')

    def test_invalid_json(self):
        content = read_file(__file__, 'better-wp-security.json')

        with self.assertRaises(PluginNotFound):
            self.parser.parse(content[0:-20])

    def test_missing_required_data(self):
        content = '{"slug": "my-test-plugin"}'

        with self.assertRaises(PluginNotFound):
            self.parser.parse(content)

    def test_with_sample_output(self):
        content = read_file(__file__, 'better-wp-security.json')
        info = self.parser.parse(content)

        self.assertEqual(info, Meta(key="plugins/better-wp-security",
                                    name="iThemes Security (formerly Better WP Security)",
                                    url="https://ithemes.com/security",
                                    repositories=[
                                        Repository(type="subversion",
                                                   location="https://plugins.svn.wordpress.org/better-wp-security/"),
                                    ]))

    def test_manual_creation(self):
        info = self.parser.create_meta(slug="better-wp-security")

        self.assertEqual(info, Meta(key="plugins/better-wp-security",
                                    repositories=[
                                        Repository(type="subversion",
                                                   location="https://plugins.svn.wordpress.org/better-wp-security/"),
                                    ]))



class ThemeApiParseTest(TestCase):

    def setUp(self):
        self.parser = ThemeParser()

    def test_no_response(self):
        with self.assertRaises(ThemeNotFound):
            self.parser.parse(None)

    def test_null_response(self):
        with self.assertRaises(ThemeNotFound):
            self.parser.parse('null')

    def test_false_response(self):
        with self.assertRaises(ThemeNotFound):
            self.parser.parse('false')

    def test_invalid_json(self):
        content = read_file(__file__, 'twentyeleven.json')

        with self.assertRaises(ThemeNotFound):
            self.parser.parse(content[0:-20])

    def test_missing_required_data(self):
        content = '{"slug": "my-test-theme"}'

        with self.assertRaises(ThemeNotFound):
            self.parser.parse(content)

    def test_with_sample_output(self):
        content = read_file(__file__, 'twentyeleven.json')
        info = self.parser.parse(content)

        self.assertEqual(info, Meta(key="themes/twentyeleven",
                                    name="Twenty Eleven",
                                    url="https://wordpress.org/themes/twentyeleven/",
                                    repositories=[
                                        Repository(type="subversion",
                                                   location="https://themes.svn.wordpress.org/twentyeleven/"),
                                    ]))

    def test_create_manually(self):
        info = self.parser.create_meta(slug="twentyeleven")

        self.assertEqual(info, Meta(key="themes/twentyeleven",
                                    repositories=[
                                        Repository(type="subversion",
                                                   location="https://themes.svn.wordpress.org/twentyeleven/"),
                                    ]))
