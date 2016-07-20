from unittest import TestCase
from openwebvulndb.wordpress.parser import PluginParser, ThemeParser
from openwebvulndb.wordpress.errors import PluginNotFound, ThemeNotFound
from openwebvulndb.common import Meta, Repository

from fixtures import read_file


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
                                    url="https://wordpress.org/plugins/better-wp-security/",
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
