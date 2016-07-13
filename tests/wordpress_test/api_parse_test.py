from unittest import TestCase
from openwebvulndb.tools.wordpress.parser import PluginParser
from openwebvulndb.tools.wordpress.errors import PluginNotFound
from openwebvulndb.models import Meta, Repository

from fixtures import read_file


class ApiParseTest(TestCase):

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
                                        Repository(type="subversion", location="https://plugins.svn.wordpress.org/better-wp-security/"),
                                    ]))
