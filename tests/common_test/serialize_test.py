from unittest import TestCase
from openwebvulndb.common import Meta, Repository
from openwebvulndb.common.schemas import MetaSchema, serialize


class SerializeTest(TestCase):

    def test_read_and_write_minimal(self):
        plugin = Meta(key="plugins/test-plugin",
                      name="Test Plugin")

        schema = MetaSchema()
        as_string, _ = serialize(schema, plugin)

        self.assertIn("Test Plugin", as_string)

        self.assertNotIn("url", as_string)
        self.assertNotIn("repositories", as_string)

        found_back, _ = schema.loads(as_string)

        self.assertIsNot(plugin, found_back)
        self.assertEqual(plugin, found_back)

    def test_read_and_write_full_meta(self):
        repo = Repository(type="subversion",
                          location="http://svn.example.com/test-plugin")

        plugin = Meta(key="plugins/test-plugin",
                      name="Test Plugin",
                      url="http://example.com/plugins/test-plugin",
                      repositories=[repo])

        schema = MetaSchema()
        as_string, _ = serialize(schema, plugin)

        self.assertIn("Test Plugin", as_string)

        found_back, _ = schema.loads(as_string)

        self.assertIsNot(plugin, found_back)
        self.assertEqual(plugin, found_back)

    def test_load_missing_fields(self):
        string = '{"key": "a-plugin"}'
        schema = MetaSchema()
        value, errors = schema.loads(string)

        self.assertEqual(errors["name"], ['Missing data for required field.'])
