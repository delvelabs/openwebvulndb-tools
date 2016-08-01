from datetime import datetime, timedelta

from unittest import TestCase
from openwebvulndb.common.models import Meta, Repository, Reference, VersionRange
from openwebvulndb.common.models import Vulnerability, VulnerabilityList
from openwebvulndb.common.schemas import MetaSchema, ReferenceSchema, VersionRangeSchema
from openwebvulndb.common.schemas import VulnerabilitySchema, VulnerabilityListSchema
from openwebvulndb.common.serialize import serialize


class SerializeTest(TestCase):

    def test_read_and_write_minimal(self):
        plugin = Meta(key="plugins/test-plugin")

        schema = MetaSchema()
        as_string, _ = serialize(schema, plugin)

        self.assertIn("test-plugin", as_string)

        self.assertNotIn("url", as_string)
        self.assertNotIn("repositories", as_string)
        self.assertNotIn("name", as_string)

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
        string = '{"name": "A Plugin"}'
        schema = MetaSchema()
        value, errors = schema.loads(string)

        self.assertEqual(errors["key"], ['Missing data for required field.'])

    def test_serialize_reference(self):
        ref = Reference(type="osvdb", id="12345")
        self.assertEqual('{"type": "osvdb", "id": "12345"}',
                         serialize(ReferenceSchema(), ref, indent=None)[0])

        ref = Reference(type="osvdb", url="http://example.com/12345")
        self.assertEqual('{"type": "osvdb", "url": "http://example.com/12345"}',
                         serialize(ReferenceSchema(), ref, indent=None)[0])

        ref = Reference(type="foobar")
        self.assertEqual({'_schema': [
            "Either id or url is required.",
        ]}, ReferenceSchema().loads(serialize(ReferenceSchema(), ref)[0])[1])

    def test_affected_version(self):
        schema = VersionRangeSchema()
        ver = VersionRange(introduced_in="1.2.3", fixed_in="1.3.4")
        self.assertEqual('{"introduced_in": "1.2.3", "fixed_in": "1.3.4"}',
                         serialize(schema, ver, indent=None)[0])

        ver = VersionRange(introduced_in="1.2.3")
        self.assertEqual('{"introduced_in": "1.2.3"}',
                         serialize(schema, ver, indent=None)[0])

        ver = VersionRange(fixed_in="1.2.3")
        self.assertEqual('{"fixed_in": "1.2.3"}',
                         serialize(schema, ver, indent=None)[0])

        ver = VersionRange()
        self.assertEqual({'_schema': [
            "Either introduced_in or fixed_in is required.",
        ]}, schema.loads(serialize(schema, ver)[0])[1])

    def test_serialize_vulnerability_minimal(self):
        schema = VulnerabilitySchema()
        vuln = Vulnerability(id="1234",
                             title="Multiple XSS")

        self.assertEqual('{"id": "1234", "title": "Multiple XSS"}', serialize(schema, vuln, indent=None)[0])

    def test_serialize_all_values(self):
        reference_date = datetime.now()
        schema = VulnerabilitySchema()
        vuln = Vulnerability(id="1234",
                             title="Multiple XSS",
                             reported_type="XSS",
                             created_at=reference_date,
                             updated_at=reference_date + timedelta(days=6))
        vuln.add_affected_version(VersionRange(fixed_in="1.3"))
        vuln.references.append(Reference(type="other", url="http://example.com/test"))

        data = serialize(schema, vuln, indent=None)[0]
        self.assertIn(reference_date.strftime("%Y-%m-%d"), data)
        self.assertIn((reference_date + timedelta(days=6)).strftime("%Y-%m-%d"), data)
        self.assertIn('"reported_type": "XSS"', data)
        self.assertIn('1.3', data)
        self.assertIn('example.com', data)

        out, errors = schema.loads(data)
        self.assertEqual("1.3", out.affected_versions[0].fixed_in)
        self.assertEqual("other", out.references[0].type)

    def test_serialize_vunlerability_list(self):
        schema = VulnerabilityListSchema()

        vuln_list = VulnerabilityList(producer="Test Provider",
                                      key="plugins/test-plugin",
                                      vulnerabilities=[
                                        Vulnerability(id="1234", title="Multiple XSS"),
                                      ])

        data = serialize(schema, vuln_list)[0]
        self.assertIn('"producer": "Test Provider"', data)
        self.assertIn('"key": "plugins/test-plugin"', data)
        self.assertIn('Multiple XSS', data)

        out, errors = schema.loads(data)
        self.assertEqual("1234", out.vulnerabilities[0].id)
