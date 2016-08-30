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

    def test_read_and_write_cpe(self):
        plugin = Meta(key="plugins/test-plugin",
                      name="Test Plugin",
                      cpe_names=["cpe:2.3:a:vendor_x:test_plugin"])

        schema = MetaSchema()
        as_string, _ = serialize(schema, plugin)

        self.assertIn("cpe:2.3:a:vendor_x:test_plugin", as_string)

        found_back, _ = schema.loads(as_string)

        self.assertIsNot(plugin, found_back)
        self.assertEqual(plugin, found_back)

    def test_load_missing_fields(self):
        string = '{"name": "A Plugin"}'
        schema = MetaSchema()
        value, errors = schema.loads(string)

        self.assertEqual(errors["key"], ['Missing data for required field.'])

    def test_popular_mark(self):
        plugin = Meta(key="plugins/wordpress-importer",
                      name="WordPress Importer",
                      is_popular=True)

        data, err = serialize(MetaSchema(), plugin)
        self.assertIn('"is_popular": true', data)

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

    def test_serialize_vulnerability_cvss(self):
        schema = VulnerabilitySchema()
        vuln = Vulnerability(id="1234",
                             title="Multiple XSS",
                             cvss=4.5)

        expect = '{"id": "1234", "title": "Multiple XSS", "cvss": 4.5}'
        self.assertEqual(expect, serialize(schema, vuln, indent=None)[0])
        data, err = schema.loads(expect)
        self.assertEqual(4.5, data.cvss)

    def test_serialize_all_values(self):
        reference_date = datetime.now()
        schema = VulnerabilitySchema()
        vuln = Vulnerability(id="1234",
                             title="Multiple XSS",
                             reported_type="XSS",
                             created_at=reference_date,
                             updated_at=reference_date + timedelta(days=6))
        vuln.add_affected_version(VersionRange(fixed_in="1.3"))
        vuln.add_unaffected_version(VersionRange(fixed_in="2.4"))
        vuln.references.append(Reference(type="other", url="http://example.com/test"))

        data = serialize(schema, vuln, indent=None)[0]
        self.assertIn(reference_date.strftime("%Y-%m-%d"), data)
        self.assertIn((reference_date + timedelta(days=6)).strftime("%Y-%m-%d"), data)
        self.assertIn('"reported_type": "XSS"', data)
        self.assertIn('1.3', data)
        self.assertIn('example.com', data)

        out, errors = schema.loads(data)
        self.assertEqual("1.3", out.affected_versions[0].fixed_in)
        self.assertEqual("2.4", out.unaffected_versions[0].fixed_in)
        self.assertEqual("other", out.references[0].type)

    def test_serialize_vunlerability_list(self):
        schema = VulnerabilityListSchema()

        vuln_list = VulnerabilityList(producer="Test Provider",
                                      key="plugins/test-plugin",
                                      copyright="2016- Delve Labs inc.",
                                      license="GNU General Public License, version 2",
                                      vulnerabilities=[
                                        Vulnerability(id="1234", title="Multiple XSS"),
                                      ])

        data = serialize(schema, vuln_list)[0]
        self.assertIn('"producer": "Test Provider"', data)
        self.assertIn('"key": "plugins/test-plugin"', data)
        self.assertIn('"license": "GNU General Public License, version 2"', data)
        self.assertIn('"copyright": "2016- Delve Labs inc."', data)
        self.assertIn('Multiple XSS', data)

        out, errors = schema.loads(data)
        self.assertEqual("1234", out.vulnerabilities[0].id)
