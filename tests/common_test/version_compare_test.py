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
from openwebvulndb.common.version import VersionCompare
from openwebvulndb.common.models import VersionRange, Vulnerability


class VersionCompareTest(TestCase):

    def test_order_versions(self):
        versions = [
            "3.6.1", "3.7", "3.7.1", "3.7.10", "3.7.11", "3.7.12", "3.7.13", "3.7.14", "3.7.15", "3.7.2", "3.7.3",
            "3.7.4", "3.7.5", "3.7.6", "3.7.7", "3.7.8", "3.7.9", "3.8", "3.8.1", "3.8.10", "3.8.11", "3.8.12"]

        expect = [
            "3.6.1", "3.7", "3.7.1", "3.7.2", "3.7.3", "3.7.4", "3.7.5", "3.7.6", "3.7.7", "3.7.8", "3.7.9",
            "3.7.10", "3.7.11", "3.7.12", "3.7.13", "3.7.14", "3.7.15", "3.8", "3.8.1", "3.8.10", "3.8.11", "3.8.12"]

        self.assertEqual(expect, VersionCompare.sorted(versions))

    def test_ordering_with_beta_flags(self):
        versions = ["4.0", "4.1", "4.1-alpha1", "4.1-beta1", "4.0-rc1"]
        expect = ["4.0-rc1", "4.0", "4.1-alpha1", "4.1-beta1", "4.1"]

        self.assertEqual(expect, VersionCompare.sorted(versions))

    def test_ordering_large_subversions(self):
        versions = ["2.80", "2.76", "2.78", "2.8"]
        expect = ["2.8", "2.76", "2.78", "2.80"]

        self.assertEqual(expect, VersionCompare.sorted(versions))


class NextMinorTest(TestCase):

    def test_next_minor(self):
        self.assertEqual("3.5", VersionCompare.next_minor("3.4"))
        self.assertEqual("3.6", VersionCompare.next_minor("3.5.4"))
        self.assertEqual("3.6", VersionCompare.next_minor("3.5.4.1"))
        self.assertEqual("3.1", VersionCompare.next_minor("3"))
        self.assertEqual("3.5", VersionCompare.next_minor("3.4.1alpha2"))

    def test_next_minor_without_leading_digit(self):
        self.assertEqual(".49", VersionCompare.next_minor(".48.2"))


class NextRevisionTest(TestCase):

    def test_next_minor(self):
        self.assertEqual("3.4.1", VersionCompare.next_revision("3.4"))
        self.assertEqual("3.5.5", VersionCompare.next_revision("3.5.4"))
        self.assertEqual("3.5.5", VersionCompare.next_revision("3.5.4.1"))
        self.assertEqual("3.0.1", VersionCompare.next_revision("3"))
        self.assertEqual("3.4.2", VersionCompare.next_revision("3.4.1alpha2"))

    def test_next_minor_without_leading_digit(self):
        self.assertEqual(".48.3", VersionCompare.next_revision(".48.2"))


class VersionRangeTest(TestCase):

    def test_vulnerability_has_no_applicable_ranges(self):
        v = Vulnerability(id="1")
        self.assertTrue(v.applies_to("1.0"))

    def test_vulnerability_introduced_in_only(self):
        v = Vulnerability(id="1")
        v.add_affected_version(VersionRange(introduced_in="2.0"))
        self.assertFalse(v.applies_to("1.0"))
        self.assertFalse(v.applies_to("1.9"))
        self.assertFalse(v.applies_to("2.0-beta3"))
        self.assertTrue(v.applies_to("2.0"))
        self.assertTrue(v.applies_to("2.1"))

    def test_vulnerability_fixed_in_only(self):
        v = Vulnerability(id="1")
        v.add_affected_version(VersionRange(fixed_in="1.0"))
        self.assertFalse(v.applies_to("1.1"))
        self.assertFalse(v.applies_to("1.0"))
        self.assertTrue(v.applies_to("0.9"))

    def test_multiple_ranges(self):
        v = Vulnerability(id="1")
        v.add_affected_version(VersionRange(introduced_in="1.0", fixed_in="1.2"))
        v.add_affected_version(VersionRange(introduced_in="2.0", fixed_in="2.3"))
        v.add_affected_version(VersionRange(introduced_in="3.0", fixed_in="3.1"))
        self.assertFalse(v.applies_to("0.9"))
        self.assertTrue(v.applies_to("2.1"))
        self.assertTrue(v.applies_to("3.0"))
        self.assertFalse(v.applies_to("3.1"))

    def test_multiple_ranges(self):
        v = Vulnerability(id="1")
        v.add_affected_version(VersionRange(fixed_in="1.2"))
        v.add_affected_version(VersionRange(fixed_in="1.3"))

        self.assertEqual(v.affected_versions, [
            VersionRange(fixed_in="1.2"),
            VersionRange(fixed_in="1.3"),
        ])

    def test_added_fix_conflicts_with_known_information(self):
        v = Vulnerability(id="1")
        v.add_affected_version(VersionRange(fixed_in="1.5"))
        v.add_affected_version(VersionRange(introduced_in="2.0", fixed_in="2.5"))
        v.add_affected_version(VersionRange(fixed_in="1.3"))
        v.add_affected_version(VersionRange(fixed_in="2.3"))
        v.add_affected_version(VersionRange(introduced_in="2.3"))

        self.assertEqual(v.affected_versions, [
            VersionRange(fixed_in="1.5"),
            VersionRange(introduced_in="2.0", fixed_in="2.5"),
        ])

    def test_unaffected_versions(self):
        v = Vulnerability(id="1")
        v.unaffected_versions = [
            VersionRange(introduced_in="6.0", fixed_in="6.1.2"),
            VersionRange(introduced_in="7.0", fixed_in="7.0.7"),
        ]

        v.add_affected_version(VersionRange(fixed_in="1.5"))
        v.add_affected_version(VersionRange(introduced_in="6.0", fixed_in="6.1.2"))
        v.add_affected_version(VersionRange(fixed_in="6.1.2"))

        self.assertEqual(v.affected_versions, [
            VersionRange(fixed_in="1.5"),
            VersionRange(fixed_in="6.1.2"),
        ])
