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
        expect = ["4.0rc1", "4.0", "4.1a1", "4.1b1", "4.1"]

        self.assertEqual(expect, VersionCompare.sorted(versions))


class NextMinorTest(TestCase):

    def test_next_minor(self):
        self.assertEqual("3.5", VersionCompare.next_minor("3.4"))
        self.assertEqual("3.6", VersionCompare.next_minor("3.5.4"))
        self.assertEqual("3.6", VersionCompare.next_minor("3.5.4.1"))
        self.assertEqual("3.1", VersionCompare.next_minor("3"))
        self.assertEqual("3.5", VersionCompare.next_minor("3.4.1alpha2"))


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
