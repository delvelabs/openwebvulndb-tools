from unittest import TestCase
from unittest.mock import MagicMock
from openwebvulndb.wordpress.vane2 import Vane2VersionRebuild
from openwebvulndb.common.schemas import VersionListSchema, SignatureSchema
from openwebvulndb.common.models import Signature, VersionDefinition, VersionList
from fixtures import file_path
import re


class Vane2VersionRebuildTest(TestCase):

    def setUp(self):
        self.version_rebuild = Vane2VersionRebuild(MagicMock())

    def test_update_load_wordpress_version_signature_from_repository(self):
        versions = '{"key": "wordpress", "producer": "unittest", "versions": [{"version": "1.4", "signatures": [{"path": "readme.html", "algo": "md5", "hash": "12345"}]}]}'
        schema = VersionListSchema()
        versions_list = schema.loads(versions).data
        self.version_rebuild.storage.read_versions.return_value = versions_list
        self.version_rebuild._cleanup_signatures = MagicMock()

        self.version_rebuild.update("wordpress")
        self.version_rebuild.storage.read_versions.assert_called_once_with("wordpress")
        self.assertEqual(re.sub("\s", "", self.version_rebuild.dump()), re.sub("\s", "", versions))

    def test_update_cleanup_signatures(self):
        versions = {"key": "wordpress", "producer": "unittest", "versions": [
            {"version": "1.4", "signatures": [{"path": "readme.html", "algo": "md5", "hash": "12345"}]}
        ]}
        schema = VersionListSchema()
        self.version_rebuild.storage.read_versions.return_value = schema.load(versions).data
        self.version_rebuild._cleanup_signatures = MagicMock()

        self.version_rebuild.update("wordpress")

        self.version_rebuild._cleanup_signatures.assert_called_once_with(self.version_rebuild.version_list.versions[0].signatures)

    def test_cleanup_signatures_only_keep_specified_files(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "wp-admin/js/common.js"]
        signatures = [{"path": "readme.html", "algo": "md5", "hash": "12345"},
                      {"path": "wp-admin/js/common.js", "algo": "md5", "hash": "23456"},
                      {"path": "other_file.js", "algo": "md5", "hash": "34567"}]
        schema = SignatureSchema()
        signatures = [schema.load(signature).data for signature in signatures]

        self.version_rebuild._cleanup_signatures(signatures)

        signature_paths = [signature.path for signature in signatures]
        self.assertIn("readme.html", signature_paths)
        self.assertIn("wp-admin/js/common.js", signature_paths)
        self.assertNotIn("other_file.js", signature_paths)

    def test_load_files_for_signatures_from_file(self):
        filename = file_path(__file__, "samples/versions_signature_files")

        self.version_rebuild.load_files_for_versions_signatures(filename)

        self.assertEqual(self.version_rebuild.get_files_to_use_for_signature(), ["readme.html", "file1.js", "style.css",
                                                                                 "another_file.js"])

    def test_versions_equal_return_true_if_two_versions_have_same_file_with_same_hash(self):
        readme_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        button_js_signature = Signature(path="button.js", hash=9101112)
        version1 = VersionDefinition(version="1.0", signatures=[readme_signature, style_css_signature, button_js_signature])
        version2 = VersionDefinition(version="2.0", signatures=[readme_signature, style_css_signature, button_js_signature])

        self.assertTrue(self.version_rebuild._versions_equal(version1, version2))

    def test_versions_equal_return_false_if_two_versions_have_same_file_with_different_hashes(self):
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        button_js_signature = Signature(path="button.js", hash=9101112)
        readme2_signature = Signature(path="readme.html", hash=2345)
        version1 = VersionDefinition(version="1.0", signatures=[readme1_signature, style_css_signature, button_js_signature])
        version2 = VersionDefinition(version="2.0", signatures=[readme2_signature, style_css_signature, button_js_signature])

        self.assertFalse(self.version_rebuild._versions_equal(version1, version2))

    def test_versions_equal_return_false_if_two_versions_have_different_files(self):
        readme_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        button_js_signature = Signature(path="button.js", hash=9101112)
        version1 = VersionDefinition(version="1.0", signatures=[readme_signature, button_js_signature])
        version2 = VersionDefinition(version="2.0", signatures=[readme_signature, button_js_signature, style_css_signature])

        self.assertFalse(self.version_rebuild._versions_equal(version1, version2))

    def test_check_for_equal_version_signatures_raises_error_if_two_different_major_versions_have_the_same_signatures(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "style.css", "button.js"]
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        button_js_signature = Signature(path="button.js", hash=9101112)
        readme2_signature = Signature(path="readme.html", hash=1234)
        version1 = VersionDefinition(version="1.0", signatures=[readme1_signature, style_css_signature, button_js_signature])
        version2 = VersionDefinition(version="2.0", signatures=[readme2_signature, style_css_signature, button_js_signature])
        self.version_rebuild.version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version2])

        with self.assertRaises(ValueError):
            self.version_rebuild.check_for_equal_version_signatures()

    def test_check_for_equal_version_signatures_do_nothing_if_two_versions_from_same_major_have_the_same_signatures(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "style.css", "button.js"]
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        button_js_signature = Signature(path="button.js", hash=9101112)
        readme1_1_signature = Signature(path="readme.html", hash=1234)
        version1 = VersionDefinition(version="1.0.1", signatures=[readme1_signature, style_css_signature, button_js_signature])
        version1_1 = VersionDefinition(version="1.0.1", signatures=[readme1_1_signature, style_css_signature, button_js_signature])
        self.version_rebuild.version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version1_1])

        try:
            self.version_rebuild.check_for_equal_version_signatures()
        except ValueError:
            self.fail("Unexpected error raised.")

    def test_check_for_equal_version_signatures_dont_raise_error_if_versions_have_different_signatures(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "style.css", "button.js"]
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        button_js_signature = Signature(path="button.js", hash=9101112)
        readme2_signature = Signature(path="readme.html", hash=2345)
        version1 = VersionDefinition(version="1.0", signatures=[readme1_signature, style_css_signature, button_js_signature])
        version2 = VersionDefinition(version="2.0", signatures=[readme2_signature, style_css_signature, button_js_signature])
        version3 = VersionDefinition(version="3.0", signatures=[readme1_signature, style_css_signature])
        self.version_rebuild.version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version2, version3])

        try:
            self.version_rebuild.check_for_equal_version_signatures()
        except ValueError:
            self.fail("Unexpected error raised.")

    def test_check_for_equal_version_signatures_raise_error_if_two_recent_minor_have_same_signature(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "style.css", "button.js"]
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        version1 = VersionDefinition(version="4.1.0", signatures=[readme1_signature, style_css_signature])
        version2 = VersionDefinition(version="4.1.1", signatures=[readme1_signature, style_css_signature])
        self.version_rebuild.version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version2])

        with self.assertRaises(ValueError):
            self.version_rebuild.check_for_equal_version_signatures()

    def test_check_for_equal_version_signatures_dont_raise_error_if_two_old_minor_have_same_signature(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "style.css", "button.js"]
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        version1 = VersionDefinition(version="1.5.0", signatures=[readme1_signature, style_css_signature])
        version2 = VersionDefinition(version="1.5.1", signatures=[readme1_signature, style_css_signature])
        self.version_rebuild.version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version2])

        try:
            self.version_rebuild.check_for_equal_version_signatures()
        except ValueError:
            self.fail("Unexpected error raised.")

    def test_get_diff_with_other_version_return_files_with_different_hash(self):
        common_file = Signature(path="style.css", hash=1234)
        button_file1 = Signature(path="button.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        button_file2 = Signature(path="button.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        version1 = VersionDefinition(version="1.0", signatures=[common_file, readme_file1, button_file1])
        version2 = VersionDefinition(version="1.1", signatures=[common_file, readme_file2, button_file2])

        files = self.version_rebuild._get_diff_with_other_version(version1, version2)

        self.assertIn("button.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)

    def test_get_diff_with_other_version_return_files_not_in_other_version(self):
        common_file = Signature(path="style.css", hash=1234)
        file1 = Signature(path="file1.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        file2 = Signature(path="file2.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        version1 = VersionDefinition(version="1.0", signatures=[common_file, readme_file1, file1])
        version2 = VersionDefinition(version="1.1", signatures=[common_file, readme_file2, file2])

        files = self.version_rebuild._get_diff_with_other_version(version1, version2)

        self.assertIn("file1.js", files)
        self.assertIn("file2.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)

    def test_get_files_for_versions_identification_return_minimum_files_required_to_make_each_version_unique(self):
        common_file = Signature(path="style.css", hash=1234)  # useless for version identification
        button_file_version1 = Signature(path="button.js", hash=2345)  # Unique to 1.0
        readme_file1 = Signature(path="readme.html", hash=3456)  # used by 1.0 and 1.1
        button_file_other_version = Signature(path="button.js", hash=4567)
        common_file2 = Signature(path="style2.css", hash=5678)  # useless for version identification
        readme_file2 = Signature(path="readme.html", hash=6789)  # unique to 2.0
        readme_file3 = Signature(path="readme.html", hash=7890)  # unique to 3.0
        common_file_version_2_3 = Signature(path="button.css", hash=8901)  # Unique to 2.0 and 3.0, but useless for version identification

        version1 = VersionDefinition(version="1.0", signatures=[common_file, common_file2, readme_file1, button_file_version1])
        version1_1 = VersionDefinition(version="1.1", signatures=[common_file, common_file2, readme_file1, button_file_other_version])
        version2 = VersionDefinition(version="2.0", signatures=[common_file, common_file2, readme_file2, button_file_other_version, common_file_version_2_3])
        version3 = VersionDefinition(version="3.0", signatures=[common_file, common_file2, readme_file3, button_file_other_version, common_file_version_2_3])

        version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version1_1, version2, version3])

        files = self.version_rebuild.get_files_for_versions_identification(version_list)

        self.assertIn("button.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)
        self.assertNotIn("style2.css", files)
        self.assertNotIn("button.css", files)

    def test_create_version_without_file_in_signature(self):
        file1_signature = Signature(path="file1", hash=1234)
        file2_signature = Signature(path="file2", hash=2345)
        version = VersionDefinition(version="1.0", signatures=[file1_signature, file2_signature])

        new_version = self.version_rebuild._create_version_without_files_in_signature(version, ["file2"])

        self.assertEqual(new_version.version, version.version)
        self.assertIn(file1_signature, new_version.signatures)
        self.assertNotIn(file2_signature, new_version.signatures)

    def test_is_recent_version(self):
        version3 = "3.1.1"
        version4 = "4.3.2"
        version2 = "2.5.1"
        version1 = "1.5.3"

        self.assertTrue(self.version_rebuild._is_recent_version(version3))
        self.assertTrue(self.version_rebuild._is_recent_version(version4))
        self.assertFalse(self.version_rebuild._is_recent_version(version2))
        self.assertFalse(self.version_rebuild._is_recent_version(version1))

    def test_get_minor_version_in_major_version(self):
        major = "4.7"
        minor1 = VersionDefinition(version="4.7.1")
        minor2 = VersionDefinition(version="4.7.2")
        minor_not_in_major = VersionDefinition(version="4.6.1")
        version_list = VersionList(key="wordpress", producer="", versions=[minor1, minor2, minor_not_in_major])

        minor_versions = self.version_rebuild.get_minor_versions_in_major_version(version_list, major)

        self.assertIn(minor1, minor_versions)
        self.assertIn(minor2, minor_versions)
        self.assertNotIn(minor_not_in_major, minor_versions)

    def test_get_common_file_for_major_version(self):
        readme1 = Signature(path="readme.html", hash=1)
        readme2 = Signature(path="readme.html", hash=2)
        button = Signature(path="button.js", hash=3)
        style_version_4_7 = Signature(path="style.css", hash=47)
        style_other_versions = Signature(path="style.css", hash=0)

        major = "4.7"
        version4_7_1 = VersionDefinition(version="4.7.1", signatures=[readme1, button, style_version_4_7])
        version4_7_2 = VersionDefinition(version="4.7.2", signatures=[readme2, button, style_version_4_7])
        version3 = VersionDefinition(version="3.4.1", signatures=[button, style_other_versions])
        version_list = VersionList(key="wordpress", producer="", versions=[version4_7_1, version4_7_2, version3])

        files = self.version_rebuild.get_common_file_for_major_version(major, version_list)

        self.assertIn("style.css", files)
        self.assertIn("button.js", files)
        self.assertEqual(len(files), 2)
