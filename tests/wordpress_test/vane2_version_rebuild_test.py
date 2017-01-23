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

        with self.assertRaises(Exception):
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
        except Exception:
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
        except Exception:
            self.fail("Unexpected error raised.")

    def test_check_for_equal_version_signatures_raise_error_if_two_recent_minor_have_same_signature(self):
        self.version_rebuild._versions_signature_files = ["readme.html", "style.css", "button.js"]
        readme1_signature = Signature(path="readme.html", hash=1234)
        style_css_signature = Signature(path="style.css", hash=5678)
        version1 = VersionDefinition(version="4.1.0", signatures=[readme1_signature, style_css_signature])
        version2 = VersionDefinition(version="4.1.1", signatures=[readme1_signature, style_css_signature])
        self.version_rebuild.version_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version2])

        with self.assertRaises(Exception):
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
        except Exception:
            self.fail("Unexpected error raised.")

    def test_compare_signatures_return_files_with_different_hash(self):
        common_file = Signature(path="style.css", hash=1234)
        button_file1 = Signature(path="button.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        button_file2 = Signature(path="button.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        signatures0 = [common_file, readme_file1, button_file1]
        signatures1 = [common_file, readme_file2, button_file2]

        files = self.version_rebuild.compare_signatures(signatures0, signatures1)

        self.assertIn("button.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)

    def test_compare_signatures_return_files_not_in_other_version(self):
        common_file = Signature(path="style.css", hash=1234)
        file1 = Signature(path="file1.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        file2 = Signature(path="file2.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        signatures0 = [common_file, readme_file1, file1]
        signatures1 = [common_file, readme_file2, file2]

        files = self.version_rebuild.compare_signatures(signatures0, signatures1)

        self.assertIn("file1.js", files)
        self.assertIn("file2.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)

    def test_compare_signatures_ignore_exclude_files(self):
        common_file = Signature(path="style.css", hash=1234)
        file1 = Signature(path="file1.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        file2 = Signature(path="file2.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        signatures0 = [common_file, readme_file1, file1]
        signatures1 = [common_file, readme_file2, file2]

        files = self.version_rebuild.compare_signatures(signatures0, signatures1, exclude_file=readme_file1.path)

        self.assertIn("file1.js", files)
        self.assertIn("file2.js", files)
        self.assertNotIn("readme.html", files)
        self.assertNotIn("style.css", files)

    def test_compare_signatures_ignore_exclude_files_ignore_plugin_and_themes_files_by_default(self):
        file0 = Signature(path="wp-content/plugins/my-plugin/style.css", hash=1234)
        file1 = Signature(path="file1.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        file2 = Signature(path="wp-content/themes/my-theme/file2.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        signatures0 = [file0, readme_file1, file1]
        signatures1 = [readme_file2, file2]

        files = self.version_rebuild.compare_signatures(signatures0, signatures1)

        self.assertIn("readme.html", files)
        self.assertNotIn("wp-content/plugins/my-plugin/style.css", files)
        self.assertIn("file1.js", files)
        self.assertNotIn("wp-content/themes/my-theme/file2.js", files)

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

        files, versions_without_diff = self.version_rebuild.get_files_for_versions_identification_major_minor_algo(version_list)

        self.assertIn("button.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)
        self.assertNotIn("style2.css", files)
        self.assertNotIn("button.css", files)

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

    def test_create_version_definition_for_major_version(self):
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

        version_definition = self.version_rebuild.create_version_definition_for_major_version(version_list, major)

        self.assertIn(style_version_4_7, version_definition.signatures)
        self.assertIn(button, version_definition.signatures)
        self.assertEqual(len(version_definition.signatures), 2)

    def test_get_diff_between_minor_versions(self):
        readme1 = Signature(path="readme.html", hash=1)
        readme2 = Signature(path="readme.html", hash=2)
        common_file = Signature(path="button.js", hash=3)

        major = ["4.7"]
        version4_7_1 = VersionDefinition(version="4.7.1", signatures=[readme1, common_file])
        version4_7_2 = VersionDefinition(version="4.7.2", signatures=[readme2, common_file])
        version_list = VersionList(key="", producer="", versions=[version4_7_1, version4_7_2])

        files, versions_without_diff = self.version_rebuild.get_files_to_identify_minor_versions(version_list, major)

        self.assertIn("readme.html", files)
        self.assertNotIn("button.js", files)

    def test_is_version_greater_than_other_version(self):
        version1 = "1.2.3"
        version2 = "2.0"
        version3 = "1.3"
        version4 = "1.2.3.1"

        self.assertTrue(self.version_rebuild.is_version_greater_than_other_version(version2, version1))
        self.assertTrue(self.version_rebuild.is_version_greater_than_other_version(version3, version1))
        self.assertTrue(self.version_rebuild.is_version_greater_than_other_version(version4, version1))
        self.assertTrue(self.version_rebuild.is_version_greater_than_other_version(version2, version3))
        self.assertTrue(self.version_rebuild.is_version_greater_than_other_version(version2, version4))
        self.assertTrue(self.version_rebuild.is_version_greater_than_other_version(version3, version4))

        self.assertFalse(self.version_rebuild.is_version_greater_than_other_version(version1, version2))
        self.assertFalse(self.version_rebuild.is_version_greater_than_other_version(version1, version3))
        self.assertFalse(self.version_rebuild.is_version_greater_than_other_version(version1, version4))
        self.assertFalse(self.version_rebuild.is_version_greater_than_other_version(version3, version2))
        self.assertFalse(self.version_rebuild.is_version_greater_than_other_version(version4, version2))
        self.assertFalse(self.version_rebuild.is_version_greater_than_other_version(version4, version3))

    def test_sort_versions(self):
        version0 = VersionDefinition(version="3.7.16")
        version1 = VersionDefinition(version="3.8.16")
        version2 = VersionDefinition(version="3.9.14")
        version3 = VersionDefinition(version="4.0.13")
        version4 = VersionDefinition(version="4.1.13")
        version5 = VersionDefinition(version="4.2.10")
        version6 = VersionDefinition(version="4.5.2")
        version7 = VersionDefinition(version="4.5.3")

        versions_list = VersionList(key="", producer="", versions=[version4, version1, version6, version0, version2,
                                                                   version7, version5, version3])
        sorted_versions = self.version_rebuild.sort_versions(versions_list)

        self.assertEqual(sorted_versions[0], version0)
        self.assertEqual(sorted_versions[1], version1)
        self.assertEqual(sorted_versions[2], version2)
        self.assertEqual(sorted_versions[3], version3)
        self.assertEqual(sorted_versions[4], version4)
        self.assertEqual(sorted_versions[5], version5)
        self.assertEqual(sorted_versions[6], version6)
        self.assertEqual(sorted_versions[7], version7)

    def test_compare_signatures(self):
        readme_signature = Signature(path="readme.html", hash=1234)
        button_signature = Signature(path="button.js", hash=2345)
        style_signature = Signature(path="style.css", hash=3456)
        other_readme_signature = Signature(path="readme.html", hash=4567)
        common_file = Signature(path="login.js", hash=5678)

        signatures0 = [readme_signature, button_signature, common_file]
        signatures1 = [style_signature, other_readme_signature, common_file]

        diff = self.version_rebuild.compare_signatures(signatures0, signatures1)

        self.assertIn("readme.html", diff)
        self.assertIn("button.js", diff)
        self.assertIn("style.css", diff)
        self.assertNotIn("login.js", diff)

    def test_keep_most_common_file_in_all_diff_for_each_diff(self):
        diff0 = ["readme.html", "test.js", "style.css"]  # should keep readme
        diff1 = ["readme.html", "myfile.html", "login.html"]  # should keep readme
        diff2 = ["button.js", "file.js", "homepage.css"]  # should keep file.js
        diff3 = ["readme.html", "login.js"]  # should keep readme.html
        diff4 = ["somefile.html", "image.png"]  # should keep image.png
        diff5 = ["file.js", "image.png"]  # choose arbitrary what it keeps
        diff_list = [diff0, diff1, diff2, diff3, diff4, diff5]

        self.version_rebuild.keep_most_common_file_in_all_diff_for_each_diff(diff_list)

        self.assertEqual(diff0, ["readme.html"])
        self.assertEqual(diff1, ["readme.html"])
        self.assertEqual(diff2, ["file.js"])
        self.assertEqual(diff3, ["readme.html"])
        self.assertEqual(diff4, ["image.png"])

    def test_keep_most_common_file_in_all_diff_for_each_diff_keep_specified_amount_of_files_per_diff(self):
        diff0 = ["readme.html", "test.js", "style.css"]  # should keep readme and style.css
        diff1 = ["readme.html", "myfile.html", "login.js"]  # should keep readme and login
        diff2 = ["button.js", "file.js", "style.css"]  # should keep file.js and style.css
        diff3 = ["readme.html", "login.js", "index.html"]  # should keep readme.html and login
        diff4 = ["somefile.html", "image.png"]  # should keep image.png and somefile.html
        diff5 = ["file.js", "image.png"]  # all files are kept
        diff_list = [diff0, diff1, diff2, diff3, diff4, diff5]

        self.version_rebuild.keep_most_common_file_in_all_diff_for_each_diff(diff_list, 2)

        self.assertIn("readme.html", diff0)
        self.assertIn("style.css", diff0)
        self.assertEqual(len(diff0), 2)
        self.assertIn("readme.html", diff1)
        self.assertIn("login.js", diff1)
        self.assertEqual(len(diff1), 2)
        self.assertIn("file.js", diff2)
        self.assertIn("style.css", diff2)
        self.assertEqual(len(diff2), 2)
        self.assertIn("readme.html", diff3)
        self.assertIn("login.js", diff3)
        self.assertEqual(len(diff3), 2)
        self.assertIn("somefile.html", diff4)
        self.assertIn("image.png", diff4)
        self.assertEqual(len(diff4), 2)
        self.assertIn("file.js", diff5)
        self.assertIn("image.png", diff5)
        self.assertEqual(len(diff5), 2)
