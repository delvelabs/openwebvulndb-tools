from unittest import TestCase
from unittest.mock import MagicMock
from openwebvulndb.wordpress.vane2 import Vane2VersionRebuild
from openwebvulndb.common.models import Signature, VersionDefinition, VersionList
from fixtures import file_path


class Vane2VersionRebuildTest(TestCase):

    def setUp(self):
        self.version_rebuild = Vane2VersionRebuild(MagicMock())
        self.files_for_versions_identification = {"readme.html", "wp-admin/js/common.js"}
        self.readme_signature = Signature(path="readme.html", hash="12345")
        self.common_js_signature = Signature(path="wp-admin/js/common.js", hash="23456")
        self.other_file_signature = Signature(path="other_file.js", hash="34567")

    def test_update_only_keep_specified_files_signatures_from_versions_list(self):
        signatures = [self.readme_signature, self.common_js_signature, self.other_file_signature]
        version1 = VersionDefinition(version="1.0", signatures=signatures)
        version2 = VersionDefinition(version="2.0", signatures=signatures)
        versions_list = VersionList(key="wordpress", producer="", versions=[version1, version2])
        self.version_rebuild.storage.read_versions.return_value = versions_list
        self.version_rebuild.get_files_for_versions_identification = MagicMock()
        self.version_rebuild.get_files_for_versions_identification.return_value = (self.files_for_versions_identification, set())
        self.version_rebuild.check_for_equal_version_signatures = MagicMock()  # Would raise exception otherwise.

        self.version_rebuild.update(signatures)

        files = [file.path for file in self.version_rebuild.files_list.files]
        self.assertIn("readme.html", files)
        self.assertIn("wp-admin/js/common.js", files)
        self.assertNotIn("other_file.js", files)

    def test_compare_signatures_return_files_with_different_hash(self):
        button_file1 = Signature(path="button.js", hash=2345)
        readme_file1 = Signature(path="readme.html", hash=3456)
        button_file2 = Signature(path="button.js", hash=4567)
        readme_file2 = Signature(path="readme.html", hash=6789)

        signatures0 = [self.common_js_signature, readme_file1, button_file1]
        signatures1 = [self.common_js_signature, readme_file2, button_file2]

        files = self.version_rebuild._compare_signatures(signatures0, signatures1)

        self.assertIn("button.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)

    def test_compare_signatures_return_files_not_in_other_version(self):
        signatures0 = [self.readme_signature, self.common_js_signature]
        signatures1 = [self.readme_signature, self.other_file_signature, self.common_js_signature]

        files = self.version_rebuild._compare_signatures(signatures0, signatures1)

        self.assertIn("other_file.js", files)

    def test_compare_signatures_ignore_exclude_files(self):
        signatures0 = [self.readme_signature, self.common_js_signature]
        signatures1 = [self.common_js_signature]

        files = self.version_rebuild._compare_signatures(signatures0, signatures1, exclude_file="readme.html")

        self.assertNotIn("readme.html", files)

    def test_compare_signatures_ignore_exclude_files_ignore_plugin_and_themes_files_by_default(self):
        file0 = Signature(path="wp-content/plugins/my-plugin/style.css", hash=1234)
        file1 = Signature(path="wp-content/themes/my-theme/file2.js", hash=4567)

        signatures0 = [file0, self.readme_signature]
        signatures1 = [file1, self.readme_signature]

        files = self.version_rebuild._compare_signatures(signatures0, signatures1)

        self.assertEqual(len(files), 0)

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

        files, versions_without_diff = self.version_rebuild.get_files_for_versions_identification(version_list)

        self.assertIn("button.js", files)
        self.assertIn("readme.html", files)
        self.assertNotIn("style.css", files)
        self.assertNotIn("style2.css", files)
        self.assertNotIn("button.css", files)

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
        sorted_versions = self.version_rebuild._sort_versions(versions_list)

        self.assertEqual(sorted_versions[0], version0)
        self.assertEqual(sorted_versions[1], version1)
        self.assertEqual(sorted_versions[2], version2)
        self.assertEqual(sorted_versions[3], version3)
        self.assertEqual(sorted_versions[4], version4)
        self.assertEqual(sorted_versions[5], version5)
        self.assertEqual(sorted_versions[6], version6)
        self.assertEqual(sorted_versions[7], version7)

    def test_keep_most_common_file_in_all_diff_for_each_diff(self):
        diff0 = {"readme.html", "test.js", "style.css"}  # should keep readme
        diff1 = {"readme.html", "myfile.html", "login.html"}  # should keep readme
        diff2 = {"button.js", "file.js", "homepage.css"}  # should keep file.js
        diff3 = {"readme.html", "login.js"}  # should keep readme.html
        diff4 = {"somefile.html", "image.png"}  # should keep image.png
        diff5 = {"file.js", "image.png"}  # choose arbitrary what it keeps
        diff_list = [diff0, diff1, diff2, diff3, diff4, diff5]

        self.version_rebuild._keep_most_common_file_in_all_diff_for_each_diff(diff_list)

        self.assertEqual(diff0, {"readme.html"})
        self.assertEqual(diff1, {"readme.html"})
        self.assertEqual(diff2, {"file.js"})
        self.assertEqual(diff3, {"readme.html"})
        self.assertEqual(diff4, {"image.png"})

    def test_keep_most_common_file_in_all_diff_for_each_diff_keep_specified_amount_of_files_per_diff(self):
        diff0 = {"readme.html", "test.js", "style.css"}  # should keep readme and style.css
        diff1 = {"readme.html", "myfile.html", "login.js"}  # should keep readme and login
        diff2 = {"button.js", "file.js", "style.css"}  # should keep file.js and style.css
        diff3 = {"readme.html", "login.js", "index.html"}  # should keep readme.html and login
        diff4 = {"somefile.html", "image.png"}  # should keep image.png and somefile.html
        diff5 = {"file.js", "image.png"}  # all files are kept
        diff_list = [diff0, diff1, diff2, diff3, diff4, diff5]

        self.version_rebuild._keep_most_common_file_in_all_diff_for_each_diff(diff_list, 2)

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

    def test_update_convert_versions_list_to_files_list(self):
        readme_signature_1 = Signature(path="readme.html", algo="SHA256", hash="12345")
        readme_signature_2 = Signature(path="readme.html", algo="SHA256", hash="98765")
        signatures1 = [readme_signature_1, self.other_file_signature]
        signatures2 = [readme_signature_2, self.common_js_signature]
        version1 = VersionDefinition(version="1.0", signatures=signatures1)
        version2 = VersionDefinition(version="2.0", signatures=signatures2)
        versions_list = VersionList(key="wordpress", producer="unittest", versions=[version1, version2])
        self.version_rebuild.storage.read_versions.return_value = versions_list
        self.version_rebuild.get_files_for_versions_identification = MagicMock()
        self.version_rebuild.get_files_for_versions_identification.return_value = (self.files_for_versions_identification, set())

        self.version_rebuild.update("wordpress")

        readme_file = [file for file in self.version_rebuild.files_list.files if file.path == "readme.html"][0]
        common_file = [file for file in self.version_rebuild.files_list.files if file.path == "wp-admin/js/common.js"][0]
        # list should be empty because other_file.js is not in files_for_versions_identification.
        other_file = [file for file in self.version_rebuild.files_list.files if file.path == "other_file.js"]
        self.assertEqual(len(other_file), 0)
        self.assertEqual(len(readme_file.signatures), 2)
        self.assertEqual(len(common_file.signatures), 1)
        self.assertEqual(common_file.signatures[0].hash, self.common_js_signature.hash)
        self.assertEqual(common_file.signatures[0].algo, self.common_js_signature.algo)
        self.assertEqual(common_file.signatures[0].versions, ["2.0"])
        signatures = sorted(readme_file.signatures, key=lambda signature: signature.hash)
        self.assertEqual(signatures[0].hash, "12345")
        self.assertEqual(signatures[0].algo, "SHA256")
        self.assertEqual(signatures[0].versions, ["1.0"])
        self.assertEqual(signatures[1].hash, "98765")
        self.assertEqual(signatures[1].algo, "SHA256")
        self.assertEqual(signatures[1].versions, ["2.0"])
