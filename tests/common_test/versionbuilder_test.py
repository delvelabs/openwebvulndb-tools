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
from unittest.mock import MagicMock
from openwebvulndb.common.versionbuilder import VersionBuilder, VersionImporter
from openwebvulndb.common.models import Signature, VersionDefinition, VersionList, FileSignature, File, FileList


class TestVersionBuilder(TestCase):

    def setUp(self):
        def exclude_useless_files_for_identification(file_paths, version_list):
            return file_paths
        self.version_builder = VersionBuilder()
        self.version_builder.exclude_useless_files_for_identification = exclude_useless_files_for_identification

    def test_create_file_list_from_version_list_return_all_hash_regroup_by_files(self):
        signature0 = Signature(path="file", hash="12345")
        signature1 = Signature(path="readme", hash="54321")
        signature2 = Signature(path="readme", hash="56789")
        version0 = VersionDefinition(version="1.0", signatures=[signature0, signature1])
        version1 = VersionDefinition(version="1.1", signatures=[signature0, signature1])
        version2 = VersionDefinition(version="1.2", signatures=[signature0, signature2])
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        file_list = self.version_builder.create_file_list_from_version_list(version_list)

        file = [file for file in file_list.files if file.path == "file"][0]
        self.assertEqual(file.path, "file")
        self.assertEqual(len(file.signatures), 1)
        self.assertEqual(file.signatures[0].hash, "12345")
        self.assertEqual(len(file.signatures[0].versions), 3)

        readme = [file for file in file_list.files if file.path == "readme"][0]
        self.assertEqual(readme.path, "readme")
        self.assertEqual(len(readme.signatures), 2)
        self.assertEqual(readme.signatures[0].hash, "54321")
        self.assertEqual(len(readme.signatures[0].versions), 2)
        self.assertIn("1.0", readme.signatures[0].versions)
        self.assertIn("1.1", readme.signatures[0].versions)
        self.assertEqual(readme.signatures[1].hash, "56789")
        self.assertEqual(readme.signatures[1].versions, ["1.2"])

    def test_create_file_list_from_version_list_return_none_if_no_signature_in_version_definitions(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        file_list = self.version_builder.create_file_list_from_version_list(version_list)

        self.assertIsNone(file_list)

    def test_create_file_list_from_version_list_recreate_version_list(self):
        self.version_builder._shrink_version_list = MagicMock()
        self.version_builder.is_version_list_empty = MagicMock(return_value=False)
        version_list = VersionList(key="key", producer="producer")

        self.version_builder.create_file_list_from_version_list(version_list, files_to_keep_per_version=50)

        self.version_builder._shrink_version_list.assert_called_once_with(version_list, 50)

    def test_create_file_from_version_list_regroup_all_versions_with_identical_hash_for_file_in_same_file_signature_model(self):
        signature0 = Signature(path="file", hash="12345")
        signature1 = Signature(path="readme", hash="54321")
        version0 = VersionDefinition(version="1.0", signatures=[signature0, signature1])
        version1 = VersionDefinition(version="1.1", signatures=[signature0, signature1])
        version2 = VersionDefinition(version="1.2", signatures=[signature0, signature1])
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        file0 = self.version_builder._create_file_from_version_list("file", version_list)
        file1 = self.version_builder._create_file_from_version_list("readme", version_list)

        file_signature0 = file0.signatures[0]
        file_signature1 = file1.signatures[0]
        self.assertEqual(len(file0.signatures), 1)
        self.assertEqual(len(file1.signatures), 1)
        self.assertEqual(file_signature0.hash, signature0.hash)
        self.assertEqual(file_signature1.hash, signature1.hash)
        versions = [version.version for version in version_list.versions]
        self.assertTrue(all(version in versions for version in file_signature0.versions))
        self.assertTrue(all(version in versions for version in file_signature1.versions))

    def test_get_signature_return_signature_with_specified_file_path_in_version_definition(self):
        signature0 = Signature(path="file0", hash="1")
        signature1 = Signature(path="file1", hash="2")
        signature2 = Signature(path="file2", hash="3")
        version = VersionDefinition(version="1.0", signatures=[signature0, signature1, signature2])

        sign0 = self.version_builder.get_signature("file0", version)
        sign1 = self.version_builder.get_signature("file1", version)
        sign2 = self.version_builder.get_signature("file2", version)

        self.assertEqual(sign0, signature0)
        self.assertEqual(sign1, signature1)
        self.assertEqual(sign2, signature2)

    def test_get_file_paths_from_version_list(self):
        signature0 = Signature(path="file0", hash="1")
        signature1 = Signature(path="file1", hash="2")
        signature2 = Signature(path="file2", hash="3")
        signature3 = Signature(path="file3", hash="4")
        signature4 = Signature(path="file0", hash="5")
        version0 = VersionDefinition(version="1.0", signatures=[signature0, signature1, signature2])
        version1 = VersionDefinition(version="1.1", signatures=[signature0, signature1, signature3])
        version2 = VersionDefinition(version="1.2", signatures=[signature4, signature2])
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        self.assertEqual(len(file_paths), 4)
        self.assertIn("file0", file_paths)
        self.assertIn("file1", file_paths)
        self.assertIn("file2", file_paths)
        self.assertIn("file3", file_paths)

    def test_exclude_files_removes_files_beginning_with_trunk_in_version_list(self):
        signature0 = Signature(path="wp-content/plugins/my-plugin/trunk/file0", hash="1")
        signature1 = Signature(path="wp-content/plugins/my-plugin/file1", hash="2")
        signature2 = Signature(path="wp-content/plugins/my-plugin/file2", hash="3")
        signature3 = Signature(path="wp-content/plugins/my-plugin/trunk/file3", hash="4")
        version = VersionDefinition(version="1.2", signatures=[signature0, signature1, signature2, signature3])
        version_list = VersionList(producer="producer", key="plugins/my-plugin", versions=[version])

        self.version_builder.exclude_files(version_list)

        self.assertEqual(len(version.signatures), 2)
        self.assertIn(signature1, version.signatures)
        self.assertIn(signature2, version.signatures)

    def test_exclude_files_removes_files_beginning_with_tags(self):
        signature0 = Signature(path="wp-content/plugins/my-plugin/tags/1.0/file0", hash="1")
        signature1 = Signature(path="wp-content/plugins/my-plugin/file1", hash="2")
        signature2 = Signature(path="wp-content/plugins/my-plugin/file2", hash="3")
        signature3 = Signature(path="wp-content/plugins/my-plugin/tags/1.0/file3", hash="4")
        version = VersionDefinition(version="1.2", signatures=[signature0, signature1, signature2, signature3])
        version_list = VersionList(producer="producer", key="plugins/my-plugin", versions=[version])

        self.version_builder.exclude_files(version_list)

        self.assertEqual(len(version.signatures), 2)
        self.assertIn(signature1, version.signatures)
        self.assertIn(signature2, version.signatures)

    def test_exclude_files_removes_files_beginning_with_branches(self):
        signature0 = Signature(path="wp-content/plugins/my-plugin/branches/file0", hash="1")
        signature1 = Signature(path="wp-content/plugins/my-plugin/file1", hash="2")
        signature2 = Signature(path="wp-content/plugins/my-plugin/file2", hash="3")
        signature3 = Signature(path="wp-content/plugins/my-plugin/branches/file3", hash="4")
        version = VersionDefinition(version="1.2", signatures=[signature0, signature1, signature2, signature3])
        version_list = VersionList(producer="producer", key="plugins/my-plugin", versions=[version])

        self.version_builder.exclude_files(version_list)

        self.assertEqual(len(version.signatures), 2)
        self.assertIn(signature1, version.signatures)
        self.assertIn(signature2, version.signatures)

    def test_shrink_version_list_do_nothing_if_total_amount_of_files_is_lower_than_max(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        for i in range(0, 5):
            version0.add_signature(path="file%d" % i, hash=str(i))
            version1.add_signature(path="file%d" % i, hash="A%d" % i)
            version2.add_signature(path="file%d" % i, hash="B%d" % i)
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        self.version_builder._shrink_version_list(version_list, files_per_version=10)

        self.assertEqual(version_list.versions[0], version0)
        self.assertEqual(version_list.versions[1], version1)
        self.assertEqual(version_list.versions[2], version2)

    def test_shrink_version_list_choose_files_arbitrarily_if_only_one_version_and_more_files_than_max(self):
        version = VersionDefinition(version="1.0")
        for i in range(0, 15):
            version.add_signature(path="file%d" % i, hash=str(i))
        version_list = VersionList(producer="producer", key="key", versions=[version])

        self.version_builder._shrink_version_list(version_list, files_per_version=10)

        self.assertEqual(len(version_list.versions[0].signatures), 10)

    def test_shrink_version_list_add_files_from_most_common_files_to_version_files_if_less_changing_files_than_max(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        for i in range(0, 15):
            version0.add_signature(path="file%d" % i, hash=str(i))
            version1.add_signature(path="file%d" % i, hash=str(i))
        for i in range(0, 4):
            version2.add_signature(path="file%d" % (i + 15), hash=str(i))
            version2.add_signature(path="file%d" % i, hash="hash")
        for i in range(4, 8):
            version2.add_signature(path="file%d" % i, hash=str(i))
        version1.add_signature(path="fileA", hash="unique_hash")

        # file0-7 are the most common files
        # file0-3 and file15-18 are diff for 1.2 (8 diff)
        # fileA is the diff for 1.1
        # file0-7, file15-18 and fileA are always kept, plus 2 files randomly choose from file6-14 (equally common in diff): 15 files total

        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        self.version_builder._shrink_version_list(version_list, files_per_version=10)

        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        self.assertEqual(len(file_paths), 15)
        self.assertEqual(len(version0.signatures), 10)
        self.assertEqual(len(version1.signatures), 11)
        self.assertEqual(len(version2.signatures), 12)
        self.assertIn("fileA", file_paths)
        for i in range(0, 8):
            self.assertIn("file%d" % i, file_paths)
        for i in range(15, 19):
            self.assertIn("file%d" % i, file_paths)
        self.assertEqual(len(file_paths & set("file%d" % i for i in range(8, 15))), 2)  # check that 2 files are arbitrarily kept from these files.

    def test_shrink_version_list_keep_max_files_from_most_common_files_if_no_changes_between_version(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        for i in range(0, 10):  # All versions are equal
            same_signature = Signature(path="file%d" % i, hash=str(i))
            version0.signatures.append(same_signature)
            version1.signatures.append(same_signature)
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1])

        self.version_builder._shrink_version_list(version_list, 10)

        self.assertEqual(len(version0.signatures), 10)
        for i in range(0, 10):
            self.assertIn("file%d" % i, [signature.path for signature in version0.signatures])

    def test_set_version_files_add_all_files_already_in_other_differences(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        identity_files = set()
        for i in range(0, 5):  # Files common to all the version
            version0.add_signature(path="file%d" % i, hash=str(i))
            version1.add_signature(path="file%d" % i, hash=str(i))
            version2.add_signature(path="file%d" % i, hash=str(i))
        for i in range(5, 10):  # Files changing in all versions
            version0.add_signature(path="file%d" % i, hash='A')
            version1.add_signature(path="file%d" % i, hash='B')
            version2.add_signature(path="file%d" % i, hash='C')
            identity_files.add("file%d" % i)
        for i in range(10, 15):  # Files changing in version 1.1
            version1.add_signature(path="file%d" % i, hash='B')
            version2.add_signature(path="file%d" % i, hash='B')
            identity_files.add("file%d" % i)
        for i in range(15, 17):  # Files only in version 1.2
            version2.add_signature(path="file%d" % i, hash="hash")
            identity_files.add("file%d" % i)
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        version0_files = self.version_builder._get_identity_files_for_version(version0, version_list, identity_files, files_per_version=10)
        identity_files |= version0_files
        version1_files = self.version_builder._get_identity_files_for_version(version1, version_list, identity_files, files_per_version=10)
        identity_files |= version1_files
        version2_files = self.version_builder._get_identity_files_for_version(version2, version_list, identity_files, files_per_version=10)

        self.assertEqual(10, len(version0.signatures))  # Only 10 files for version 1.0, so they are all kept
        self.assertEqual(15, len(version1.signatures))  # 10 files are changing in 1.1 + 5 files already kept by 1.0 but no changing in 1.1
        self.assertEqual(17, len(version2.signatures))  # 7 files changing in 1.2 + 5 from 1.1 + 5 from 1.0
        for i in range(0, 10):
            self.assertIn("file%d" % i, version0_files)
        for i in range(0, 15):
            self.assertIn("file%d" % i, version1_files)
        for i in range(0, 17):
            self.assertIn("file%d" % i, version2_files)

    def test_get_diff_between_versions_set_all_files_as_diff_for_first_version(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        for i in range(0, 5):
            version0.add_signature(path="file%d" % i, hash=str(i))
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1])

        diff_list = self.version_builder._get_diff_between_versions(version_list, 14)

        self.assertEqual(len(diff_list["1.0"]), 5)

    def test_get_diff_between_versions_return_all_files_that_differ_or_are_added_between_versions(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        for i in range(0, 5):  # All versions are equal
            same_signature = Signature(path="file%d" % i, hash=str(i))
            version0.signatures.append(same_signature)
            version1.signatures.append(same_signature)
            version2.signatures.append(same_signature)
        for i in range(5, 10):  # 5 diff between each version
            version0.add_signature(path="file%d" % i, hash=str(i))
            version1.add_signature(path="file%d" % i, hash="A%d" % i)
            version2.add_signature(path="file%d" % i, hash="B%d" % i)
        for i in range(10, 15):  # 10 diff between 1.0 and 1.1
            version0.add_signature(path="file%d" % i, hash=str(i))
            version1.add_signature(path="file%d" % i, hash="A%d" % i)
            version2.add_signature(path="file%d" % i, hash="A%d" % i)
        for i in range(15, 20):  # 10 diff between 1.1 and 1.2
            version0.add_signature(path="file%d" % i, hash=str(i))
            version1.add_signature(path="file%d" % i, hash=str(i))
            version2.add_signature(path="file%d" % i, hash="A%d" % i)
        for i in range(20, 25):  # 15 diff between 1.1 and 1.2
            version2.add_signature(path="file%d" % i, hash=str(i))

        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        diff_list = self.version_builder._get_diff_between_versions(version_list, 10)

        self.assertEqual(len(diff_list["1.1"]), 10)
        self.assertEqual(len(diff_list["1.2"]), 10)

    def test_keep_most_common_file_in_all_diff_for_each_diff(self):
        diff_1_0 = {"file0", "file1", "file2", "file3", "file4"}
        diff_1_1 = {"file2", "file3"}
        diff_1_2 = {"file3", "file5"}
        differences_between_versions = {"1.0": diff_1_0, "1.1": diff_1_1, "1.2": diff_1_2}

        self.version_builder._keep_most_common_file_in_all_diff_for_each_diff(differences_between_versions, None, 2)

        self.assertEqual(differences_between_versions["1.0"], {"file3", "file2"})
        self.assertEqual(differences_between_versions["1.1"], {"file3", "file2"})
        self.assertEqual(len(differences_between_versions["1.2"]), 2)

    def test_keep_most_common_file_in_all_diff_for_each_diff_use_most_common_files_if_too_many_diff_with_same_count(self):
        diff_1_0 = {"file0", "file1", "file3", "file4"}  # file3-4 will be kept
        diff_1_1 = {"file2", "file5", "file6"}  # file5-6 will be kept
        diff_1_2 = {"file7", "file8", "file9"}  # file 7-8 will be kept
        diff_1_3 = {"file7", "file8"}
        differences_between_versions = {"1.0": diff_1_0, "1.1": diff_1_1, "1.2": diff_1_2, "1.3": diff_1_3}
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        version3 = VersionDefinition(version="1.3")
        for i in range(0, 5):
            version0.add_signature(path="file%d" % i, hash=i)
        for i in range(2, 7):
            version1.add_signature(path="file%d" % i, hash=i)
        for i in range(4, 10):
            version2.add_signature(path="file%d" % i, hash=i)
            version3.add_signature(path="file%d" % i, hash=i)
        # file count:
        # file0, file1: 1
        # file2, file3, file7, file8, file9: 2
        # file5, file6: 3
        # file4: 4
        version_list = VersionList(key="key", producer="producer", versions=[version0, version1, version2, version3])
        self.version_builder._keep_most_common_file_in_all_diff_for_each_diff(differences_between_versions, version_list, 2)

        self.assertEqual(differences_between_versions["1.0"], {"file3", "file4"})
        self.assertEqual(differences_between_versions["1.1"], {"file5", "file6"})
        self.assertEqual(differences_between_versions["1.2"], {"file7", "file8"})
        self.assertEqual(differences_between_versions["1.3"], {"file7", "file8"})

    def test_get_most_common_files(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        # most common files
        signature0 = Signature(path="file0", hash="1")
        signature1 = Signature(path="file1", hash="2")
        version0.signatures.append(signature0)
        version1.signatures.append(signature0)
        version2.signatures.append(signature0)
        version0.signatures.append(signature1)
        version1.signatures.append(signature1)
        version2.signatures.append(signature1)
        # Only in 1.1 and 1.2
        version1.add_signature(path="file2", hash="3")
        version2.add_signature(path="file2", hash="4")
        # only in 1.0
        version0.add_signature(path="file3", hash="5")
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        three_most_common_files = self.version_builder._get_most_common_files(version_list, 3)
        two_most_common_files = self.version_builder._get_most_common_files(version_list, 2)

        self.assertIn("file0", three_most_common_files)
        self.assertIn("file1", three_most_common_files)
        self.assertIn("file2", three_most_common_files)
        self.assertNotIn("file3", three_most_common_files)
        self.assertIn("file0", two_most_common_files)
        self.assertIn("file1", two_most_common_files)
        self.assertNotIn("file2", two_most_common_files)
        self.assertNotIn("file3", two_most_common_files)

    def test_get_most_common_files_present_in_version_return_files_in_given_version_and_common_to_most_versions(self):
        version = VersionDefinition(version="1.0")
        version.add_signature(path="file0", hash="1")
        version.add_signature(path="file1", hash="2")
        version.add_signature(path="file2", hash="3")
        self.version_builder._get_most_common_files = MagicMock(return_value=["file0", "file1", "file3", "file4",
                                                                              "file2"])

        files = self.version_builder._get_most_common_files_present_in_version("version_list", version, 2)

        self.assertIn("file0", files)
        self.assertIn("file1", files)
        self.assertNotIn("file2", files)  # won't be returned because only two files are required and it's the least common file.
        self.assertNotIn("file3", files)
        self.assertNotIn("file4", files)

    def test_compare_signature_dont_return_files_that_are_removed_in_current_version(self):
        file0 = Signature(path="file0", hash="0")
        file1 = Signature(path="file1", hash="1")
        previous_version = VersionDefinition(version="1.0", signatures=[file0, file1])
        current_version = VersionDefinition(version="1.1", signatures=[file1])

        diff = self.version_builder._compare_versions_signatures(previous_version, current_version)

        self.assertEqual(len(diff), 0)


class TestVersionImporter(TestCase):

    def setUp(self):
        self.importer = VersionImporter()

    def test_import_version_list(self):
        file_list = FileList(key="key", producer="producer")
        for i in range(10):
            file = File(path="file%d" % i)
            for j in range(5):
                file.signatures.append(FileSignature(hash=j+i, versions=["1.%d" % j]))
            file_list.files.append(file)

        version_list = self.importer.import_version_list(file_list)

        self.assertEqual(version_list.key, file_list.key)
        self.assertEqual(version_list.producer, file_list.producer)
        self.assertEqual(len(version_list.versions), 5)
        for version in version_list.versions:
            self.assertEqual(len(version.signatures), 10)
            for i in range(10):
                self.assertIn("file%d" % i, [signature.path for signature in version.signatures])
                signature = version.signatures[i]
                self.assertEqual(signature.hash, int(version.version[-1]) + int(signature.path[-1]))
