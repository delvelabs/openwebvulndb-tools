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
from openwebvulndb.common.versionbuilder import VersionBuilder
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

    def test_create_file_from_version_list_file_create_file_with_all_file_signatures_for_file_path(self):
        version_list = VersionList(producer="producer", key="key", versions=[])
        self.version_builder.get_file_signatures = MagicMock(return_value=["signatures"])

        file = self.version_builder.create_file_from_version_list("file", version_list)

        self.assertEqual(file.path, "file")
        self.version_builder.get_file_signatures.assert_called_once_with("file", version_list)
        self.assertEqual(file.signatures, ["signatures"])

    def test_get_file_signatures_regroup_all_versions_with_identical_hash_for_file_in_same_file_signature_model(self):
        signature0 = Signature(path="file", hash="12345")
        signature1 = Signature(path="readme", hash="54321")
        version0 = VersionDefinition(version="1.0", signatures=[signature0, signature1])
        version1 = VersionDefinition(version="1.1", signatures=[signature0, signature1])
        version2 = VersionDefinition(version="1.2", signatures=[signature0, signature1])
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        file_signatures0 = self.version_builder.get_file_signatures("file", version_list)
        file_signatures1 = self.version_builder.get_file_signatures("readme", version_list)

        file_signature0 = file_signatures0[0]
        file_signature1 = file_signatures1[0]
        self.assertEqual(len(file_signatures0), 1)
        self.assertEqual(len(file_signatures1), 1)
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

    def test_get_file_paths_from_version_list_exclude_files_beginning_with_trunk(self):
        signature0 = Signature(path="wp-content/plugins/my-plugin/trunk/file0", hash="1")
        signature1 = Signature(path="wp-content/plugins/my-plugin/file1", hash="2")
        signature2 = Signature(path="wp-content/plugins/my-plugin/file2", hash="3")
        signature3 = Signature(path="wp-content/plugins/my-plugin/trunk/file3", hash="4")
        version = VersionDefinition(version="1.2", signatures=[signature0, signature1, signature2, signature3])
        version_list = VersionList(producer="producer", key="plugins/my-plugin", versions=[version])

        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        self.assertEqual(len(file_paths), 2)
        self.assertIn(signature1.path, file_paths)
        self.assertIn(signature2.path, file_paths)

    def test_get_file_paths_from_version_list_exclude_files_beginning_with_tags(self):
        signature0 = Signature(path="wp-content/plugins/my-plugin/tags/1.0/file0", hash="1")
        signature1 = Signature(path="wp-content/plugins/my-plugin/file1", hash="2")
        signature2 = Signature(path="wp-content/plugins/my-plugin/file2", hash="3")
        signature3 = Signature(path="wp-content/plugins/my-plugin/tags/1.0/file3", hash="4")
        version = VersionDefinition(version="1.2", signatures=[signature0, signature1, signature2, signature3])
        version_list = VersionList(producer="producer", key="plugins/my-plugin", versions=[version])

        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        self.assertEqual(len(file_paths), 2)
        self.assertIn(signature1.path, file_paths)
        self.assertIn(signature2.path, file_paths)

    def test_limit_files_amount_keep_all_files_if_total_lower_than_limit(self):
        max_files = 100
        version = VersionDefinition(version="1.2")
        for i in range(0, 99):
            version.signatures.append(Signature(path="file%d" % i, hash=str(i)))
        version_list = VersionList(producer="producer", key="key", versions=[version])
        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        filtered_file_paths = self.version_builder.limit_files_amount(file_paths, version_list, max_files)

        self.assertEqual(file_paths, filtered_file_paths)

    def test_limit_files_amount_remove_exceeding_files_arbitrarily_if_all_files_have_same_value_for_identification(self):
        max_files = 100
        version = VersionDefinition(version="1.2")
        for i in range(0, 200):
            version.signatures.append(Signature(path="file%d" % i, hash=str(i)))
        version_list = VersionList(producer="producer", key="key", versions=[version])
        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        filtered_file_paths = self.version_builder.limit_files_amount(file_paths, version_list, max_files)

        self.assertEqual(len(filtered_file_paths), max_files)

    def test_limit_files_amount_keep_best_files_for_version_identification(self):
        max_files = 50
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        for i in range(0, 50):
            useless_signature = Signature(path="file%d" % i, hash=str(i))
            version0.signatures.append(useless_signature)
            version1.signatures.append(useless_signature)
            version2.signatures.append(useless_signature)

        for i in range(0, 50):
            version0.signatures.append(Signature(path="%dfile" % i, hash=str(i)))
            version1.signatures.append(Signature(path="%dfile" % i, hash="A%d" % i))
            version2.signatures.append(Signature(path="%dfile" % i, hash="B%d" % i))
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])
        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        filtered_file_paths = self.version_builder.limit_files_amount(file_paths, version_list, max_files)

        self.assertTrue(all(path.endswith("file") for path in filtered_file_paths))
        self.assertEqual(len(filtered_file_paths), max_files)

    def test_limit_files_amount_keep_at_most_max_files(self):
        max_files = 50
        version0 = VersionDefinition(version="1.0")  # 100 files, 50 will be kept
        version1 = VersionDefinition(version="1.1")  # 50 diff between 1.1 and 1.0, 25 will be kept
        version2 = VersionDefinition(version="1.2")  # 25 diff between 1.2 and 1.1, 25 will be kept
        for i in range(0, 100):
            version0.signatures.append(Signature(path="file%d" % i, hash=str(i)))

        version1.signatures.extend(version0.signatures)
        for i in range(0, 50):
            version1.signatures[i] = Signature(path="file%d" % i, hash="%dA" % i)
        version2.signatures.extend(version1.signatures)
        for i in range(75, 100):
            version2.signatures[i] = Signature(path="file%d" % i, hash="%dA" % i)
        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])
        file_paths = self.version_builder.get_file_paths_from_version_list(version_list)

        filtered_file_paths = self.version_builder.limit_files_amount(file_paths, version_list, max_files)

        self.assertEqual(len(filtered_file_paths), max_files)

    def test_get_diff_between_versions_return_all_files_that_differ_or_appear_between_versions(self):
        version0 = VersionDefinition(version="1.0")
        version1 = VersionDefinition(version="1.1")
        version2 = VersionDefinition(version="1.2")
        for i in range(0, 5):  # All versions are equal
            same_signature = Signature(path="file%d" % i, hash=str(i))
            version0.signatures.append(same_signature)
            version1.signatures.append(same_signature)
            version2.signatures.append(same_signature)
        for i in range(5, 10):  # 5 diff between each version
            version0.signatures.append(Signature(path="file%d" % i, hash=str(i)))
            version1.signatures.append(Signature(path="file%d" % i, hash="A%d" % i))
            version2.signatures.append(Signature(path="file%d" % i, hash="B%d" % i))
        for i in range(10, 15):  # 10 diff between 1.0 and 1.1
            version0.signatures.append(Signature(path="file%d" % i, hash=str(i)))
            version1.signatures.append(Signature(path="file%d" % i, hash="A%d" % i))
            version2.signatures.append(Signature(path="file%d" % i, hash="A%d" % i))
        for i in range(15, 20):  # 10 diff between 1.1 and 1.2
            version0.signatures.append(Signature(path="file%d" % i, hash=str(i)))
            version1.signatures.append(Signature(path="file%d" % i, hash=str(i)))
            version2.signatures.append(Signature(path="file%d" % i, hash="A%d" % i))
        for i in range(20, 25):  # 15 diff between 1.1 and 1.2
            version1.signatures.append(Signature(path="file%d" % i, hash=str(i)))
            version2.signatures.append(Signature(path="file%d" % i, hash="A%d" % i))

        version_list = VersionList(producer="producer", key="key", versions=[version0, version1, version2])

        diff_list = self.version_builder._get_diff_between_versions(version_list)

        self.assertEqual(len(diff_list["1.1"]), 10)
        self.assertEqual(len(diff_list["1.2"]), 10)
