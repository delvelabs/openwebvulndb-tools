from openwebvulndb.common.schemas import VersionListSchema
from openwebvulndb.common.models import VersionDefinition
import json
import re
from collections import Counter


class Vane2VersionRebuild:

    def __init__(self, storage):
        self.storage = storage
        self.version_list = []
        self._versions_signature_files = []
        self.major_version_pattern = "\d+\.\d+"

    def update(self, key):
        self.version_list = self.storage.read_versions(key)
        for version in self.version_list.versions:
            self._cleanup_signatures(version.signatures)

    def _cleanup_signatures(self, version_signatures):
        to_remove = []
        for signature in version_signatures:
            if signature.path not in self.get_files_to_use_for_signature():
                to_remove.append(signature)
        for signature in to_remove:
            version_signatures.remove(signature)

    def get_files_to_use_for_signature(self):
        return self._versions_signature_files

    def dump(self):
        schema = VersionListSchema(exclude=("versions.signatures.contains_version",))
        return json.dumps(schema.dump(self.version_list).data, indent=4)

    def load_files_for_versions_signatures(self, filename):
        with open(filename, "r") as fp:
            for line in fp.readlines():
                self._versions_signature_files.append(line.strip())

    def check_for_equal_version_signatures(self):
        equal_versions = []
        for index, version in enumerate(self.version_list.versions):
            if index + 1 < len(self.version_list.versions):
                other_version = self.version_list.versions[index + 1]
                if self._versions_equal(version, other_version):
                    if not self._is_same_major_version(version.version, other_version.version) or self._is_recent_version(version.version):
                        message = "Version {0} has the same signature as version {1}.".format(version.version, other_version.version)
                        equal_versions.append(message)
        if len(equal_versions) > 0:
            message = ""
            for _version in equal_versions:
                message += _version + "\n"
            raise Exception(message)

    def _versions_equal(self, version1, version2):
        return len(self.compare_signatures(version1.signatures, version2.signatures)) == 0

    def _find_file_signature_in_signatures(self, file_path, signatures):
        for signature in signatures:
            if signature.path == file_path:
                return signature

    def _is_plugin_or_theme_file(self, file_path):
        return re.match("wp-content/((plugins)|(themes))", file_path) is not None

    def compare_signatures(self, signatures0, signatures1, exclude_file=None):
        diff = []
        for signature in signatures0:
            if signature.path != exclude_file and not self._is_plugin_or_theme_file(signature.path):
                other_signature = self._find_file_signature_in_signatures(signature.path, signatures1)
                if other_signature is not None:
                    if signature.hash != other_signature.hash:
                        diff.append(signature.path)
                else:
                    diff.append(signature.path)
        # Check for files in other_version not present in version:
        for signature in signatures1:
            if signature.path != exclude_file and not self._is_plugin_or_theme_file(signature.path):
                if self._find_file_signature_in_signatures(signature.path, signatures0) is None:
                    diff.append(signature.path)
        return diff

    def _is_same_major_version(self, version0, version1):
        version0_major = re.match(self.major_version_pattern, version0)
        version1_major = re.match(self.major_version_pattern, version1)
        return version0_major.group() == version1_major.group()

    def _list_different_versions_from_pattern(self, versions_list, version_pattern):
        versions = []
        for version in versions_list.versions:
            version = re.match(version_pattern, version.version).group()
            if version not in versions:
                versions.append(version)
        return versions

    def create_version_definition_for_major_version(self, versions_list, major_version):
        signatures = []
        minor_versions = self.get_minor_versions_in_major_version(versions_list, major_version)
        if len(minor_versions) > 1:
            common_files = self.get_common_files_for_versions(minor_versions)
            for signature in minor_versions[0].signatures:
                if signature.path in common_files:
                    signatures.append(signature)
        else:
            signatures = minor_versions[0].signatures
        return VersionDefinition(version=major_version, signatures=signatures)

    def get_minor_versions_in_major_version(self, versions_list, major_version):
        minor_versions = []
        for version in versions_list.versions:
            if self._is_same_major_version(version.version, major_version):
                minor_versions.append(version)
        return minor_versions

    def get_diff_between_versions(self, versions, exclude_file=None, files_to_keep_per_diff=1):
        diff_list = []
        versions_without_diff = []
        for index, version in enumerate(versions):
            if index + 1 < len(versions):
                other_version = versions[index + 1]
                diff = self.compare_signatures(version.signatures, other_version.signatures, exclude_file)
                if len(diff) == 0:
                    versions_without_diff.append(
                        "version {0} and version {1} have the same signature.".format(version.version, other_version.version))
                else:
                    diff_list.append(diff)

        self.keep_most_common_file_in_all_diff_for_each_diff(diff_list, files_to_keep_per_diff)
        return set(file for diff in diff_list for file in diff), versions_without_diff

    def keep_most_common_file_in_all_diff_for_each_diff(self, diff_list, files_to_keep_per_diff=1):
        files_count_in_all_diff = Counter([file for diff in diff_list for file in diff])
        for diff in diff_list:
            new_diff = []
            for file_count in files_count_in_all_diff.most_common():
                file = file_count[0]
                if file in diff:
                    new_diff.append(file)
                    if len(new_diff) == files_to_keep_per_diff:
                        break  # Done for this diff, proceed with the next.
            diff.clear()
            diff.extend(new_diff)
            # Update the counter with the removed files, so the files kept by the previous diffs are taken into
            # account for the choices of the next diffs.
            files_count_in_all_diff = Counter([file for diff in diff_list for file in diff])

    def get_files_to_identify_major_versions(self, versions_list, exclude_file=None, files_to_keep_per_diff=1):
        major_versions = self._list_different_versions_from_pattern(versions_list, self.major_version_pattern)
        major_versions_definition = []
        for version in major_versions:
            version_definition = self.create_version_definition_for_major_version(versions_list, version)
            major_versions_definition.append(version_definition)
        return self.get_diff_between_versions(major_versions_definition, exclude_file, files_to_keep_per_diff)

    def get_files_to_identify_minor_versions(self, versions_list, major_versions, exclude_file=None, files_to_keep_per_diff=1):
        files = set()
        versions_without_diff = []
        for version in major_versions:
            minor_versions = self.get_minor_versions_in_major_version(versions_list, version)
            _files, _versions_without_diff = self.get_diff_between_versions(minor_versions, exclude_file, files_to_keep_per_diff)
            files |= _files
            versions_without_diff.extend(_versions_without_diff)
        return files, versions_without_diff

    def _is_recent_version(self, version):
        return re.match("[34]\.\d", version) is not None

    def _get_identical_files_between_versions(self, version1, version2):
        identical_files = []
        for signature in version1.signatures:
            file = signature.path
            other_file_signature = self._find_file_signature_in_signatures(file, version2.signatures)
            if other_file_signature is not None:
                if signature.hash == other_file_signature.hash:
                    identical_files.append(file)
        return identical_files

    def get_common_files_for_versions(self, versions):
        common_files = set()
        for index, version in enumerate(versions):
            if index + 1 < len(versions):
                identical_files = self._get_identical_files_between_versions(version, versions[index + 1])
                if len(identical_files) == 0:
                    print("no common files between {0} and {1}".format(version.version, versions[index + 1].version))
                else:
                    if len(common_files) > 0:
                        common_files &= set(identical_files)
                    else:
                        common_files = set(identical_files)
        return common_files

    def is_version_greater_than_other_version(self, version, other_version):
        _version = re.split("\.", version)
        _other_version = re.split("\.", other_version)
        for index, number in enumerate(_version):
            if len(_other_version) == index and int(number) != 0:
                return True
            if int(number) > int(_other_version[index]):
                return True
            elif int(number) < int(_other_version[index]):
                return False
        return False

    def sort_versions(self, versions_list):
        sorted_versions = []
        for version in versions_list.versions:
            if len(sorted_versions) > 0:
                for index, _version in enumerate(sorted_versions):
                    if not self.is_version_greater_than_other_version(version.version, _version.version):
                        sorted_versions.insert(index, version)
                        break
                else:
                    sorted_versions.append(version)
            else:
                sorted_versions.append(version)
        return sorted_versions

    def get_files_for_versions_identification_major_minor_algo(self, versions_list, files_to_keep_per_diff=1):
        files, versions_without_diff = self.get_files_to_identify_major_versions(versions_list, files_to_keep_per_diff=files_to_keep_per_diff)

        major_versions = self._list_different_versions_from_pattern(versions_list, self.major_version_pattern)
        _files, _versions_without_diff = self.get_files_to_identify_minor_versions(versions_list, major_versions, files_to_keep_per_diff=files_to_keep_per_diff)
        files |= _files
        versions_without_diff.extend(_versions_without_diff)
        return files, versions_without_diff

    def get_files_for_versions_identification_major_minor_algo_without_readme(self, versions_list, files_to_keep_per_diff=1):
        files, versions_without_diff = self.get_files_to_identify_major_versions(versions_list, exclude_file="readme.html", files_to_keep_per_diff=files_to_keep_per_diff)

        major_versions = self._list_different_versions_from_pattern(versions_list, self.major_version_pattern)
        _files, _versions_without_diff = self.get_files_to_identify_minor_versions(versions_list, major_versions, exclude_file="readme.html", files_to_keep_per_diff=files_to_keep_per_diff)
        files |= _files
        versions_without_diff.extend(_versions_without_diff)
        return files, versions_without_diff

    def get_files_for_versions_identification_chronological_diff_algo(self, versions_list, files_to_keep_per_diff=1):
        versions = self.sort_versions(versions_list)
        files, versions_without_diff = self.get_diff_between_versions(versions, files_to_keep_per_diff=files_to_keep_per_diff)
        return files, versions_without_diff

    def get_files_for_versions_identification_chronological_diff_algo_without_readme(self, versions_list, files_to_keep_per_diff=1):
        versions = self.sort_versions(versions_list)
        files, versions_without_diff = self.get_diff_between_versions(versions, exclude_file="readme.html", files_to_keep_per_diff=files_to_keep_per_diff)
        return files, versions_without_diff
