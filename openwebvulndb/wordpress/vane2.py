from openwebvulndb.common.schemas import VersionListSchema
import re
from collections import Counter


class Vane2VersionRebuild:

    def __init__(self, storage):
        self.storage = storage
        self.version_list = []
        self.major_version_pattern = "\d+\.\d+"

    def update(self, key, files_to_use_for_version_signatures):
        self.version_list = self.storage.read_versions(key)
        for version in self.version_list.versions:
            self._cleanup_signatures(version.signatures, files_to_use_for_version_signatures)

    def get_files_for_versions_identification(self, versions_list, exclude_file=None, files_to_keep_per_diff=1):
        versions = self._sort_versions(versions_list)
        files, versions_without_diff = self._get_diff_between_versions(versions, exclude_file=exclude_file,
                                                                       files_to_keep_per_diff=files_to_keep_per_diff)
        return files

    def dump(self):
        schema = VersionListSchema(exclude=("versions.signatures.contains_version",))
        return schema.dump(self.version_list).data

    def check_for_equal_version_signatures(self):
        equal_versions = []
        for index, version in enumerate(self.version_list.versions):
            if index + 1 < len(self.version_list.versions):
                other_version = self.version_list.versions[index + 1]
                if self._versions_equal(version, other_version):
                    if not self._is_same_major_version(version.version, other_version.version) or \
                            self._is_recent_version(version.version):
                        message = "Version {0} has the same signature as version {1}.".format(version.version,
                                                                                              other_version.version)
                        equal_versions.append(message)
        if len(equal_versions) > 0:
            message = ""
            for _version in equal_versions:
                message += _version + "\n"
            raise Exception(message)

    def _cleanup_signatures(self, version_signatures, signatures_files):
        to_remove = []
        for signature in version_signatures:
            if signature.path not in signatures_files:
                to_remove.append(signature)
        for signature in to_remove:
            version_signatures.remove(signature)

    def _versions_equal(self, version1, version2):
        return len(self._compare_signatures(version1.signatures, version2.signatures)) == 0

    def _is_same_major_version(self, version0, version1):
        version0_major = re.match(self.major_version_pattern, version0)
        version1_major = re.match(self.major_version_pattern, version1)
        return version0_major.group() == version1_major.group()

    def _find_file_signature_in_signatures(self, file_path, signatures):
        for signature in signatures:
            if signature.path == file_path:
                return signature

    def _is_plugin_or_theme_file(self, file_path):
        return re.match("wp-content/((plugins)|(themes))", file_path) is not None

    def _signatures_equal(self, signature, other_signature):
        if signature is not None and other_signature is not None:
            return signature.hash == other_signature.hash
        return False

    def _compare_signatures(self, signatures0, signatures1, exclude_file=None):
        diff = []
        for signature in signatures0:
            if signature.path != exclude_file and not self._is_plugin_or_theme_file(signature.path):
                other_signature = self._find_file_signature_in_signatures(signature.path, signatures1)
                if not self._signatures_equal(signature, other_signature):
                    diff.append(signature.path)

        # Check for files in other_version not present in version:
        for signature in signatures1:
            if signature.path != exclude_file and not self._is_plugin_or_theme_file(signature.path):
                if self._find_file_signature_in_signatures(signature.path, signatures0) is None:
                    diff.append(signature.path)
        return diff

    def _get_diff_between_versions(self, versions, exclude_file=None, files_to_keep_per_diff=1):
        diff_list = []
        versions_without_diff = []
        for index, version in enumerate(versions):
            if index + 1 < len(versions):
                other_version = versions[index + 1]
                diff = self._compare_signatures(version.signatures, other_version.signatures, exclude_file)
                if len(diff) == 0:
                    versions_without_diff.append(
                        "version {0} and version {1} have the same signature.".format(version.version,
                                                                                      other_version.version))
                else:
                    diff_list.append(diff)

        self._keep_most_common_file_in_all_diff_for_each_diff(diff_list, files_to_keep_per_diff)
        return set(file for diff in diff_list for file in diff), versions_without_diff

    def _keep_most_common_file_in_all_diff_for_each_diff(self, diff_list, files_to_keep_per_diff=1):
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

    def _is_recent_version(self, version):
        return re.match("[34]\.\d", version) is not None

    def _is_version_greater_than_other_version(self, version, other_version):
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

    def _sort_versions(self, versions_list):
        sorted_versions = []
        for version in versions_list.versions:
            for index, _version in enumerate(sorted_versions):
                if not self._is_version_greater_than_other_version(version.version, _version.version):
                    sorted_versions.insert(index, version)
                    break
            else:
                sorted_versions.append(version)
        return sorted_versions
