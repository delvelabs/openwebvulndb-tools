from openwebvulndb.common.schemas import VersionListSchema
from openwebvulndb.common.models import VersionDefinition
import json
import re


class Vane2VersionRebuild:

    def __init__(self, storage):
        self.storage = storage
        self.version_list = []
        self._versions_signature_files = []

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
        for version in self.version_list.versions:
            for other_version in self.version_list.versions:
                if version != other_version:
                    if self._versions_equal(version, other_version):
                        if not self._is_two_versions_have_same_major(version, other_version) or self._is_recent_version(version.version):
                            print("Version {0} has the same signature as version {1}.".format(version.version, other_version.version))

    def _versions_equal(self, version1, version2):
        version1_signatures = version1.signatures
        version2_signatures = version2.signatures
        if len(version2_signatures) != len(version1_signatures):
            return False
        for signature in version1_signatures:
            _signature = self._find_file_signature_in_signatures(signature.path, version2_signatures)
            if _signature is not None:
                if signature.hash != _signature.hash:
                    return False
            else:
                return False
        return True

    def _find_file_signature_in_signatures(self, file_path, signatures):
        for signature in signatures:
            if signature.path == file_path:
                return signature

    def _get_diff_with_other_version(self, version, other_version):
        diff = []
        for signature in version.signatures:
            other_signature = self._find_file_signature_in_signatures(signature.path, other_version.signatures)
            if other_signature is not None:
                if signature.hash != other_signature.hash:
                    diff.append(signature.path)
            else:
                diff.append(signature.path)
        # Check for files in other_version not present in version:
        for signature in other_version.signatures:
            if self._find_file_signature_in_signatures(signature.path, version.signatures) is None:
                diff.append(signature.path)
        return diff

    def _create_version_without_files_in_signature(self, version, files_to_exclude):
        signatures = [signature for signature in version.signatures if signature.path not in files_to_exclude]
        return VersionDefinition(version=version.version, signatures=signatures)

    def _compare_versions_without_files(self, versions, files_to_exclude):
        for version in versions:
            for other_version in versions:
                if version != other_version:
                    version_without_files = self._create_version_without_files_in_signature(version, files_to_exclude)
                    other_version_without_files = self._create_version_without_files_in_signature(other_version, files_to_exclude)
                    if self._versions_equal(version_without_files, other_version_without_files):
                        return True
        return False

    def _get_file_occurrence_in_versions(self, file, versions):
        occurrence = 0
        for version in versions:
            if self._find_file_signature_in_signatures(file, version.signatures) is not None:
                occurrence += 1
        return occurrence

    def _remove_redundant_diff_between_versions(self, versions, diff):
        important_files = set()
        files_sorted_by_occurrence = []
        files_occurrence = {file: self._get_file_occurrence_in_versions(file, versions) for file in diff}
        for file in diff:
            if len(files_sorted_by_occurrence) == 0:
                files_sorted_by_occurrence.append(file)
            elif files_occurrence[files_sorted_by_occurrence[len(files_sorted_by_occurrence) - 1]] > files_occurrence[file]:
                files_sorted_by_occurrence.insert(len(files_sorted_by_occurrence) - 1, file)
            else:
                files_sorted_by_occurrence.append(file)

        files_to_exclude = []
        for file in files_sorted_by_occurrence:
            files_to_exclude.append(file)
            if self._compare_versions_without_files(versions, files_to_exclude):
                important_files.add(file)
                files_to_exclude.remove(file)
        return important_files

    def _is_two_versions_have_same_major(self, version, other_version):
        version_major = re.match("\d+\.\d+", version.version)
        other_version_major = re.match("\d+\.\d+", other_version.version)
        return version_major.group() == other_version_major.group()

    def _is_same_major_version(self, version0, version1):
        version0_major = re.match("\d+\.\d+", version0)
        version1_major = re.match("\d+\.\d+", version1)
        return version0_major.group() == version1_major.group()

    def _get_major_versions(self, versions_list):
        major_versions = []
        for version in versions_list.versions:
            major_version = re.match("\d+\.\d+", version.version).group()
            if major_version not in major_versions:
                major_versions.append(major_version)
        return major_versions

    def get_major_version_signature(self, versions_list, major):
        signatures = []
        common_files = self.get_common_file_for_major_version(major, versions_list)
        minor_versions = self.get_minor_versions_in_major_version(versions_list, major)
        for file in common_files:
            signatures.append(self._find_file_signature_in_signatures(file, minor_versions[0].signatures))
        return signatures

    def get_minor_versions_in_major_version(self, versions_list, major_version):
        minor_versions = []
        for version in versions_list.versions:
            if self._is_same_major_version(version.version, major_version):
                minor_versions.append(version)
        return minor_versions

    def get_diff_between_minor_versions(self, minor_versions):
        diff = set()
        for version in minor_versions:
            for other_version in minor_versions:
                if version != other_version:
                    diff = self._get_diff_with_other_version(version, other_version)
                    if len(diff) == 0:
                        print("version {0} and version {1} have the same signature.")
                    diff |= diff
        return self._remove_redundant_diff_between_versions(minor_versions, diff)

    def get_diff_between_major_versions(self, major_versions):
        diff_list = []
        for index, version in enumerate(major_versions):
            if index + 1 < len(major_versions):
                other_version = major_versions[index + 1]
                diff = self._get_diff_with_other_version(version, other_version)
                if len(diff) == 0:
                    print("version {0} and version {1} have the same signature.".format(version.version, other_version.version))
                else:
                    diff_list.append(diff)

        def get_file_occurrence_in_diff(diff_list):
            file_occurrence = {}
            for diff in diff_list:
                for file in diff:
                    if file in file_occurrence:
                        file_occurrence[file] += 1
                    else:
                        file_occurrence[file] = 1
            return file_occurrence

        file_occurrence_in_diff = get_file_occurrence_in_diff(diff_list)
        for diff in diff_list:
            if len(diff) > 1:
                file_with_most_occurrence = None
                for file in diff:
                    if file_with_most_occurrence is None or file_occurrence_in_diff[file] > file_occurrence_in_diff[file_with_most_occurrence]:
                        file_with_most_occurrence = file
                diff.clear()
                diff.append(file_with_most_occurrence)
            file_occurrence_in_diff = get_file_occurrence_in_diff(diff_list)
        return [diff[0] for diff in diff_list]

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

    def get_common_file_for_major_version(self, major, versions_list):
        minor_versions = self.get_minor_versions_in_major_version(versions_list, major)
        common_files = set()
        if len(minor_versions) == 1:
            return set((signature.path for signature in minor_versions[0].signatures))
        for index, version in enumerate(minor_versions):
            if index + 1 < len(minor_versions):
                identical_files = self._get_identical_files_between_versions(version, minor_versions[index + 1])
                if len(identical_files) == 0:
                    print("no common files between {0} and {1}".format(version.version, minor_versions[index + 1].version))
                else:
                    if len(common_files) > 0:
                        common_files &= set(identical_files)
                    else:
                        common_files = set(identical_files)
        return common_files

    def get_files_for_versions_identification(self, versions_list):
        files = set()
        version_done = 0
        major_versions = self._get_major_versions(versions_list)
        major_versions_definition = []
        for version in major_versions:
            signatures = self.get_major_version_signature(versions_list, version)
            version_definition = VersionDefinition(version=version, signatures=signatures)
            major_versions_definition.append(version_definition)
        print("Getting files to identify major versions")
        files = self.get_diff_between_major_versions(major_versions_definition)
        print("files to identify major versions:")
        print(files)
        #for major in major_versions:
            #print("getting files to identify minor versions in %s" % major)
            #minor_versions = self.get_minor_versions_in_major_version(versions_list, major)
            #files |= self.get_diff_between_minor_versions(minor_versions)
        return files
