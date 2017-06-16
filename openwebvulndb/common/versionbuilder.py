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

from .models import File, FileList, VersionList
from collections import Counter
from .version import parse


class VersionBuilder:

    def __init__(self):
        self.version_list = None
        self.files_per_version = 0

    def create_file_list_from_version_list(self, version_list, files_per_version=50):
        self.version_list = version_list
        self.files_per_version = files_per_version
        self.exclude_files()
        if self.is_version_list_empty():
            return None
        self._shrink_version_list()
        file_list = FileList(key=version_list.key, producer=version_list.producer)
        file_paths = self.get_file_paths_from_version_list()
        for file_path in file_paths:
            file = self._create_file_from_version_list(file_path)
            file_list.files.append(file)
        return file_list

    def _create_file_from_version_list(self, file_path):
        file = File(path=file_path)
        for version_definition in self.version_list.versions:
            signature = self.get_signature(file_path, version_definition)
            if signature is not None:
                file_signature = file.get_signature(signature.hash, create_missing=True)
                file_signature.versions.append(version_definition.version)
        return file

    def get_signature(self, file_path, version_definition):
        for signature in version_definition.signatures:
            if file_path == signature.path:
                return signature

    def get_file_paths_from_version_list(self):
        file_paths = set()
        for version_definition in self.version_list.versions:
            file_paths.update(self._get_paths_in_version(version_definition))
        return file_paths

    def exclude_files(self):
        key = self.version_list.key
        exclude_trunk = "wp-content/%s/trunk/" % key
        exclude_tags = "wp-content/%s/tags/" % key
        exclude_branches = "wp-content/%s/branches/" % key
        for version_definition in self.version_list.versions:
            files_to_remove = set()
            for signature in version_definition.signatures:
                file_path = signature.path
                if exclude_tags in file_path or exclude_trunk in file_path or exclude_branches in file_path:
                    files_to_remove.add(file_path)
            if len(files_to_remove) > 0:
                files_to_keep = set(self._get_paths_in_version(version_definition)) - files_to_remove
                self._set_files_for_version(version_definition, files_to_keep)

    def _shrink_version_list(self):
        if len(self.version_list.versions) == 1:
            # If only one version, choose files randomly.
            files_in_version = list(self._get_paths_in_version(self.version_list.versions[0]))
            if len(files_in_version) > self.files_per_version:
                files_in_version = files_in_version[:self.files_per_version]
            self._set_files_for_version(self.version_list.versions[0], files_in_version)
        else:
            differences_between_versions = self._get_differences_between_versions()
            if any(len(diff) > self.files_per_version for diff in differences_between_versions.values()):
                self._keep_most_common_differences_between_versions(differences_between_versions)
            identity_files = set()
            for differences in differences_between_versions.values():
                identity_files |= differences
            for version in self.version_list.versions:
                identity_files |= self._get_identity_files_for_version(version, identity_files)
            for version in self.version_list.versions:
                files_to_keep = identity_files & set(self._get_paths_in_version(version))
                self._set_files_for_version(version, files_to_keep)

    def _get_identity_files_for_version(self, version, identity_files):
        files_in_version = set(self._get_paths_in_version(version))
        identity_files_for_version = identity_files & files_in_version
        if len(identity_files_for_version) < self.files_per_version:
            files_to_add = self.files_per_version - len(identity_files_for_version)
            new_files_counter = self._get_counter_for_files(files_in_version - identity_files_for_version)
            identity_files_for_version.update(file for file, count in new_files_counter.most_common(files_to_add))
        return identity_files_for_version

    def _set_files_for_version(self, version, files_to_keep):
        signatures_to_keep = []
        for file in files_to_keep:
            signatures_to_keep.append(self.get_signature(file, version))
        version.signatures = signatures_to_keep

    def _get_differences_between_versions(self):
        differences_between_versions = {}
        sorted_version_definitions = self._sort_versions()
        first_version = sorted_version_definitions[0]
        # All files are new in the first version
        differences_between_versions[first_version.version] = set(self._get_paths_in_version(first_version))
        for previous_version, version in self._pair_list_iteration(sorted_version_definitions):
            differences_between_versions[version.version] = self._compare_versions_signatures(previous_version, version)
        return differences_between_versions

    def _compare_versions_signatures(self, previous_version, current_version):
        files_in_previous_version = set(self._get_paths_in_version(previous_version))
        files_in_current_version = set(self._get_paths_in_version(current_version))

        diff = files_in_current_version - files_in_previous_version
        common_files = files_in_current_version & files_in_previous_version

        for file_path in common_files:
            signature0 = self.get_signature(file_path, previous_version)
            signature1 = self.get_signature(file_path, current_version)
            if signature0.hash != signature1.hash:
                diff.add(file_path)
        return diff

    def _keep_most_common_differences_between_versions(self, differences_between_versions):
        diff_counter = Counter(file for diff in differences_between_versions.values() for file in diff)
        file_counter = self._get_counter_for_files(diff_counter.keys())

        for version, diff in differences_between_versions.items():
            if len(diff) > self.files_per_version:
                sorted_files = sorted(diff, reverse=True, key=lambda file: file_counter[file])
                sorted_files = sorted(sorted_files, reverse=True, key=lambda file: diff_counter[file])
                differences_between_versions[version] = set(sorted_files[:self.files_per_version])
            # Update the counter, so the next versions doesn't count diff removed from this version.
                diff_counter = Counter(file for diff in differences_between_versions.values() for file in diff)

    def _sort_versions(self):
        sorted_versions = sorted(self.version_list.versions, key=lambda v: parse(v.version))
        return sorted_versions

    def _pair_list_iteration(self, _list):
        """Iterates over all element in the list and return the element and the next element in the list in a tuple."""
        for index in range(0, len(_list) - 1):
            yield _list[index], _list[index + 1]

    def _get_paths_in_version(self, version_definition):
        for signature in version_definition.signatures:
            yield signature.path

    def is_version_list_empty(self):
        if len(self.version_list.versions) == 0 or\
                all(len(version.signatures) == 0 for version in self.version_list.versions):
            return True

    def _get_counter_for_files(self, paths):
        file_counter = Counter()
        for version in self.version_list.versions:
            file_counter.update(file_path for file_path in self._get_paths_in_version(version) if file_path in paths)
        return file_counter


class VersionImporter:
    """Convert a FileList model to a VersionList model."""

    def import_version_list(self, file_list):
        version_list = VersionList(key=file_list.key, producer=file_list.producer)
        for file in file_list.files:
            for file_signature in file.signatures:
                for version in file_signature.versions:
                    version_definition = version_list.get_version(version, create_missing=True)
                    version_definition.add_signature(path=file.path, hash=file_signature.hash, algo=file_list.hash_algo)
        return version_list
