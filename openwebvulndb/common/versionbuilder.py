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

from .models import FileSignature, File, FileList
from collections import Counter
from .version import parse


class VersionBuilder:

    def create_file_list_from_version_list(self, version_list, files_to_keep_per_version=50):
        if self.is_version_list_empty(version_list):
            return None
        # TODO filter files before this step.
        self.recreate_version_list(version_list, files_to_keep_per_version)
        file_list = FileList(key=version_list.key, producer=version_list.producer)
        file_paths = self.get_file_paths_from_version_list(version_list)
        file_paths = [file for file in file_paths if not self.exclude_file(file, version_list.key)]
        if len(file_paths) == 0:
            return None
        for file_path in file_paths:
            file = self.create_file_from_version_list(file_path, version_list)
            file_list.files.append(file)
        return file_list

    def create_file_from_version_list(self, file_path, version_list):
        file_signatures = self.get_file_signatures(file_path, version_list)
        return File(path=file_path, signatures=file_signatures)

    def get_file_signatures(self, file_path, version_list):
        file_signatures = []
        for version_definition in version_list.versions:
            signature = self.get_signature(file_path, version_definition)
            if signature is not None:
                hash = signature.hash
                file_signature = self.get_file_signature_for_hash(hash, file_signatures)
                file_signature.versions.append(version_definition.version)
        return file_signatures

    def get_signature(self, file_path, version_definition):
        for signature in version_definition.signatures:
            if file_path == signature.path:
                return signature

    def get_file_signature_for_hash(self, hash, files_signature_list):
        for file_signature in files_signature_list:
            if hash == file_signature.hash:
                return file_signature
        file_signature = FileSignature(hash=hash)
        files_signature_list.append(file_signature)
        return file_signature

    def get_file_paths_from_version_list(self, version_list):
        file_paths = set()
        for version_definition in version_list.versions:
            file_paths.update(self.get_file_paths_in_version_definition(version_definition))
        return list(file_paths)

    def exclude_file(self, file_path, key):
        exclude_trunk = "wp-content/%s/trunk/" % key
        exclude_tags = "wp-content/%s/tags/" % key
        exclude_branches = "wp-content/%s/branches/" % key
        if exclude_tags in file_path or exclude_trunk in file_path or exclude_branches in file_path:
            return True
        return False

    def recreate_version_list(self, version_list, files_to_keep_per_diff):
        if all(len(version.signatures) <= files_to_keep_per_diff for version in version_list.versions):
            return
        elif len(version_list.versions) == 1:
            files_to_keep = self._get_most_common_files(version_list, files_to_keep_per_diff)  # Let counter choose files to keep.
            self._remove_files_from_version(version_list.versions[0], files_to_keep)
        else:
            differences_between_versions = self._get_diff_between_versions(version_list, files_to_keep_per_diff)
            for version in version_list.versions:
                files_to_keep = differences_between_versions[version.version]
                if len(files_to_keep) < files_to_keep_per_diff:
                    most_common_files = self._get_most_common_files_present_in_version(version_list, version, files_to_keep_per_diff)
                    new_files = set(iter(most_common_files)) - files_to_keep
                    missing_file_count = files_to_keep_per_diff - len(files_to_keep)
                    most_common_files_not_in_diff = [file for file in most_common_files if file in new_files]
                    files_to_add = []
                    for file in most_common_files:
                        if file in most_common_files_not_in_diff:
                            files_to_add.append(file)
                        if len(files_to_add) == missing_file_count:
                            break
                    files_to_keep.update(files_to_add)
                self._remove_files_from_version(version, files_to_keep)

    def _remove_files_from_version(self, version, files_to_keep):
        new_signature_list = []
        for file in files_to_keep:
            new_signature_list.append(self.get_signature(file, version))
        version.signatures = new_signature_list

    def _get_diff_between_versions(self, version_list, files_to_keep_per_diff):
        differences_between_versions = {}
        sorted_version_definitions = self._sort_versions(version_list)
        first_version = sorted_version_definitions[0]
        # All files are new in the first version
        differences_between_versions[first_version.version] = set(iter(self.get_file_paths_in_version_definition(first_version)))
        for previous_version, version in self._pair_list_iteration(sorted_version_definitions):
            differences_between_versions[version.version] = self._compare_versions_signatures(previous_version, version)
        if any(len(diff) > files_to_keep_per_diff for diff in differences_between_versions.values()):
            self._keep_most_common_file_in_all_diff_for_each_diff(differences_between_versions, files_to_keep_per_diff)
        return differences_between_versions

    def _compare_versions_signatures(self, previous_version, current_version):
        files_in_previous_version = set(iter(self.get_file_paths_in_version_definition(previous_version)))
        files_in_current_version = set(iter(self.get_file_paths_in_version_definition(current_version)))

        diff = files_in_current_version - files_in_previous_version
        common_files = files_in_current_version & files_in_previous_version

        for file_path in common_files:
            signature0 = self.get_signature(file_path, previous_version)
            signature1 = self.get_signature(file_path, current_version)
            if signature0.hash != signature1.hash:
                diff.add(file_path)
        return diff

    def _keep_most_common_file_in_all_diff_for_each_diff(self, differences_between_versions, files_to_keep_per_diff):
        most_common_files_in_diff = Counter(file for diff in differences_between_versions.values() for file in diff).most_common()
        for version, diff in differences_between_versions.items():
            if len(diff) > files_to_keep_per_diff:
                new_diff = set()
                for file, file_count in most_common_files_in_diff:
                    if file in diff:
                        new_diff.add(file)
                        if len(new_diff) == files_to_keep_per_diff:
                            break  # Done for this diff, proceed with the next.
            differences_between_versions[version] = new_diff
            # Update the counter with the removed files, so the files kept by the previous diffs are taken into
            # account for the choices of the next diffs.
            most_common_files_in_diff = Counter(file for diff in differences_between_versions.values() for file in diff).most_common()

    def _get_most_common_files_present_in_version(self, version_list, version, file_count):
        most_common_files = self._get_most_common_files(version_list, None)
        files_in_version = self.get_file_paths_in_version_definition(version)
        most_common_files_in_version = [file for file in most_common_files if file in files_in_version]
        return most_common_files_in_version[:file_count]

    def _get_most_common_files(self, version_list, file_count):
        file_counter = Counter()
        for version in version_list.versions:
            file_counter.update(self.get_file_paths_in_version_definition(version))
        return [file for file, count in file_counter.most_common(file_count)]

    def _sort_versions(self, version_list):
        sorted_versions = sorted(version_list.versions, key=lambda v: parse(v.version))
        return sorted_versions

    def _pair_list_iteration(self, _list):
        """Iterates over all element in the list and return the element and the next element in the list in a tuple."""
        for index in range(0, len(_list) - 1):
            yield _list[index], _list[index + 1]

    def get_file_paths_in_version_definition(self, version_definition):
        return [signature.path for signature in version_definition.signatures]

    def is_version_list_empty(self, version_list):
        if len(version_list.versions) == 0 or all(len(version.signatures) == 0 for version in version_list.versions):
            return True
