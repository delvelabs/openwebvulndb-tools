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

    def create_file_list_from_version_list(self, version_list):
        file_list = FileList(key=version_list.key, producer=version_list.producer)
        file_paths = self.get_file_paths_from_version_list(version_list)
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
            for signature in version_definition.signatures:
                if not self.exclude_file(signature.path, version_list.key):
                    file_paths.add(signature.path)
        file_paths = list(file_paths)
        file_paths = self.limit_files_amount(file_paths, version_list, 100)
        return file_paths

    def exclude_file(self, file_path, key):
        exclude_trunk = "wp-content/%s/trunk/" % key
        exclude_tags = "wp-content/%s/tags/" % key
        if exclude_tags in file_path or exclude_trunk in file_path:
            return True
        return False

    def limit_files_amount(self, file_paths, version_list, max_file_amount):
        # TODO:
        #   -get a list of all files that differ from one version to another, for all versions, ignore the max.
        #   -If some diff contains more files than the max, choose the most common ones, capping at max, remove exceeding arbitrarily if filtering by occurence is not enough
        #   -If some diff contains less files than the max, choose in the most common ones for the diff (done at the same time as the last step?)
        #   -If the total amount of files is less than the max, return all files
        #   -If there is still some files missing, choose the files in the first version that appears in the most versions
        #   -If no diff at all, (just one version) return all files, capping at the max per diff.
        if len(file_paths) <= max_file_amount:
            return file_paths
        files = self._get_diff_between_versions(self._sort_versions(version_list), max_file_amount)
        if len(files) == 0:
            return file_paths[:max_file_amount]
        elif len(files) < max_file_amount:
            pass
        return list(files)

    def _get_diff_between_versions(self, versions, files_to_keep_per_diff):
        diff_list = []
        for version, next_version in self._pair_list_iteration(versions):
            diff = self._compare_signatures(version.signatures, next_version.signatures)
            if len(diff) > 0:
                diff_list.append(diff)
        self._keep_most_common_file_in_all_diff_for_each_diff(diff_list, files_to_keep_per_diff)
        return set(file for diff in diff_list for file in diff)

    def _compare_signatures(self, signatures0, signatures1):
        files_in_signatures0 = set(signature.path for signature in signatures0)
        files_in_signatures1 = set(signature.path for signature in signatures1)

        diff = files_in_signatures0 ^ files_in_signatures1
        common_files = files_in_signatures0 & files_in_signatures1

        for file_path in common_files:
            signature0 = self._find_file_signature_in_signatures(file_path, signatures0)
            signature1 = self._find_file_signature_in_signatures(file_path, signatures1)
            if signature0.hash != signature1.hash:
                diff.add(file_path)
        return diff

    def _find_file_signature_in_signatures(self, file_path, signatures):
        for signature in signatures:
            if signature.path == file_path:
                return signature

    def _keep_most_common_file_in_all_diff_for_each_diff(self, diff_list, files_to_keep_per_diff=1):
        files_count_in_all_diff = Counter(file for diff in diff_list for file in diff)
        for diff in diff_list:
            new_diff = set()
            for file_count in files_count_in_all_diff.most_common():
                file = file_count[0]
                if file in diff:
                    new_diff.add(file)
                    if len(new_diff) == files_to_keep_per_diff:
                        break  # Done for this diff, proceed with the next.
            diff &= new_diff
            # Update the counter with the removed files, so the files kept by the previous diffs are taken into
            # account for the choices of the next diffs.
            files_count_in_all_diff = Counter(file for diff in diff_list for file in diff)

    def _sort_versions(self, version_list):
        sorted_versions = sorted(version_list.versions, key=lambda v: parse(v.version))
        return sorted_versions

    def _pair_list_iteration(self, _list):
        """Iterates over all element in the list and return the element and the next element in the list in a tuple."""
        for index in range(0, len(_list) - 1):
            yield _list[index], _list[index + 1]
