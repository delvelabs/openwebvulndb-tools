import re
from collections import Counter
from ...common.vane2models import File, Signature, FilesList
from ...common.vane2schemas import FilesListSchema
from ...common.serialize import serialize
import packaging.version


class VersionRebuild:

    def __init__(self, storage):
        self.storage = storage
        self.version_list = None
        self.files_list = None

    def update(self, key):
        self.version_list = self.storage.read_versions(key)
        files, equal_versions = self.get_files_for_versions_identification(self.version_list, files_to_keep_per_diff=2)
        _files, _equal_versions = self.get_files_for_versions_identification(self.version_list,
                                                                             exclude_file="readme.html",
                                                                             files_to_keep_per_diff=2)
        files_to_use_for_version_signatures = files | _files
        equal_versions &= _equal_versions

        self._create_files_list(key, files_to_use_for_version_signatures)

        return equal_versions

    def _create_files_list(self, key, files_to_use_for_version_signatures):
        self.files_list = FilesList(key=key, producer="Vane2 Export")
        for file_path in files_to_use_for_version_signatures:
            file = File(path=file_path)
            signatures = self._get_all_signatures_for_file(file_path)
            file.signatures = signatures
            self.files_list.files.append(file)

    def get_files_for_versions_identification(self, versions_list, exclude_file=None, files_to_keep_per_diff=1):
        versions = self._sort_versions(versions_list)
        files, versions_without_diff = self._get_diff_between_versions(versions, exclude_file=exclude_file,
                                                                       files_to_keep_per_diff=files_to_keep_per_diff)
        return files, versions_without_diff

    def dump(self):
        return serialize(FilesListSchema(), self.files_list)

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
        diff = set()
        for signature in signatures0:
            if signature.path != exclude_file and not self._is_plugin_or_theme_file(signature.path):
                other_signature = self._find_file_signature_in_signatures(signature.path, signatures1)
                if not self._signatures_equal(signature, other_signature):
                    diff.add(signature.path)

        # Check for files in other_version not present in version:
        for signature in signatures1:
            if signature.path != exclude_file and not self._is_plugin_or_theme_file(signature.path):
                if self._find_file_signature_in_signatures(signature.path, signatures0) is None:
                    diff.add(signature.path)
        return diff

    def _get_diff_between_versions(self, versions, exclude_file=None, files_to_keep_per_diff=1):
        diff_list = []
        versions_without_diff = set()
        for version, next_version in self._pair_list_iteration(versions):
            diff = self._compare_signatures(version.signatures, next_version.signatures, exclude_file)
            if len(diff) == 0:
                versions_without_diff.add(
                    "version {0} and version {1} have the same signature.".format(version.version, next_version.version))
            else:
                diff_list.append(diff)

        self._keep_most_common_file_in_all_diff_for_each_diff(diff_list, files_to_keep_per_diff)
        return set(file for diff in diff_list for file in diff), versions_without_diff

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

    def _sort_versions(self, versions_list):
        sorted_versions = sorted(versions_list.versions, key=lambda v: packaging.version.parse(v.version))
        return sorted_versions

    def _pair_list_iteration(self, _list):
        """Iterates over all element in the list and return the element and the next element in the list in a tuple."""
        for index in range(0, len(_list) - 1):
            yield _list[index], _list[index + 1]

    def _get_all_signatures_for_file(self, file_path):
        signatures = {}
        for version in self.version_list.versions:
            signature = self._find_file_signature_in_signatures(file_path, version.signatures)
            if signature is not None:
                if signature.hash in signatures:
                    signatures[signature.hash].versions.append(version.version)
                else:
                    file_signature = Signature(hash=signature.hash, algo=signature.algo)
                    file_signature.versions.append(version.version)
                    signatures[signature.hash] = file_signature
        return [file_signature for file_signature in signatures.values()]
