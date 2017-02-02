import re
from collections import Counter
from ...common.models import File, FileSignature, FileList
from ...common.schemas import FileListSchema
from ...common.serialize import serialize
import packaging.version


class VersionRebuild:

    def __init__(self, storage):
        self.storage = storage
        self.version_list = None
        self.file_list = None

    def update(self, key, files_to_keep_per_diff=2):
        self.version_list = self.storage.read_versions(key)

        files, equal_versions = self.get_files_for_versions_identification(
            self.version_list, exclude_file=self._get_files_to_exclude(key), files_to_keep_per_diff=files_to_keep_per_diff)
        # Get a list of file signatures  without the readme, because we can't rely on it for version identification.
        _files, _equal_versions = self.get_files_for_versions_identification(
            self.version_list, exclude_file=self._get_files_to_exclude(key, exclude_readme=True),
            files_to_keep_per_diff=files_to_keep_per_diff)
        files_to_use_for_version_signatures = files | _files
        equal_versions &= _equal_versions

        self._create_file_list(key, files_to_use_for_version_signatures)

        return equal_versions

    def _create_file_list(self, key, files_to_use_for_version_signatures):
        self.file_list = FileList(key=key, producer="Vane2Export")
        for file_path in files_to_use_for_version_signatures:
            file = File(path=file_path)
            signatures = self._get_all_signatures_for_file(file_path)
            file.signatures = signatures
            self.file_list.files.append(file)

    def get_files_for_versions_identification(self, version_list, exclude_file=None, files_to_keep_per_diff=1):
        versions = self._sort_versions(version_list)
        files, versions_without_diff = self._get_diff_between_versions(versions, exclude_file=exclude_file,
                                                                       files_to_keep_per_diff=files_to_keep_per_diff)
        # if no diff were found, (ex: plugin with only one version), return all the files:
        if len(files) == 0 and len(versions) > 0:
            files = set(signature.path for version in versions for signature in version.signatures)
        return files, versions_without_diff

    def dump(self):
        return serialize(FileListSchema(), self.file_list)

    def _find_file_signature_in_signatures(self, file_path, signatures):
        for signature in signatures:
            if signature.path == file_path:
                return signature

    def _compare_signatures(self, signatures0, signatures1, excluded_file=None):
        def exclude_file(file_path):
            if excluded_file is not None:
                for file_pattern in excluded_file:
                    if re.search(file_pattern, file_path) is not None:
                        return True
            return False

        files_in_signatures0 = set(signature.path for signature in signatures0 if not exclude_file(signature.path))
        files_in_signatures1 = set(signature.path for signature in signatures1 if not exclude_file(signature.path))

        diff = files_in_signatures0 ^ files_in_signatures1
        common_files = files_in_signatures0 & files_in_signatures1

        for file_path in common_files:
            signature0 = self._find_file_signature_in_signatures(file_path, signatures0)
            signature1 = self._find_file_signature_in_signatures(file_path, signatures1)
            if signature0.hash != signature1.hash:
                diff.add(file_path)
        return diff

    def _get_diff_between_versions(self, versions, exclude_file=None, files_to_keep_per_diff=1):
        diff_list = []
        versions_without_diff = set()
        for version, next_version in self._pair_list_iteration(versions):
            diff = self._compare_signatures(version.signatures, next_version.signatures, exclude_file)
            if len(diff) == 0:
                versions_without_diff.add("version {0} and version {1} have the same signature.".format(
                    version.version, next_version.version))
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

    def _sort_versions(self, version_list):
        sorted_versions = sorted(version_list.versions, key=lambda v: packaging.version.parse(v.version))
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
                    file_signature = FileSignature(hash=signature.hash, algo=signature.algo)
                    file_signature.versions.append(version.version)
                    signatures[signature.hash] = file_signature
        return [file_signature for file_signature in signatures.values()]

    def _get_files_to_exclude(self, key, exclude_readme=False):
        files_to_exclude = []
        if "plugins" not in key and "themes" not in key:
            files_to_exclude.append("wp-content/((plugins)|(themes))")
        if exclude_readme:
            files_to_exclude.append("readme\.(html|txt)")
        return files_to_exclude
