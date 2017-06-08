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
                file_paths.add(signature.path)
        return list(file_paths)
