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

from argparse import ArgumentParser

from openwebvulndb import app
from .versionbuilder import VersionBuilder
from .schemas import FileListSchema


def find_identity_files(storage, input_key):
    versions = storage.read_versions(input_key)

    from collections import defaultdict
    file_map = defaultdict(list)
    for v in versions.versions:
        for s in v.signatures:
            file_map[s.path].append(s.hash)

    data = [(len(set(values)), len(values), path) for path, values in file_map.items()]
    data.sort(reverse=True)
    for uniques, total, path in data:
        print("%s/%s    %s" % (uniques, total, path))

    print("Total version count: %s" % len(versions.versions))


def find_unclosed_vulnerabilities(storage, input_filter):
    for meta in storage.list_meta():
        if input_filter == "popular" and not meta.is_popular:
            continue

        for vlist in storage.list_vulnerabilities(meta.key):
            for v in vlist.vulnerabilities:
                if not v.affected_versions or any(r.fixed_in is None for r in v.affected_versions):
                    print("{l.key: <60} {l.producer: <15} {v.id: <20} {v.title}".format(l=vlist, v=v))


def change_version_format(storage, keep_old=True):
    version_builder = VersionBuilder()
    keys = ["mu", "wordpress", "plugins", "themes"]
    for key in keys:
        for _key in storage.list_directories(key):
            keys.append("{0}/{1}".format(key, _key))
    progress = 0
    for key in keys:
        progress += 1
        print_progress("{0} / {1} component".format(progress, len(keys)))
        try:
            version_list = storage.read_versions(key)
            file_list = version_builder.create_file_list_from_version_list(version_list)
            if file_list is not None:
                if keep_old:
                    storage._write(FileListSchema(), file_list, "versions_new.json")
                else:
                    storage._write(FileListSchema(), file_list, "versions.json")
        except FileNotFoundError:
            pass


def check_if_old_versions_equal_new_versions(storage):
    keys = ["mu", "wordpress", "plugins", "themes"]
    for key in keys:
        for _key in storage.list_directories(key):
            keys.append("{0}/{1}".format(key, _key))
    count = 0
    for key in keys:
        try:
            version_list = storage.read_versions(key)
            file_list = storage._read(FileListSchema(), key, 'versions_new.json')
            total_files = set()
            for version_definition in version_list.versions:
                for signature in version_definition.signatures:
                    total_files.add(signature.path)
            if len(total_files) != len(file_list.files):
                print("Error, missing file for %s" % key)
            else:
                for file in file_list.files:
                    check_if_hash_and_version_for_files_are_ok(file, version_list)
            count += 1
        except FileNotFoundError:
            pass
    print("%d files checked" % count)


def check_if_hash_and_version_for_files_are_ok(file, version_list):
    file_path = file.path
    hash_versions = {}
    for version_definition in version_list.versions:
        for signature in version_definition.signatures:
            if signature.path == file_path:
                if signature.hash in hash_versions:
                    hash_versions[signature.hash].add(version_definition.version)
                else:
                    hash_versions[signature.hash] = {version_definition.version}

    for file_signature in file.signatures:
        if len(file_signature.versions) != len(hash_versions[file_signature.hash]) or len(file_signature.versions) != \
                len(set(version for version in file_signature.versions) & hash_versions[file_signature.hash]):
            print("Error, missing version for {0} in {1}".format(file_path, version_list.key))


def print_progress(string):
    print("\r%s" % string, end="")


def count_files_per_component(storage):
    def sort_by_files(file_list):
        return len(file_list.files)
    component_files = []
    keys = ["mu", "wordpress", "plugins", "themes"]
    progress = 0
    for key in keys:
        progress += 1
        print_progress("{0} / {1} component".format(progress, len(keys)))
        for _key in storage.list_directories(key):
            keys.append("{0}/{1}".format(key, _key))
    for key in keys:
        try:
            file_list = storage._read(FileListSchema(), key, 'versions_new.json')
            if len(file_list.files) != 0:
                component_files.append(file_list)
        except FileNotFoundError:
            pass
    component_files = sorted(component_files, key=sort_by_files, reverse=True)
    with open("file_path_count2", "wt") as fp:
        for component in component_files:
            fp.write("{0}: {1} files\n".format(component.key, len(component.files)))


operations = dict(find_identity_files=find_identity_files,
                  find_unclosed_vulnerabilities=find_unclosed_vulnerabilities,
                  change_version_format=change_version_format,
                  check_if_old_versions_equal_new_versions=check_if_old_versions_equal_new_versions,
                  count_files_per_component=count_files_per_component)


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument('-k', '--key', dest='input_key', default="wordpress",
                    help='Software key for targetting specific plugins or themes')
parser.add_argument('-f', '--filter', dest='input_filter', choices=["popular"],
                    help='Filters for vulnerabilities')
args = parser.parse_args()


try:
    local = app.sub(input_key=args.input_key,
                    input_filter=args.input_filter)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
