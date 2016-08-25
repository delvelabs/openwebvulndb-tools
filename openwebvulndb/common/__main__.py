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


operations = dict(find_identity_files=find_identity_files)


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument('-k', '--key', dest='input_key', default="wordpress",
                    help='Software key for targetting specific plugins or themes')
args = parser.parse_args()


try:
    local = app.sub(input_key=args.input_key)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
