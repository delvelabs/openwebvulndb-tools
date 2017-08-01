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
from .securityfocus.reader import CvssMapper


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


def set_cvss_based_on_reported_type(storage):
    cvss_mapper = CvssMapper(storage)
    for meta in storage.list_meta():
        for vuln_list in storage.list_vulnerabilities(meta.key):
            for vuln in vuln_list.vulnerabilities:
                if vuln.cvss is None:
                    vuln.cvss = cvss_mapper.get_cvss_from_vulnerability_type(vuln.reported_type)
            if vuln_list.dirty:
                storage.write_vulnerabilities(vuln_list)
                vuln_list.clean()


operations = dict(find_identity_files=find_identity_files,
                  find_unclosed_vulnerabilities=find_unclosed_vulnerabilities,
                  set_cvss_based_on_reported_type=set_cvss_based_on_reported_type)


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
