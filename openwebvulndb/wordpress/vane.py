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

from datetime import datetime
from heapq import heappush
import json
import re
from os.path import join
from collections import defaultdict, OrderedDict
import xml.etree.ElementTree as ET
from xml.dom import minidom

from ..common import VersionRange
from ..common.version import VersionCompare
from ..common.manager import ReferenceManager


DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class VaneImporter:

    version_match = re.compile(r'\d+(\.\d+)+')

    def __init__(self, *, vulnerability_manager, storage):
        self.manager = vulnerability_manager
        self.storage = storage
        self.reference_manager = ReferenceManager()
        self.files = {}

    def get_list(self, *args):
        return self.manager.get_producer_list("VaneImporter", *args)

    def dump(self, input_path):
        def path(file):
            return join(input_path, file)

        self.dump_plugins(path('plugin_vulns.json'))
        self.dump_themes(path('theme_vulns.json'))
        self.dump_wordpress(path('wp_vulns.json'))
        self.dump_lists("plugins", path('plugins.txt'), path('plugins_full.txt'))
        self.dump_lists("themes", path('themes.txt'), path('themes_full.txt'))

    def load(self, input_path):
        def path(file):
            return join(input_path, file)

        self.load_plugins(path('plugin_vulns.json'))
        self.load_themes(path('theme_vulns.json'))
        self.load_wordpress(path('wp_vulns.json'))

    def load_wordpress(self, data_file_path):
        vl = self.get_list("wordpress")

        for key, data in self._iterate(data_file_path):
            for vuln_data in data["vulnerabilities"]:
                vuln = vl.get_vulnerability(vuln_data["id"], create_missing=True)
                self.apply_data(vuln, vuln_data, key=key)

    def load_plugins(self, data_file_path):
        self.load_vulnerabilities(data_file_path, "plugins")

    def load_themes(self, data_file_path):
        self.load_vulnerabilities(data_file_path, "themes")

    def load_vulnerabilities(self, data_file_path, base):
        for key, data in self._iterate(data_file_path):
            vl = self.get_list(base, key)

            for vuln_data in data["vulnerabilities"]:
                vuln = vl.get_vulnerability(vuln_data["id"], create_missing=True)
                self.apply_data(vuln, vuln_data)

    def dump_wordpress(self, data_file_path):
        version_list = self.storage.read_versions("wordpress")
        vulnerability_lists = list(self.storage.list_vulnerabilities("wordpress"))

        def iterate():
            for v in version_list.versions:
                number = v.version
                applicable = self.dump_wordpress_vulnerabilities_for_version(vulnerability_lists, number)
                yield number, applicable

        self._dump_file(data_file_path, iterate())

    def dump_plugins(self, data_file_path):
        self._dump_components(data_file_path, "plugins")

    def dump_themes(self, data_file_path):
        self._dump_components(data_file_path, "themes")

    def _dump_components(self, data_file_path, type):
        components = self.storage.list_directories(type)

        def iterate():
            for slug in components:
                applicable = list(self.dump_vulnerabilities(type, slug))
                yield slug, applicable

        self._dump_file(data_file_path, iterate())

    def _dump_file(self, data_file_path, data):
        out = []
        for section, applicable in data:
            if len(applicable) > 0:
                out.append({section: {"vulnerabilities": applicable}})

        with open(data_file_path, "w") as fp:
            fp.write(json.dumps(out, indent=4))

    def dump_wordpress_vulnerabilities_for_version(self, vlists, version):
        applicable = self.manager.filter_for_version(version, vlists)
        return [self.dump_vulnerability(v, for_version=version) for v in applicable]

    def dump_vulnerabilities(self, *args):
        key = "/".join(args)
        for vlist in self.storage.list_vulnerabilities(key):
            for vuln in vlist.vulnerabilities:
                yield self.dump_vulnerability(vuln)

    def dump_lists(self, group, partial_file_path, full_file_path):
        partial_list = []
        full_list = []

        for meta in self.storage.list_meta(group):
            _, slug = meta.key.split("/")

            heappush(full_list, slug)
            if meta.is_popular:
                heappush(partial_list, slug)

        with open(partial_file_path, "w") as fp:
            fp.write("\n".join(partial_list))

        with open(full_file_path, "w") as fp:
            fp.write("\n".join(full_list))

    @staticmethod
    def _iterate(data_file_path):
        with open(data_file_path, 'r') as fp:
            data_file = json.load(fp)
            for entry in data_file:
                for key, vuln_data in entry.items():
                    yield key, vuln_data

    @classmethod
    def dump_vulnerability(cls, vuln, for_version=None):
        out = OrderedDict()
        out["id"] = vuln.id

        def apply_title(r):
            if r.introduced_in is not None:
                out["title"] = "%s (%s+)" % (out["title"], r.introduced_in)

        if vuln.title is not None:
            out["title"] = vuln.title
        if vuln.cvss is not None:
            out["cvss"] = vuln.cvss
        if vuln.reported_type is not None:
            out["vuln_type"] = vuln.reported_type
        if vuln.updated_at is not None:
            out["updated_at"] = _format_date(vuln.updated_at)
        if vuln.created_at is not None:
            out["created_at"] = _format_date(vuln.created_at)

        if for_version is not None:
            for r in vuln.affected_versions:
                if r.fixed_in is not None and r.contains(for_version):
                    apply_title(r)
                    out["fixed_in"] = r.fixed_in
                    break
        else:
            versions = [r.fixed_in for r in vuln.affected_versions if r.fixed_in is not None]
            if len(versions) > 0:
                versions = VersionCompare.sorted(versions)
                apply_title(vuln.affected_versions[0])
                out["fixed_in"] = versions[-1]

        out.update(cls.extract_references(vuln))

        return out

    @staticmethod
    def extract_references(vuln):
        out = defaultdict(list)
        for ref in vuln.references:
            if ref.type == "other":
                out["url"].append(ref.url)
            else:
                out[ref.type].append(ref.id)

        return out

    def apply_data(self, vuln, vuln_data, key=None):
        if "title" in vuln_data:
            vuln.title = vuln_data["title"]
        if "vuln_type" in vuln_data:
            vuln.reported_type = vuln_data["vuln_type"]

        range = self._find_range(vuln_data.get("title") or "", vuln_data.get("fixed_in"), key=key)
        if range is not None:
            vuln.add_affected_version(range)

        if "updated_at" in vuln_data:
            vuln.updated_at = _parse_date(vuln_data["updated_at"])
        if "created_at" in vuln_data:
            vuln.created_at = _parse_date(vuln_data["created_at"])

        ref_manager = self.reference_manager.for_list(vuln.references)

        for normalized in self.reference_manager.normalized_sources:
            for id in self._values_for(vuln_data, normalized):
                ref_manager.include_normalized(normalized, id)

        for url in self._values_for(vuln_data, "url"):
            ref_manager.include_url(url)

    @staticmethod
    def _values_for(vuln_data, key):
        if key in vuln_data:
            value = vuln_data[key]
            if isinstance(value, str) or isinstance(value, int):
                yield value
            else:
                for v in vuln_data[key]:
                    yield v

    def _find_range(self, title, fixed_in, key=None):
        range = VersionRange()

        if key is None:
            match = self.version_match.search(title)
            if match:
                range.introduced_in = match.group(0)
        else:
            range.introduced_in = key
            range.fixed_in = VersionCompare.next_minor(key)

        if fixed_in is not None:
            range.fixed_in = fixed_in

        return range


class VaneVersionRebuild:

    def __init__(self, file):
        self.file = file
        self.tree = ET.parse(file)
        self.file_nodes = dict(self._list_files())

    @property
    def files(self):
        return list(self.file_nodes.keys())

    def get_hash(self, file_path, version):
        try:
            node = self.file_nodes[file_path]
            for h in node.iter('hash'):
                for v in h.iter('version'):
                    if v.text == version:
                        return h

            h = node.makeelement('hash', {})
            node.insert(0, h)
            v = h.makeelement('version', {})
            v.text = version
            h.append(v)
            return h
        except KeyError:
            raise FileNotFoundError(file_path)

    @staticmethod
    def load(string):
        return ET.fromstring(string)

    @staticmethod
    def dump(node):
        return ET.tostring(node).decode('utf-8')

    def write(self):
        self.tree.write(self.file, encoding="UTF-8")
        xml = minidom.parse(self.file)

        with open(self.file, "w") as fp:
            fp.write(xml.toprettyxml())

    def update(self, version_list):
        for file, node in self.file_nodes.items():
            for v in version_list.versions:
                for sig in v.signatures:
                    if sig.path == file:
                        hash = self.get_hash(file, v.version)
                        hash.attrib[sig.algo.lower()] = sig.hash
                        break

            self.clean(node)

    @staticmethod
    def clean(node):
        existing = dict()
        to_remove = set()
        for child in node.iter('hash'):
            for k, v in child.attrib.items():
                if v in existing:
                    to_remove.add(child)
                    if existing[v] is not None:
                        to_remove.add(existing[v])
                        existing[v] = None
                else:
                    existing[v] = child

        for r in to_remove:
            node.remove(r)

    def _list_files(self):
        root = self.tree.getroot()
        for node in root.iter("file"):
            yield node.attrib["src"], node


def _parse_date(data):
    return datetime.strptime(data, DATE_FORMAT)


def _format_date(date):
    """Format the date with additional complexity due to lack of options for
       microsecond precision."""
    out = date.strftime(DATE_FORMAT[0:-6])
    out += "%.3f" % (date.second + date.microsecond / 1e6)
    out += "Z"
    return out
