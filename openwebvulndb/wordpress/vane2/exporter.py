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

from openwebvulndb.common.models import FileListGroup
from openwebvulndb.common.serialize import serialize
from openwebvulndb.common.schemas import FileListGroupSchema, FileListSchema, VulnerabilityListGroupSchema
from openwebvulndb.common.models import VulnerabilityListGroup, VulnerabilityList
from .versionrebuild import VersionRebuild
from os.path import join


class Exporter:

    def __init__(self, storage):
        self.storage = storage
        self.version_rebuild = VersionRebuild(self.storage)

    def export_plugins(self, export_path, only_popular=False, only_vulnerable=False):
        plugin_list = FileListGroup(key="plugins", producer="Vane2Export")
        for plugin_key in self._list_keys("plugins", only_popular, only_vulnerable):
            self.version_rebuild.update(plugin_key)
            plugin_file_list = self.version_rebuild.file_list
            if len(plugin_file_list.files) > 0:
                plugin_list.file_lists.append(plugin_file_list)

        file_name = self._get_export_file_name(export_path, "plugins", only_popular, only_vulnerable)
        self._dump(file_name, plugin_list, FileListGroupSchema())

    def export_themes(self, export_path, only_popular=False, only_vulnerable=False):
        theme_list = FileListGroup(key="themes", producer="Vane2Export")
        for theme_key in self._list_keys("themes", only_popular, only_vulnerable):
            self.version_rebuild.update(theme_key)
            theme_file_list = self.version_rebuild.file_list
            if len(theme_file_list.files) > 0:
                theme_list.file_lists.append(theme_file_list)

        file_name = self._get_export_file_name(export_path, "themes", only_popular, only_vulnerable)
        self._dump(file_name, theme_list, FileListGroupSchema())

    def export_wordpress(self, export_path):
        equal_versions = self.version_rebuild.update("wordpress")
        wordpress_file_list = self.version_rebuild.file_list
        file_name = self._get_export_file_name(export_path, "wordpress", False, False)
        self._dump(file_name, wordpress_file_list, FileListSchema())
        return equal_versions

    def export_vulnerabilities(self, export_path):
        vulnerability_list_group = VulnerabilityListGroup(producer="vane2_export")

        for plugin_key in self._list_vulnerable("plugins"):
            vulnerability_list_group.vulnerability_lists.append(
                self._regroup_vulnerabilities_of_key_in_one_list(plugin_key))

        for theme_key in self._list_vulnerable("themes"):
            vulnerability_list_group.vulnerability_lists.append(
                self._regroup_vulnerabilities_of_key_in_one_list(theme_key))

        vulnerability_list_group.vulnerability_lists.append(self._regroup_vulnerabilities_of_key_in_one_list("wordpress"))

        file_name = join(export_path, "vane2_vulns.json")
        self._dump(file_name, vulnerability_list_group, VulnerabilityListGroupSchema())

    def _regroup_vulnerabilities_of_key_in_one_list(self, key):
        vulnerability_list = VulnerabilityList(key=key, producer="vane2_export")
        for _vulnerability_list in self.storage.list_vulnerabilities(key):
            vulnerability_list.vulnerabilities.extend(_vulnerability_list.vulnerabilities)
        return vulnerability_list

    def _dump(self, file_name, data, schema):
        data, errors = serialize(schema, data)
        with open(file_name, "w") as fp:
            fp.write(data)

    def _list_keys(self, key, only_popular=False, only_vulnerable=False):
        if only_popular:
            yield from self._list_popular(key)
        elif only_vulnerable:
            yield from self._list_vulnerable(key)
        else:
            yield from self._list_all_keys(key)

    def _list_vulnerable(self, key):
        for _key in self._list_all_keys(key):
            if self._is_vulnerable(_key):
                yield _key

    def _list_popular(self, key):
        for _key in self._list_all_keys(key):
            if self._is_popular(_key):
                yield _key

    def _list_all_keys(self, key):
        for _key, path, dirnames, files in self.storage.walk(key):
            if "versions.json" in files:
                yield _key

    def _is_popular(self, key):
        for meta in self.storage.list_meta(key):
            return meta.is_popular
        return False

    def _is_vulnerable(self, key):
        return any(self.storage.list_vulnerabilities(key))

    def _get_export_file_name(self, path, key, popular, vulnerable):
        base_file_name = "vane2{0}{1}_versions.json"
        if popular:
            file_name = base_file_name.format("_popular_", key)
        elif vulnerable:
            file_name = base_file_name.format("_vulnerable_", key)
        else:
            file_name = base_file_name.format("_", key)
        return join(path, file_name)
