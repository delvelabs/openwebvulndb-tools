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

from unittest import TestCase
from unittest.mock import MagicMock, call
from openwebvulndb.common.models import VersionList, VersionDefinition, Signature, Meta, Vulnerability, \
    VulnerabilityList
from openwebvulndb.wordpress.vane2.exporter import Exporter
from openwebvulndb.common.schemas import FileListGroupSchema, FileListSchema


class ExporterTest(TestCase):

    def setUp(self):
        self.storage = FakeStorage(None, None)
        self.exporter = Exporter(self.storage)
        self.exporter._dump = MagicMock()

    def test_export_plugins_regroup_plugins_in_one_file(self):
        version_definition = VersionDefinition(version="1.0", signatures=[Signature(path="file")])
        plugin0_version_list = VersionList(key="plugin0", producer="unittest", versions=[version_definition])
        plugin1_version_list = VersionList(key="plugin1", producer="unittest", versions=[version_definition])
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["plugin0", "plugin1"]
        self.storage.version_list = [plugin0_version_list, plugin1_version_list]

        self.exporter.export_plugins(export_path="path")

        args, kwargs = self.exporter._dump.call_args
        plugins = args[1]
        schema = args[2]
        self.assertIsInstance(schema, FileListGroupSchema)
        self.assertEqual(plugins.key, "plugins")
        self.assertEqual(plugins.producer, "Vane2Export")
        self.assert_object_with_attribute_value_in_container("key", "plugin0", plugins.file_lists)
        self.assert_object_with_attribute_value_in_container("producer", "Vane2Export", plugins.file_lists)
        self.assert_object_with_attribute_value_in_container("key", "plugin1", plugins.file_lists)

    def test_export_plugins_create_file_list_from_version_list_for_plugin(self):
        versions = [VersionDefinition(version="1.0", signatures=[Signature(path="file.html", hash="a1b2c3")]),
                    VersionDefinition(version="2.0", signatures=[Signature(path="file.html", hash="d4e5f6"),
                                                                 Signature(path="style.css", hash="12345")])]
        plugin_version_list = VersionList(key="my-plugin", producer="unittest", versions=versions)
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["my-plugin"]
        self.storage.version_list = [plugin_version_list]

        self.exporter.export_plugins("path")

        args, kwargs = self.exporter._dump.call_args
        plugins = args[1]
        plugin = plugins.file_lists[0]
        self.assertEqual(plugin.key, "my-plugin")
        self.assert_object_with_attribute_value_in_container("path", "file.html", plugin.files)
        self.assert_object_with_attribute_value_in_container("path", "style.css", plugin.files)
        path_file = self.get_object_with_attribute_value_in_container("path", "file.html", plugin.files)
        style_file = self.get_object_with_attribute_value_in_container("path", "style.css", plugin.files)
        path_version1_signature = self.get_object_with_attribute_value_in_container("hash", "a1b2c3",
                                                                                    path_file.signatures)
        path_version2_signature = self.get_object_with_attribute_value_in_container("hash", "d4e5f6",
                                                                                    path_file.signatures)
        style_signature = style_file.signatures[0]
        self.assertEqual(path_version1_signature.versions, ["1.0"])
        self.assertEqual(path_version2_signature.versions, ["2.0"])
        self.assertEqual(style_signature.versions, ["2.0"])

    def test_export_plugins_ignore_plugins_with_empty_versions_file(self):
        plugin_version_list = VersionList(key="my-plugin", producer="unittest")
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["my-plugin"]
        self.storage.version_list = [plugin_version_list]

        self.exporter.export_plugins("path")

        args, kwargs = self.exporter._dump.call_args
        plugins = args[1]
        self.assertEqual(len(plugins.file_lists), 0)

    def test_export_plugins_call_list_keys_with_good_args(self):
        self.exporter._list_keys = MagicMock()

        self.exporter.export_plugins("path", only_popular=True)
        self.exporter.export_plugins("path", only_vulnerable=True)

        calls = [call("plugins", True, False), call("plugins", False, True)]
        self.exporter._list_keys.assert_has_calls(calls, any_order=True)

    def test_export_plugins_call_dump_with_good_file_name(self):
        self.exporter.export_plugins("path")
        self.exporter.export_plugins("path", only_popular=True)
        self.exporter.export_plugins("path", only_vulnerable=True)

        calls = self.exporter._dump.mock_calls
        name, args, kwargs = calls[0]
        self.assertEqual(args[0], "path/vane2_plugins_versions.json")
        name, args, kwargs = calls[1]
        self.assertEqual(args[0], "path/vane2_popular_plugins_versions.json")
        name, args, kwargs = calls[2]
        self.assertEqual(args[0], "path/vane2_vulnerable_plugins_versions.json")

    def test_export_themes_regroup_themes_in_one_file(self):
        version_definition = VersionDefinition(version="1.0", signatures=[Signature(path="file")])
        theme0_version_list = VersionList(key="theme0", producer="unittest", versions=[version_definition])
        theme1_version_list = VersionList(key="theme1", producer="unittest", versions=[version_definition])
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["theme0", "theme1"]
        self.storage.version_list = [theme0_version_list, theme1_version_list]

        self.exporter.export_themes("path")

        args, kwargs = self.exporter._dump.call_args
        themes = args[1]
        schema = args[2]
        self.assertIsInstance(schema, FileListGroupSchema)
        self.assertEqual(themes.key, "themes")
        self.assertEqual(themes.producer, "Vane2Export")
        self.assert_object_with_attribute_value_in_container("key", "theme0", themes.file_lists)
        self.assert_object_with_attribute_value_in_container("producer", "Vane2Export", themes.file_lists)
        self.assert_object_with_attribute_value_in_container("key", "theme1", themes.file_lists)

    def test_export_themes_create_file_list_from_version_list_for_theme(self):
        versions = [VersionDefinition(version="1.0", signatures=[Signature(path="file.html", hash="a1b2c3")]),
                    VersionDefinition(version="2.0", signatures=[Signature(path="file.html", hash="d4e5f6"),
                                                                 Signature(path="style.css", hash="12345")])]
        theme_version_list = VersionList(key="my-theme", producer="unittest", versions=versions)
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["my-theme"]
        self.storage.version_list = [theme_version_list]

        self.exporter.export_themes("path")

        args, kwargs = self.exporter._dump.call_args
        themes = args[1]
        theme = themes.file_lists[0]
        self.assertEqual(theme.key, "my-theme")
        self.assert_object_with_attribute_value_in_container("path", "file.html", theme.files)
        self.assert_object_with_attribute_value_in_container("path", "style.css", theme.files)
        path_file = self.get_object_with_attribute_value_in_container("path", "file.html", theme.files)
        style_file = self.get_object_with_attribute_value_in_container("path", "style.css", theme.files)
        path_version1_signature = self.get_object_with_attribute_value_in_container("hash", "a1b2c3",
                                                                                    path_file.signatures)
        path_version2_signature = self.get_object_with_attribute_value_in_container("hash", "d4e5f6",
                                                                                    path_file.signatures)
        style_signature = style_file.signatures[0]
        self.assertEqual(path_version1_signature.versions, ["1.0"])
        self.assertEqual(path_version2_signature.versions, ["2.0"])
        self.assertEqual(style_signature.versions, ["2.0"])

    def test_export_themes_ignore_themes_with_empty_versions_file(self):
        theme_version_list = VersionList(key="my-theme", producer="unittest")
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["my-theme"]
        self.storage.version_list = [theme_version_list]

        self.exporter.export_themes("path")

        args, kwargs = self.exporter._dump.call_args
        themes = args[1]
        self.assertEqual(len(themes.file_lists), 0)

    def test_export_themes_call_list_keys_with_good_args(self):
        self.exporter._list_keys = MagicMock()

        self.exporter.export_themes("path", only_popular=True)
        self.exporter.export_themes("path", only_vulnerable=True)

        calls = [call("themes", True, False), call("themes", False, True)]
        self.exporter._list_keys.assert_has_calls(calls, any_order=True)

    def test_export_themes_call_dump_with_good_file_name(self):
        self.exporter.export_themes("path")
        self.exporter.export_themes("path", only_popular=True)
        self.exporter.export_themes("path", only_vulnerable=True)

        calls = self.exporter._dump.mock_calls
        name, args, kwargs = calls[0]
        self.assertEqual(args[0], "path/vane2_themes_versions.json")
        name, args, kwargs = calls[1]
        self.assertEqual(args[0], "path/vane2_popular_themes_versions.json")
        name, args, kwargs = calls[2]
        self.assertEqual(args[0], "path/vane2_vulnerable_themes_versions.json")

    def test_export_wordpress_dump_wordpress_versions(self):
        versions = [VersionDefinition(version="1.0", signatures=[Signature(path="file.html", hash="a1b2c3")]),
                    VersionDefinition(version="2.0", signatures=[Signature(path="file.html", hash="d4e5f6"),
                                                                 Signature(path="style.css", hash="12345")])]
        wordpress_version_list = VersionList(key="wordpress", producer="unittest", versions=versions)
        self.exporter._list_keys = MagicMock()
        self.exporter._list_keys.return_value = ["wordpress"]
        self.storage.version_list = [wordpress_version_list]

        self.exporter.export_wordpress("path")

        args, kwargs = self.exporter._dump.call_args
        file_name = args[0]
        wordpress_file_list = args[1]
        schema = args[2]
        self.assertEqual(file_name, "path/vane2_wordpress_versions.json")
        self.assertIsInstance(schema, FileListSchema)
        self.assertEqual(wordpress_file_list.key, "wordpress")
        self.assert_object_with_attribute_value_in_container("path", "file.html", wordpress_file_list.files)
        self.assert_object_with_attribute_value_in_container("path", "style.css", wordpress_file_list.files)
        path_file = self.get_object_with_attribute_value_in_container("path", "file.html", wordpress_file_list.files)
        style_file = self.get_object_with_attribute_value_in_container("path", "style.css", wordpress_file_list.files)
        path_version1_signature = self.get_object_with_attribute_value_in_container("hash", "a1b2c3",
                                                                                    path_file.signatures)
        path_version2_signature = self.get_object_with_attribute_value_in_container("hash", "d4e5f6",
                                                                                    path_file.signatures)
        style_signature = style_file.signatures[0]
        self.assertEqual(path_version1_signature.versions, ["1.0"])
        self.assertEqual(path_version2_signature.versions, ["2.0"])
        self.assertEqual(style_signature.versions, ["2.0"])

    def test_export_vulnerabilities_export_all_vuln_lists_in_one_file(self):
        plugin0_vuln0 = Vulnerability(id="0")
        plugin0_vuln1 = Vulnerability(id="1")
        plugin0_vuln_list = VulnerabilityList(producer="test", key="plugins/plugin0",
                                              vulnerabilities=[plugin0_vuln0, plugin0_vuln1])
        plugin1_vuln0 = Vulnerability(id="2")
        plugin1_vuln1 = Vulnerability(id="3")
        plugin1_vuln_list = VulnerabilityList(producer="test", key="plugins/plugin1",
                                              vulnerabilities=[plugin1_vuln0, plugin1_vuln1])
        theme_vuln0 = Vulnerability(id="4")
        theme_vuln1 = Vulnerability(id="5")
        theme_vuln_list = VulnerabilityList(producer="test", key="themes/theme",
                                            vulnerabilities=[theme_vuln0, theme_vuln1])
        wordpress_vuln0 = Vulnerability(id="6")
        wordpress_vuln1 = Vulnerability(id="7")
        wordpress_vuln_list = VulnerabilityList(producer="test", key="wordpress",
                                                vulnerabilities=[wordpress_vuln0, wordpress_vuln1])
        self.storage.add_vulnerability_lists({'plugins/plugin0': plugin0_vuln_list, 'plugins/plugin1': plugin1_vuln_list,
                                              'themes/theme': theme_vuln_list, 'wordpress': wordpress_vuln_list})

        self.exporter.export_vulnerabilities("path_to_dir")

        args, kwargs = self.exporter._dump.call_args
        vulnerability_list_group = args[1]
        self.assertEqual(vulnerability_list_group.producer, "vane2_export")
        vulnerability_lists = vulnerability_list_group.vulnerability_lists
        self.assert_object_with_attribute_value_in_container("key", "plugins/plugin0", vulnerability_lists)
        self.assert_object_with_attribute_value_in_container("key", "plugins/plugin1", vulnerability_lists)
        self.assert_object_with_attribute_value_in_container("key", "themes/theme", vulnerability_lists)
        self.assert_object_with_attribute_value_in_container("key", "wordpress", vulnerability_lists)
        exported_plugin0_vuln_list = self.get_object_with_attribute_value_in_container("key", "plugins/plugin0",
                                                                                       vulnerability_lists)
        exported_plugin1_vuln_list = self.get_object_with_attribute_value_in_container("key", "plugins/plugin1",
                                                                                       vulnerability_lists)
        exported_theme_vuln_list = self.get_object_with_attribute_value_in_container("key", "themes/theme",
                                                                                       vulnerability_lists)
        exported_wordpress_vuln_list = self.get_object_with_attribute_value_in_container("key", "wordpress",
                                                                                         vulnerability_lists)
        self.assertIn(plugin0_vuln0, exported_plugin0_vuln_list.vulnerabilities)
        self.assertIn(plugin0_vuln1, exported_plugin0_vuln_list.vulnerabilities)
        self.assertIn(plugin1_vuln0, exported_plugin1_vuln_list.vulnerabilities)
        self.assertIn(plugin1_vuln1, exported_plugin1_vuln_list.vulnerabilities)
        self.assertIn(theme_vuln0, exported_theme_vuln_list.vulnerabilities)
        self.assertIn(theme_vuln1, exported_theme_vuln_list.vulnerabilities)
        self.assertIn(wordpress_vuln0, exported_wordpress_vuln_list.vulnerabilities)
        self.assertIn(wordpress_vuln1, exported_wordpress_vuln_list.vulnerabilities)

    def test_regroup_vulnerabilities_of_key_in_one_list(self):
        plugin_vuln0 = Vulnerability(id="0")
        plugin_vuln1 = Vulnerability(id="1")
        self.storage.vulnerability_lists['plugins/plugin/producer0'] = VulnerabilityList(
            producer="producer0", key="plugins/plugin", vulnerabilities=[plugin_vuln0])
        self.storage.vulnerability_lists['plugins/plugin/producer1'] = VulnerabilityList(
            producer="producer1", key="plugins/plugin", vulnerabilities=[plugin_vuln1])

        plugin_vuln_list = self.exporter._regroup_vulnerabilities_of_key_in_one_list("plugins/plugin")

        self.assertIn(plugin_vuln0, plugin_vuln_list.vulnerabilities)
        self.assertIn(plugin_vuln1, plugin_vuln_list.vulnerabilities)

    def test_list_all_keys_yield_key_if_versions_file_is_present(self):
        self.storage.content = [("plugins/plugin0", "dirpath", "dirnames", ["META.json", "versions.json"]),
                                          ("plugins/plugin1", "dirpath", "dirnames", ["META.json"]),
                                          ("themes/theme0", "dirpath", "dirnames", ["META.json", "versions.json"]),
                                          ("themes/theme1", "dirpath", "dirnames", ["META.json"])]

        for key in self.exporter._list_all_keys("plugins"):
            self.assertEqual(key, "plugins/plugin0")

        for key in self.exporter._list_all_keys("themes"):
            self.assertEqual(key, "themes/theme0")

    def test_list_vulnerable_list_keys_of_plugins_or_themes_with_vuln(self):
        files = ["versions.json"]
        self.storage.vulnerability_lists = {"plugins/plugin1": ["vuln"], "themes/theme1": ["vuln"]}
        self.storage.content = [("plugins/plugin0", "dirpath", "dirnames", files),
                                ("plugins/plugin1", "dirpath", "dirnames", files),
                                ("themes/theme0", "dirpath", "dirnames", files),
                                ("themes/theme1", "dirpath", "dirnames", files)]

        plugin_key = list(self.exporter._list_vulnerable("plugins"))
        theme_key = list(self.exporter._list_vulnerable("themes"))
        self.assertEqual(plugin_key, ["plugins/plugin1"])
        self.assertEqual(theme_key, ["themes/theme1"])

    def test_list_popular_list_keys_of_popular_plugins_or_themes(self):
        files = ["META.json", "versions.json"]
        self.storage.meta_list = [Meta(key='plugins/plugin0', is_popular=True),
                                  Meta(key='plugins/plugin1', is_popular=False),
                                  Meta(key='themes/theme0', is_popular=True),
                                  Meta(key='themes/theme1', is_popular=False)]
        self.storage.content = [("plugins/plugin0", "dirpath", "dirnames", files),
                                ("plugins/plugin1", "dirpath", "dirnames", files),
                                ("themes/theme0", "dirpath", "dirnames", files),
                                ("themes/theme1", "dirpath", "dirnames", files)]

        plugin_key = list(self.exporter._list_popular("plugins"))
        theme_key = list(self.exporter._list_popular("themes"))
        self.assertEqual(plugin_key, ["plugins/plugin0"])
        self.assertEqual(theme_key, ["themes/theme0"])

    def assert_object_with_attribute_value_in_container(self, attribute, value, container):
        self.assertIsNotNone(self.get_object_with_attribute_value_in_container(attribute, value, container))

    def get_object_with_attribute_value_in_container(self, attribute, value, container):
        for _object in container:
            if hasattr(_object, attribute):
                if getattr(_object, attribute) == value:
                    return _object
        return None


class FakeStorage:

    def __init__(self, version_list, meta_list=None):
        self.version_list = version_list or []
        self.meta_list = meta_list or []
        self.content = []
        self.vulnerability_lists = {}

    def list_meta(self, key):
        for meta in self.meta_list:
            if key in meta.key:
                yield meta

    def list_vulnerabilities(self, key):
        for _key in self.vulnerability_lists.keys():
            if _key.startswith(key):
                yield self.vulnerability_lists[_key]

    def walk(self, key):
        for _key, path, dirnames, files in self.content:
            if key in _key:
                yield _key, path, dirnames, files

    def read_versions(self, key):
        for version_list in self.version_list:
            if version_list.key == key:
                return version_list
        return None

    def read_meta(self, key):
        for meta in self.meta_list:
            if meta.key == key:
                return meta
        return None

    def add_vulnerability_lists(self, vulnerability_lists):
        self.vulnerability_lists = vulnerability_lists
        for key in vulnerability_lists.keys():
            self.content.append((key, "path", "dirname", ["versions.json"]))
