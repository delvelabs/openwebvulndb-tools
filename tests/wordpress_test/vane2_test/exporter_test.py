from unittest import TestCase
from unittest.mock import MagicMock, call
from openwebvulndb.common.models import VersionList, VersionDefinition, Signature, Meta
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

    def test_walk_yield_keys_and_files_in_storage_if_versions_file_is_present(self):
        self.storage.content = [("plugins/plugin0", "dirpath", "dirnames", ["META.json", "versions.json"]),
                                          ("plugins/plugin1", "dirpath", "dirnames", ["META.json"]),
                                          ("themes/theme0", "dirpath", "dirnames", ["META.json", "versions.json"]),
                                          ("themes/theme1", "dirpath", "dirnames", ["META.json"])]

        for key, files in self.exporter._walk("plugins"):
            self.assertEqual(key, "plugins/plugin0")
            self.assertEqual(files, ["META.json", "versions.json"])

        for key, files in self.exporter._walk("themes"):
            self.assertEqual(key, "themes/theme0")
            self.assertEqual(files, ["META.json", "versions.json"])

    def test_list_vulnerable_list_keys_of_plugins_or_themes_with_vuln(self):
        files = ["META.json", "versions.json"]
        vuln_files0 = ["META.json", "versions.json", "vuln-cvereader.json"]
        vuln_files1 = ["META.json", "versions.json", "vuln-securityfocus.json"]
        self.storage.content = [("plugins/plugin0", "dirpath", "dirnames", files),
                                ("plugins/plugin1", "dirpath", "dirnames", vuln_files0),
                                ("themes/theme0", "dirpath", "dirnames", files),
                                ("themes/theme1", "dirpath", "dirnames", vuln_files1)]

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

    def test_list_all_keys_list_all_keys_within_key(self):
        files = ["META.json", "versions.json"]
        self.storage.content = [("plugins/plugin0", "dirpath", "dirnames", files),
                                ("plugins/plugin1", "dirpath", "dirnames", files),
                                ("themes/theme0", "dirpath", "dirnames", files),
                                ("themes/theme1", "dirpath", "dirnames", files)]

        plugin_keys = list(self.exporter._list_all_keys("plugins"))
        theme_keys = list(self.exporter._list_all_keys("themes"))
        self.assertIn("plugins/plugin0", plugin_keys)
        self.assertIn("plugins/plugin1", plugin_keys)
        self.assertEqual(len(plugin_keys), 2)
        self.assertIn("themes/theme0", theme_keys)
        self.assertIn("themes/theme1", theme_keys)
        self.assertEqual(len(theme_keys), 2)

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
