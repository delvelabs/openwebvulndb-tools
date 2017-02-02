from unittest import TestCase
from unittest.mock import MagicMock
from openwebvulndb.common.models import VersionList, VersionDefinition, Signature, Meta
from openwebvulndb.wordpress.vane2.exporter import Exporter
from openwebvulndb.common.schemas import FileListGroupSchema


class ExporterTest(TestCase):

    def setUp(self):
        self.storage = FakeStorage(None, None)
        self.exporter = Exporter(self.storage)

    def test_export_plugins_regroup_plugins_in_one_file(self):
        plugin0_versions_list = VersionList(key="plugin0", producer="unittest")
        plugin1_versions_list = VersionList(key="plugin1", producer="unittest")
        self.exporter._list_plugins_keys = MagicMock()
        self.exporter._list_plugins_keys.return_value = ["plugin0", "plugin1"]
        self.storage.plugins_versions_list = [plugin0_versions_list, plugin1_versions_list]

        self.exporter.export_plugins()

        plugins = self.exporter.plugins_list
        self.assertEqual(plugins.key, "plugins")
        self.assertEqual(plugins.producer, "Vane2Export")
        self.assert_object_with_attribute_value_in_container("key", "plugin0", plugins.file_lists)
        self.assert_object_with_attribute_value_in_container("producer", "Vane2Export", plugins.file_lists)
        self.assert_object_with_attribute_value_in_container("key", "plugin1", plugins.file_lists)

    def test_export_plugins_create_file_list_from_version_list_for_plugin(self):
        versions = [VersionDefinition(version="1.0", signatures=[Signature(path="file.html", hash="a1b2c3")]),
                    VersionDefinition(version="2.0", signatures=[Signature(path="file.html", hash="d4e5f6"),
                                                                 Signature(path="style.css", hash="12345")])]
        plugin_versions_list = VersionList(key="my-plugin", producer="unittest", versions=versions)
        self.exporter._list_plugins_keys = MagicMock()
        self.exporter._list_plugins_keys.return_value = ["my-plugin"]
        self.storage.plugins_versions_list = [plugin_versions_list]

        self.exporter.export_plugins()

        plugins = self.exporter.plugins_list
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

    def test_list_plugins_keys(self):
        files = ["versions.json"]
        self.storage.walk.return_value = [("plugins/plugin0", "dirpath", "dirnames", files),
                                          ("plugins/plugin1", "dirpath", "dirnames", files)]

        plugins_keys = list(self.exporter._list_plugins_keys())

        self.assertIn("plugins/plugin0", plugins_keys)
        self.assertIn("plugins/plugin1", plugins_keys)

    def test_list_plugins_keys_list_popular_plugins(self):
        self.storage.meta_list = [Meta(key='plugins/plugin0', is_popular=True),
                                  Meta(key='plugins/plugin1', is_popular=False)]
        files = ["META.json", "versions.json"]
        self.storage.walk.return_value = [("plugins/plugin0", "dirpath", "dirnames", files),
                                     ("plugins/plugin1", "dirpath", "dirnames", files)]

        plugins_keys = list(self.exporter._list_plugins_keys(only_popular=True))

        self.assertIn("plugins/plugin0", plugins_keys)
        self.assertNotIn("plugins/plugin1", plugins_keys)

    def test_list_plugins_keys_skip_plugins_without_version_file(self):
        self.storage.meta_list = [Meta(key='plugins/plugin0'),
                                  Meta(key='plugins/plugin1')]
        self.storage.walk.return_value = [("plugins/plugin0", "dirpath", "dirnames", ["META.json", "versions.json"]),
                                          ("plugins/plugin1", "dirpath", "dirnames", ["META.json"])]

        plugins_keys = list(self.exporter._list_plugins_keys())

        self.assertIn("plugins/plugin0", plugins_keys)
        self.assertNotIn("plugins/plugin1", plugins_keys)

    def assert_object_with_attribute_value_in_container(self, attribute, value, container):
        if self.get_object_with_attribute_value_in_container(attribute, value, container) is None:
            self.fail("No object with has an attribute '{0}' with the value '{1}' in '{2}'".format(attribute, value,
                                                                                                   container))

    def get_object_with_attribute_value_in_container(self, attribute, value, container):
        for _object in container:
            if hasattr(_object, attribute):
                if getattr(_object, attribute) == value:
                    return _object
        return None


class FakeStorage:

    def __init__(self, plugins_versions_list, meta_list=None):
        self.plugins_versions_list = plugins_versions_list or []
        self.meta_list = meta_list or []
        self.walk = MagicMock()

    def read_versions(self, key):
        for version_list in self.plugins_versions_list:
            if version_list.key == key:
                return version_list
        return None

    def read_meta(self, key):
        for meta in self.meta_list:
            if meta.key == key:
                return meta
        return None
