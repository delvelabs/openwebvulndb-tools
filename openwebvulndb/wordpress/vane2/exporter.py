from openwebvulndb.common.models import FileListGroup
from openwebvulndb.common.serialize import serialize
from openwebvulndb.common.schemas import FileListGroupSchema
from .versionrebuild import VersionRebuild


class Exporter:

    def __init__(self, storage):
        self.storage = storage
        self.plugins_list = FileListGroup(key="plugins", producer="Vane2Export")

    def export_plugins(self, only_popular=False):
        version_rebuild = VersionRebuild(self.storage)
        for plugin_key in self._list_plugins_keys(only_popular):
            version_rebuild.update(plugin_key)
            plugin = version_rebuild.file_list
            self.plugins_list.file_lists.append(plugin)

    def dump_plugins(self):
        input("press key to continue")
        return serialize(FileListGroupSchema(), self.plugins_list)

    def _list_plugins_keys(self, only_popular=False):
        if only_popular:
            yield from self._list_popular_plugins_keys()
        else:
            yield from self._list_all_plugins_keys()

    def _list_popular_plugins_keys(self):
        for key, path, dirnames, files in self.storage.walk("plugins"):
            if "versions.json" in files and self._is_plugin_popular(key, files):
                yield key

    def _list_all_plugins_keys(self):
        for key, path, dirnames, files in self.storage.walk("plugins"):
            if "versions.json" in files:
                yield key

    def _is_plugin_popular(self, key, files):
        if "META.json" in files:
            meta = self.storage.read_meta(key)
            return meta.is_popular
        return False
