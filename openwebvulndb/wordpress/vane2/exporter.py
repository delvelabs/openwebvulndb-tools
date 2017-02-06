from openwebvulndb.common.models import FileListGroup
from openwebvulndb.common.serialize import serialize
from openwebvulndb.common.schemas import FileListGroupSchema
from .versionrebuild import VersionRebuild


class Exporter:

    def __init__(self, storage):
        self.storage = storage
        self.plugins_list = FileListGroup(key="plugins", producer="Vane2Export")
        self.themes_list = FileListGroup(key="themes", producer="Vane2Export")

    def export_plugins(self, only_popular=False, only_vulnerable=False):
        version_rebuild = VersionRebuild(self.storage)
        for plugin_key in self._list_keys("plugins", only_popular, only_vulnerable):
            version_rebuild.update(plugin_key)
            plugin = version_rebuild.file_list
            self.plugins_list.file_lists.append(plugin)

    def export_themes(self, only_popular=False, only_vulnerable=False):
        version_rebuild = VersionRebuild(self.storage)
        for theme_key in self._list_keys("themes", only_popular, only_vulnerable):
            version_rebuild.update(theme_key)
            theme_files = version_rebuild.file_list
            self.themes_list.file_lists.append(theme_files)

    def dump_plugins(self):
        return serialize(FileListGroupSchema(), self.plugins_list)

    def _list_keys(self, key, only_popular=False, only_vulnerable=False):
        if only_popular:
            yield from self._list_popular(key)
        elif only_vulnerable:
            yield from self._list_vulnerable(key)
        else:
            yield from self._list_all_keys(key)

    def _list_vulnerable(self, key):
        for _key, files in self._walk(key):
            if self._contains_vuln_file(files):
                yield _key

    def _list_popular(self, key):
        for _key, files in self._walk(key):
            if self._is_popular(_key, files):
                yield _key

    def _list_all_keys(self, key):
        for _key, files in self._walk(key):
            yield _key

    def _list_popular_plugins_keys(self):
        for key, path, dirnames, files in self.storage.walk("plugins"):
            if "versions.json" in files and self._is_popular(key, files):
                yield key

    def _list_all_plugins_keys(self):
        for key, path, dirnames, files in self.storage.walk("plugins"):
            if "versions.json" in files:
                yield key

    def _is_popular(self, key, files):
        if "META.json" in files:
            meta = self.storage.read_meta(key)
            return meta.is_popular
        return False

    def _contains_vuln_file(self, files):
        for file in files:
            if file.startswith("vuln-") and file.endswith(".json"):
                return True
        return False

    def _walk(self, key):
        for key, path, dirnames, files in self.storage.walk(key):
            if "versions.json" in files:
                yield key, files
