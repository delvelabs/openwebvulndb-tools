import asyncio
import aiohttp

from ..common.logs import logger
from .parser import PluginParser, ThemeParser
from .errors import RepositoryUnreachable, SoftwareNotFound


class WordPressRepository:

    def __init__(self, loop, storage=None, httpsession=None):
        self.loop = loop
        self.session = httpsession
        self.plugin_parser = PluginParser()
        self.theme_parser = ThemeParser()
        self.storage = storage

    async def enumerate_plugins(self):
        command = self.get_enumerate_plugins_command()
        return await self.enumerate_subversion(command)

    async def enumerate_themes(self):
        command = self.get_enumerate_themes_command()
        return await self.enumerate_subversion(command)

    async def enumerate_subversion(self, command):
        process = await asyncio.create_subprocess_exec(
            *command,
            loop=self.loop,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL
        )

        out = set()
        while not process.stdout.at_eof():
            line = await process.stdout.readline()
            if line != b'':
                out.add(line.decode('utf8').strip("\n/"))

        code = await process.wait()
        if code == 0:
            return out
        else:
            raise RepositoryUnreachable()

    async def fetch_plugin(self, plugin_name):
        url = 'https://api.wordpress.org/plugins/info/1.0/{slug}.json'.format(slug=plugin_name)
        return await self.fetch(url, self.plugin_parser)

    async def fetch_theme(self, plugin_name):
        url = 'https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]={slug}'.format(
            slug=plugin_name)

        return await self.fetch(url, self.theme_parser)

    async def fetch(self, url, parser):
        try:
            response = await self.session.get(url)
            data = await response.text()
            response.close()

            return parser.parse(data)
        except SoftwareNotFound:
            raise
        except:
            raise RepositoryUnreachable('Failed to obtain the plugin information')

    def current_plugins(self):
        return self.storage.list_directories("plugins")

    def current_themes(self):
        return self.storage.list_directories("themes")

    def get_enumerate_plugins_command(self):
        return ["svn", "ls", "https://plugins.svn.wordpress.org/"]

    def get_enumerate_themes_command(self):
        return ["svn", "ls", "https://themes.svn.wordpress.org/"]

    async def perform_plugin_lookup(self):
        return await self.perform_lookup(self.current_plugins,
                                         self.enumerate_plugins,
                                         self.fetch_plugin)

    async def perform_theme_lookup(self):
        return await self.perform_lookup(self.current_themes,
                                         self.enumerate_themes,
                                         self.fetch_theme)

    async def perform_lookup(self, current, obtain, fetch):
        current = current()
        repository = await obtain()
        new = repository - current

        logger.info("Found {total} entries, processing {new} new ones.".format(total=len(repository), new=len(new)))

        for item in new:
            try:
                meta = await fetch(item)
                self.storage.write_meta(meta)
            except RepositoryUnreachable as e:
                logger.warn("Unable to reach repository for {item}: {e}".format(item=item, e=e))
            except SoftwareNotFound as e:
                logger.info("Entry not found for {item}: {e}".format(item=item, e=e))
