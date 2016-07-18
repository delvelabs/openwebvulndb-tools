import asyncio
import os
import aiohttp

from .parser import PluginParser
from .errors import RepositoryUnreachable, PluginNotFound


class WordPressRepository:

    def __init__(self, loop, storage=None):
        self.loop = loop
        self.session = aiohttp.ClientSession(loop=loop)
        self.parser = PluginParser()
        self.storage = storage

    async def enumerate_plugins(self):
        command = self.get_enumerate_command()
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
        try:
            url = 'https://api.wordpress.org/plugins/info/1.0/{slug}.json'.format(slug=plugin_name)
            response = await self.session.get(url)
            data = await response.text()
            response.close()

            return self.parser.parse(data)
        except PluginNotFound:
            raise
        except:
            raise RepositoryUnreachable('Failed to obtain the plugin information')

    def current_plugins(self):
        return self.storage.list_directories("plugins")

    def get_enumerate_command(self):
        return ["svn", "ls", "https://plugins.svn.wordpress.org/"]

    async def perform_lookup(self):
        current = self.current_plugins()
        repository = await self.enumerate_plugins()
        new = repository - current

        for plugin in new:
            try:
                meta = await self.fetch_plugin(plugin)
                self.storage.write_meta(meta)
            except RepositoryUnreachable:
                pass
            except PluginNotFound:
                pass
