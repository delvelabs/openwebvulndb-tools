import asyncio
import os

from .errors import RepositoryUnreachable
from ...common.config import DEFAULT_PATH


class WordPressRepository:

    def __init__(self, loop, path=DEFAULT_PATH):
        self.loop = loop
        self.path = path

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

    def current_plugins(self):
        return {entry.name for entry in os.scandir(self.path) if entry.is_dir()}

    def get_enumerate_command(self):
        return ["svn", "ls", "https://plugins.svn.wordpress.org/"]

    async def perform_lookup(self):
        current = self.current_plugins()
        repository = await self.enumerate_plugins()
        new = repository - current

        for plugin in new:
            meta = await self.fetch_plugin(plugin)
