import asyncio
from os.path import join
from .errors import ExecutionFailure


class RepositoryChecker:

    def __init__(self, subversion=None):
        self.subversion = subversion
        self.handlers = dict(subversion=self.svn_has_content)

    async def has_content(self, repository):
        """
        Determines if the provided repository contains content or if the entry is bogus.

        Subversion:
           - Typical structure, tagged revisions
           - Direct version list
        """
        try:
            return await self.handlers[repository.type](repository)
        except KeyError:
            return False

    async def svn_has_content(self, repository):
        base_content = await self.subversion.ls(repository.location)
        if self.is_classic_structure(base_content):
            tags = await self.subversion.ls(join(repository.location, 'tags'))
            return len(tags) > 0

        return len(base_content) > 0

    def is_classic_structure(self, content):
        return "tags/" in content


class Subversion:
    def __init__(self, loop=None):
        self.loop = loop

    @staticmethod
    def build_ls(url):
        return ["svn", "ls", url]

    async def ls(self, url):
        try:
            command = self.build_ls(url)
            return await asyncio.wait_for(self.read_lines(command), 30.0, loop=self.loop)
        except asyncio.TimeoutError:
            raise ExecutionFailed('Timeout reached')

    async def read_lines(self, command):
        process = await asyncio.create_subprocess_exec(
            *command,
            loop=self.loop,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL
        )

        out = []
        while not process.stdout.at_eof():
            line = await process.stdout.readline()
            if line != b'':
                out.append(line.decode('utf8').strip("\n"))

        code = await process.wait()
        if code == 0:
            return out

        raise ExecutionFailure()
