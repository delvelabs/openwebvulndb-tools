import asyncio
import aiohttp

from ..common.logs import logger
from ..common.parallel import ParallelWorker
from .parser import PluginParser, ThemeParser
from .errors import RepositoryUnreachable, SoftwareNotFound
from ..common.errors import ExecutionFailure


class WordPressRepository:

    def __init__(self, loop, storage=None, aiohttp_session=None, repository_checker=None, subversion=None):
        self.loop = loop
        self.session = aiohttp_session
        self.checker = repository_checker
        self.plugin_parser = PluginParser()
        self.theme_parser = ThemeParser()
        self.storage = storage
        self.subversion = subversion

    async def enumerate_plugins(self):
        return await self.enumerate_subversion("https://plugins.svn.wordpress.org/")

    async def enumerate_themes(self):
        return await self.enumerate_subversion("https://themes.svn.wordpress.org/")

    async def enumerate_subversion(self, url):
        try:
            lines = await self.subversion.ls(url)
            return {line.strip("/") for line in lines}
        except ExecutionFailure:
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
        return self.storage.list_directories("plugins") | set(self.storage.read_lines('plugins-ignore.txt'))

    def current_themes(self):
        return self.storage.list_directories("themes") | set(self.storage.read_lines('themes-ignore.txt'))

    async def perform_plugin_lookup(self):
        return await self.perform_lookup(self.current_plugins,
                                         self.enumerate_plugins,
                                         self.fetch_plugin,
                                         self.plugin_parser.create_meta)

    async def perform_theme_lookup(self):
        return await self.perform_lookup(self.current_themes,
                                         self.enumerate_themes,
                                         self.fetch_theme,
                                         self.theme_parser.create_meta)

    async def perform_lookup(self, current, obtain, fetch, default):
        current = current()
        repository = await obtain()
        new = repository - current

        logger.info("Found {total} entries, processing {new} new ones.".format(total=len(repository), new=len(new)))

        fetch_worker = ParallelWorker(5, loop=self.loop)
        check_worker = ParallelWorker(5, loop=self.loop)

        async def do_check_content(slug, meta):
            for repo in meta.repositories:
                if await self.checker.has_content(repo):
                    self.storage.write_meta(meta)
                    return

            group = meta.key.partition("/")[0]
            self.storage.append("{}-ignore.txt".format(group), slug)

        async def do_fetch(slug):
            try:
                meta = await fetch(slug)
                self.storage.write_meta(meta)
            except RepositoryUnreachable as e:
                logger.warn("Unable to reach repository for {slug}: {e}".format(slug=slug, e=e))
            except SoftwareNotFound as e:
                logger.debug("Entry not found for {slug}: {e}".format(slug=slug, e=e))
                meta = default(slug=slug)
                await check_worker.request(do_check_content, slug, meta)

        for slug in new:
            await fetch_worker.request(do_fetch, slug)

        await fetch_worker.wait()
        await check_worker.wait()
