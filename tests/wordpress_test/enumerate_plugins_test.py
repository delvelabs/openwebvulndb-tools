import subprocess
import asyncio

from unittest import TestCase
from unittest.mock import MagicMock, patch, call
from fixtures import read_file, file_path, async_test, fake_future
from openwebvulndb.tools.wordpress.repository import WordPressRepository, RepositoryUnreachable
from openwebvulndb.models import Meta


class EnumeratePluginsTest(TestCase):

    @async_test()
    async def test_default_command(self, loop):
       handler = WordPressRepository(loop=loop)
       self.assertEqual(handler.get_enumerate_command(), ["svn", "ls", "https://plugins.svn.wordpress.org/"])

    @async_test()
    async def test_obtain_list(self, loop):
       handler = WordPressRepository(loop=loop)

       handler.get_enumerate_command = lambda: ["cat", file_path(__file__, "plugins.svn.txt")]
       plugins = await handler.enumerate_plugins()

       self.assertEqual(plugins, {'aioseo-fix', 'easy-book-reviews', 'isd-wordpress-rss-feed-plugin', 'picashow', 'wp-auto-hotel-finder'})

    @async_test()
    async def test_failure_to_list(self, loop):
        handler = WordPressRepository(loop=loop)

        handler.get_enumerate_command = lambda: ["svn", "ls", "https://localhost:1234/"]
        with self.assertRaises(RepositoryUnreachable):
            await handler.enumerate_plugins()

    @async_test()
    async def test_read_path_empty(self, loop):
        empty = file_path(__file__, '')
        with_data = file_path(__file__, '..')

        handler = WordPressRepository(loop=loop, path=empty)
        self.assertEqual(handler.current_plugins() - {'__pycache__'}, set())

    @async_test()
    async def test_read_path_with_data(self, loop):
        with_data = file_path(__file__, '..')

        handler = WordPressRepository(loop=loop, path=with_data)
        self.assertIn("wordpress_test", handler.current_plugins())

    @async_test()
    async def test_no_calls_made_when_nothing_new(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.assert_not_called()
        await handler.perform_lookup()

    @async_test()
    async def test_calls_made_when_new_plugins_arrive(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.return_value = fake_future(Meta(key="a", name="A"), loop)
        await handler.perform_lookup()

        handler.fetch_plugin.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
