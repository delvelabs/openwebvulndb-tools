from aiohttp import ClientResponse, ClientTimeoutError

from unittest import TestCase
from unittest.mock import MagicMock, call
from fixtures import read_file, file_path, async_test, fake_future
from openwebvulndb.wordpress.repository import WordPressRepository, RepositoryUnreachable
from openwebvulndb.wordpress.errors import PluginNotFound
from openwebvulndb.common import Meta


class EnumeratePluginsTest(TestCase):

    @async_test()
    async def test_default_command(self, loop):
        handler = WordPressRepository(loop=loop)
        self.assertEqual(handler.get_enumerate_plugins_command(), ["svn", "ls", "https://plugins.svn.wordpress.org/"])

    @async_test()
    async def test_obtain_list(self, loop):
        handler = WordPressRepository(loop=loop)

        handler.get_enumerate_plugins_command = lambda: ["cat", file_path(__file__, "plugins.svn.txt")]
        plugins = await handler.enumerate_plugins()

        self.assertEqual(plugins, {'aioseo-fix', 'easy-book-reviews', 'isd-wordpress-rss-feed-plugin', 'picashow',
                                   'wp-auto-hotel-finder'})

    @async_test()
    async def test_failure_to_list(self, loop):
        handler = WordPressRepository(loop=loop)

        handler.get_enumerate_plugins_command = lambda: ["svn", "ls", "https://localhost:1234/"]
        with self.assertRaises(RepositoryUnreachable):
            await handler.enumerate_plugins()

    @async_test()
    async def test_read_path_empty(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = set()

        self.assertEqual(handler.current_plugins(), set())
        handler.storage.list_directories.assert_called_with('plugins')

    @async_test()
    async def test_read_path_with_data(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = {"wordpress_test"}
        self.assertIn("wordpress_test", handler.current_plugins())
        handler.storage.list_directories.assert_called_with('plugins')

    @async_test()
    async def test_no_calls_made_when_nothing_new(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.assert_not_called()
        await handler.perform_plugin_lookup()

    @async_test()
    async def test_calls_made_when_new_plugins_arrive(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.return_value = fake_future(Meta(key="a", name="A"), loop)
        await handler.perform_plugin_lookup()

        handler.fetch_plugin.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
        handler.storage.write_meta.assert_called_with(Meta(key="a", name="A"))

    @async_test()
    async def test_when_fetch_fails(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.side_effect = PluginNotFound('A side effect!')
        await handler.perform_plugin_lookup()

        handler.fetch_plugin.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)

    @async_test()
    async def test_fetch_plugin_data(self, loop):
        my_response = ClientResponse('GET', 'https://api.wordpress.org/plugins/info/1.0/better-wp-security.json')
        my_response.status = 200
        my_response.headers = {'Content-Type': 'application/json'}
        my_response._content = read_file(__file__, 'better-wp-security.json').encode('utf8')

        handler = WordPressRepository(loop=loop)
        handler.session.close()  # We replace the implementation
        handler.session = MagicMock()
        handler.session.get.return_value = fake_future(my_response, loop)

        plugin = await handler.fetch_plugin('better-wp-security')

        handler.session.get.assert_called_with('https://api.wordpress.org/plugins/info/1.0/better-wp-security.json')
        self.assertEqual('plugins/better-wp-security', plugin.key)

    @async_test()
    async def test_fetch_plugin_fails_to_request(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.session.close()  # We replace the implementation
        handler.session = MagicMock()
        handler.session.get.side_effect = ClientTimeoutError()

        with self.assertRaises(RepositoryUnreachable):
            await handler.fetch_plugin('better-wp-security')

        handler.session.get.assert_called_with('https://api.wordpress.org/plugins/info/1.0/better-wp-security.json')
