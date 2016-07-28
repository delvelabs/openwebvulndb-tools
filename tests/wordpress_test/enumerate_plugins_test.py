from aiohttp import ClientResponse, ClientTimeoutError

from unittest import TestCase
from unittest.mock import MagicMock, call
from fixtures import read_file, async_test, fake_future
from openwebvulndb.wordpress.repository import WordPressRepository, RepositoryUnreachable
from openwebvulndb.wordpress.errors import PluginNotFound
from openwebvulndb.common import Meta, Repository
from openwebvulndb.common.errors import ExecutionFailure


class EnumeratePluginsTest(TestCase):

    @async_test()
    async def test_obtain_list(self, loop):
        handler = WordPressRepository(loop=loop, subversion=MagicMock())
        handler.subversion.ls.return_value = fake_future([
            'aioseo-fix/',
            'easy-book-reviews/',
            'isd-wordpress-rss-feed-plugin/',
            'picashow/',
            'wp-auto-hotel-finder/',
        ], loop)

        plugins = await handler.enumerate_plugins()
        handler.subversion.ls.assert_called_with("https://plugins.svn.wordpress.org/")

        self.assertEqual(plugins, {'aioseo-fix', 'easy-book-reviews', 'isd-wordpress-rss-feed-plugin', 'picashow',
                                   'wp-auto-hotel-finder'})

    @async_test()
    async def test_failure_to_list(self, loop):
        handler = WordPressRepository(loop=loop, subversion=MagicMock())
        handler.subversion.ls.side_effect = ExecutionFailure()

        with self.assertRaises(RepositoryUnreachable):
            await handler.enumerate_plugins()

    @async_test()
    async def test_read_path_empty(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = set()
        handler.storage.read_lines.return_value = []

        self.assertEqual(handler.current_plugins(), set())
        handler.storage.list_directories.assert_called_with('plugins')
        handler.storage.read_lines.assert_called_with('plugins-ignore.txt')

    @async_test()
    async def test_read_path_with_data(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = {"wordpress_test"}
        handler.storage.read_lines.return_value = []
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
        handler = WordPressRepository(loop=loop, storage=MagicMock(), repository_checker=MagicMock())
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.side_effect = PluginNotFound('A side effect!')
        handler.checker.has_content.return_value = fake_future(True, loop)
        await handler.perform_plugin_lookup()

        handler.fetch_plugin.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
        handler.storage.write_meta.assert_has_calls([
            call(handler.plugin_parser.create_meta(slug="a")),
            call(handler.plugin_parser.create_meta(slug="b")),
        ], any_order=True)
        handler.checker.has_content.assert_has_calls([
            call(Repository(type="subversion", location="https://plugins.svn.wordpress.org/a/")),
            call(Repository(type="subversion", location="https://plugins.svn.wordpress.org/b/")),
        ], any_order=True)

    @async_test()
    async def test_when_fetch_fails_bad_repo(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock(), repository_checker=MagicMock())
        handler.current_plugins = lambda: {'hello-world', 'unknown-plugin'}
        handler.enumerate_plugins = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_plugin = MagicMock()
        handler.fetch_plugin.side_effect = PluginNotFound('A side effect!')
        handler.checker.has_content.return_value = fake_future(False, loop)
        await handler.perform_plugin_lookup()

        handler.fetch_plugin.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
        handler.storage.write_meta.assert_not_called()
        handler.checker.has_content.assert_has_calls([
            call(Repository(type="subversion", location="https://plugins.svn.wordpress.org/a/")),
            call(Repository(type="subversion", location="https://plugins.svn.wordpress.org/b/")),
        ], any_order=True)
        handler.storage.append.assert_has_calls([
            call("plugins-ignore.txt", "a"),
            call("plugins-ignore.txt", "b"),
        ], any_order=True)

    @async_test()
    async def test_fetch_plugin_data(self, loop):
        my_response = ClientResponse('GET', 'https://api.wordpress.org/plugins/info/1.0/better-wp-security.json')
        my_response.status = 200
        my_response.headers = {'Content-Type': 'application/json'}
        my_response._content = read_file(__file__, 'better-wp-security.json').encode('utf8')

        handler = WordPressRepository(loop=loop, aiohttp_session=MagicMock())
        handler.session.get.return_value = fake_future(my_response, loop)

        plugin = await handler.fetch_plugin('better-wp-security')

        handler.session.get.assert_called_with('https://api.wordpress.org/plugins/info/1.0/better-wp-security.json')
        self.assertEqual('plugins/better-wp-security', plugin.key)

    @async_test()
    async def test_fetch_plugin_fails_to_request(self, loop):
        handler = WordPressRepository(loop=loop, aiohttp_session=MagicMock())
        handler.session.get.side_effect = ClientTimeoutError()

        with self.assertRaises(RepositoryUnreachable):
            await handler.fetch_plugin('better-wp-security')

        handler.session.get.assert_called_with('https://api.wordpress.org/plugins/info/1.0/better-wp-security.json')
