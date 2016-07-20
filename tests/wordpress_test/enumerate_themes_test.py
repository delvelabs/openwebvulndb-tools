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
        self.assertEqual(handler.get_enumerate_themes_command(), ["svn", "ls", "https://themes.svn.wordpress.org/"])

    @async_test()
    async def test_obtain_list(self, loop):
        handler = WordPressRepository(loop=loop)

        handler.get_enumerate_themes_command = lambda: ["cat", file_path(__file__, "themes.svn.txt")]
        themes = await handler.enumerate_themes()

        self.assertEqual(themes, {'a-class-act-ny', 'skt-bakery', 'the-modern-accounting-firm'})

    @async_test()
    async def test_failure_to_list(self, loop):
        handler = WordPressRepository(loop=loop)

        handler.get_enumerate_themes_command = lambda: ["svn", "ls", "https://localhost:1234/"]
        with self.assertRaises(RepositoryUnreachable):
            await handler.enumerate_themes()

    @async_test()
    async def test_read_path_empty(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = set()

        self.assertEqual(handler.current_themes(), set())
        handler.storage.list_directories.assert_called_with('themes')

    @async_test()
    async def test_read_path_with_data(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = {"wordpress_test"}
        self.assertIn("wordpress_test", handler.current_themes())
        handler.storage.list_directories.assert_called_with('themes')

    @async_test()
    async def test_no_calls_made_when_nothing_new(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.current_themes = lambda: {'hello-world', 'unknown-theme'}
        handler.enumerate_themes = lambda: fake_future({'hello-world'}, loop)

        handler.fetch_theme = MagicMock()
        handler.fetch_theme.assert_not_called()
        await handler.perform_theme_lookup()

    @async_test()
    async def test_calls_made_when_new_themes_arrive(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.current_themes = lambda: {'hello-world', 'unknown-theme'}
        handler.enumerate_themes = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_theme = MagicMock()
        handler.fetch_theme.return_value = fake_future(Meta(key="a", name="A"), loop)
        await handler.perform_theme_lookup()

        handler.fetch_theme.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
        handler.storage.write_meta.assert_called_with(Meta(key="a", name="A"))

    @async_test()
    async def test_when_fetch_fails(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.current_themes = lambda: {'hello-world', 'unknown-theme'}
        handler.enumerate_themes = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_theme = MagicMock()
        handler.fetch_theme.side_effect = PluginNotFound('A side effect!')
        await handler.perform_theme_lookup()

        handler.fetch_theme.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)

    @async_test()
    async def test_fetch_theme_data(self, loop):
        my_response = ClientResponse('GET', 'https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=twentyeleven')  # noqa
        my_response.status = 200
        my_response.headers = {'Content-Type': 'application/json'}
        my_response._content = read_file(__file__, 'twentyeleven.json').encode('utf8')

        handler = WordPressRepository(loop=loop)
        handler.session.close()  # We replace the implementation
        handler.session = MagicMock()
        handler.session.get.return_value = fake_future(my_response, loop)

        theme = await handler.fetch_theme('twentyeleven')

        handler.session.get.assert_called_with('https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=twentyeleven')  # noqa
        self.assertEqual('themes/twentyeleven', theme.key)
        self.assertEqual('Twenty Eleven', theme.name)

    @async_test()
    async def test_fetch_theme_fails_to_request(self, loop):
        handler = WordPressRepository(loop=loop)
        handler.session.close()  # We replace the implementation
        handler.session = MagicMock()
        handler.session.get.side_effect = ClientTimeoutError()

        with self.assertRaises(RepositoryUnreachable):
            await handler.fetch_theme('twentyeleven')

        handler.session.get.assert_called_with('https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=twentyeleven')  # noqa
