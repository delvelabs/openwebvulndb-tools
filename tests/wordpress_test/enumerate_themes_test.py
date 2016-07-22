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
            'a-class-act-ny', 'skt-bakery', 'the-modern-accounting-firm'], loop)

        themes = await handler.enumerate_plugins()
        handler.subversion.ls.assert_called_with("https://plugins.svn.wordpress.org/")

        self.assertEqual(themes, {'a-class-act-ny', 'skt-bakery', 'the-modern-accounting-firm'})

    @async_test()
    async def test_failure_to_list(self, loop):
        handler = WordPressRepository(loop=loop, subversion=MagicMock())
        handler.subversion.ls.side_effect = ExecutionFailure()

        with self.assertRaises(RepositoryUnreachable):
            await handler.enumerate_themes()

    @async_test()
    async def test_read_path_empty(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = set()
        handler.storage.read.return_value = []

        self.assertEqual(handler.current_themes(), set())
        handler.storage.list_directories.assert_called_with('themes')
        handler.storage.read.assert_called_with('themes-ignore.txt')

    @async_test()
    async def test_read_path_with_data(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = {"wordpress_test"}
        handler.storage.read.return_value = []
        self.assertIn("wordpress_test", handler.current_themes())
        handler.storage.list_directories.assert_called_with('themes')

    @async_test()
    async def test_read_path_with_data_from_ignore(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock())
        handler.storage.list_directories.return_value = set()
        handler.storage.read.return_value = ['wordpress_test']
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
        handler = WordPressRepository(loop=loop, storage=MagicMock(), repository_checker=MagicMock())
        handler.current_themes = lambda: {'hello-world', 'unknown-theme'}
        handler.enumerate_themes = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_theme = MagicMock()
        handler.fetch_theme.side_effect = PluginNotFound('A side effect!')
        handler.checker.has_content.return_value = fake_future(True, loop)
        await handler.perform_theme_lookup()

        handler.fetch_theme.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
        handler.storage.write_meta.assert_has_calls([
            call(handler.theme_parser.create_meta(slug="a")),
            call(handler.theme_parser.create_meta(slug="b")),
        ], any_order=True)
        handler.checker.has_content.assert_has_calls([
            call(Repository(type="subversion", location="https://themes.svn.wordpress.org/a/")),
            call(Repository(type="subversion", location="https://themes.svn.wordpress.org/b/")),
        ], any_order=True)

    @async_test()
    async def test_when_fetch_fails_bad_repo(self, loop):
        handler = WordPressRepository(loop=loop, storage=MagicMock(), repository_checker=MagicMock())
        handler.current_themes = lambda: {'hello-world', 'unknown-theme'}
        handler.enumerate_themes = lambda: fake_future({'hello-world', 'a', 'b'}, loop)

        handler.fetch_theme = MagicMock()
        handler.fetch_theme.side_effect = PluginNotFound('A side effect!')
        handler.checker.has_content.return_value = fake_future(False, loop)
        await handler.perform_theme_lookup()

        handler.fetch_theme.assert_has_calls([
            call('a'),
            call('b'),
        ], any_order=True)
        handler.storage.write_meta.assert_not_called()
        handler.checker.has_content.assert_has_calls([
            call(Repository(type="subversion", location="https://themes.svn.wordpress.org/a/")),
            call(Repository(type="subversion", location="https://themes.svn.wordpress.org/b/")),
        ], any_order=True)
        handler.storage.append.assert_has_calls([
            call("themes-ignore.txt", "a"),
            call("themes-ignore.txt", "b"),
        ], any_order=True)

    @async_test()
    async def test_fetch_theme_data(self, loop):
        my_response = ClientResponse('GET', 'https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=twentyeleven')  # noqa
        my_response.status = 200
        my_response.headers = {'Content-Type': 'application/json'}
        my_response._content = read_file(__file__, 'twentyeleven.json').encode('utf8')

        handler = WordPressRepository(loop=loop, aiohttp_session=MagicMock())
        handler.session.get.return_value = fake_future(my_response, loop)

        theme = await handler.fetch_theme('twentyeleven')

        handler.session.get.assert_called_with('https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=twentyeleven')  # noqa
        self.assertEqual('themes/twentyeleven', theme.key)
        self.assertEqual('Twenty Eleven', theme.name)

    @async_test()
    async def test_fetch_theme_fails_to_request(self, loop):
        handler = WordPressRepository(loop=loop, aiohttp_session=MagicMock())
        handler.session.get.side_effect = ClientTimeoutError()

        with self.assertRaises(RepositoryUnreachable):
            await handler.fetch_theme('twentyeleven')

        handler.session.get.assert_called_with('https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=twentyeleven')  # noqa
