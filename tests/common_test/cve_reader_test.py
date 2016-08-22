from unittest import TestCase
from unittest.mock import MagicMock, call
from fixtures import read_file

from openwebvulndb.common.models import Meta
from openwebvulndb.common.cve import CVEReader, CPEMapper


content = read_file(__file__, 'cve.circl.lu.json')


class TargetIdentificationTest(TestCase):

    def setUp(self):
        self.storage = MagicMock()
        self.reader = CVEReader(storage=self.storage)
        self.reader.load_mapping({
            "cpe:2.3:a:wordpress:wordpress": "wordpress",
            "cpe:2.3:a:wordpress:wordpress_mu": "mu",
        })

    def test_identify_target(self):
        self.assertIsNone(self.reader.identify_target({
        }))

    def test_target_is_wordpress(self):
        self.assertEqual("wordpress", self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        }))

    def test_target_is_wordpress_my(self):
        self.assertEqual("mu", self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress_mu:2.9.2",
            ],
        }))

    def test_cpe_does_not_indicate_wordpress(self):
        self.reader.groups = ["plugins", "themes"]
        self.assertIsNone(self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:doryphores:audio_player:2.0.4.5",
                "cpe:2.3:a:doryphores:audio_player:2.0.4.4",
                "cpe:2.3:a:doryphores:audio_player:2.0.2.0",
                "cpe:2.3:a:doryphores:audio_player:2.0.1.0",
                "cpe:2.3:a:wordpress:wordpress"
            ],
        }))

    def test_fall_back_to_searching_in_references(self):
        self.assertEqual("plugins/audio-player", self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:doryphores:audio_player:2.0.4.5",
                "cpe:2.3:a:doryphores:audio_player:2.0.4.4",
                "cpe:2.3:a:doryphores:audio_player:2.0.2.0",
                "cpe:2.3:a:doryphores:audio_player:2.0.1.0",
                "cpe:2.3:a:wordpress:wordpress"
            ],
            "references": [
                "http://wordpress.org/extend/plugins/audio-player/changelog/",
                "http://packetstormsecurity.com/files/120129/WordPress-Audio-Player-SWF-Cross-Site-Scripting.html",
                "http://insight-labs.org/?p=738"
            ],
        }))

    def test_fall_back_to_guessing_from_cpe(self):
        self.reader.groups = ["plugins", "themes"]
        self.storage.list_directories.return_value = []
        self.assertIsNone(self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:doryphores:audio_player:2.0.4.5",
                "cpe:2.3:a:doryphores:audio_player:2.0.4.4",
                "cpe:2.3:a:doryphores:audio_player:2.0.2.0",
                "cpe:2.3:a:doryphores:audio_player:2.0.1.0",
                "cpe:2.3:a:doryphores:some_framework_plugin:2.0.1.0",
                "cpe:2.3:a:wordpress:wordpress"
            ],
        }))
        self.storage.list_directories.assert_has_calls([
            call("plugins"),
            call("themes"),
        ])
        self.assertEqual(2, self.storage.list_directories.call_count)

    def test_fallback_finds_by_guessing(self):
        self.storage.list_directories.side_effect = [
            ["hello", "world", "audio-player"],
            ["twentyeleven"],
        ]
        self.reader.groups = ["plugins", "themes"]

        self.assertEqual("plugins/audio-player", self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:doryphores:audio_player:2.0.4.5",
                "cpe:2.3:a:doryphores:audio_player:2.0.4.4",
                "cpe:2.3:a:doryphores:audio_player:2.0.2.0",
                "cpe:2.3:a:doryphores:audio_player:2.0.1.0",
                "cpe:2.3:a:doryphores:some_framework_plugin:2.0.1.0",
                "cpe:2.3:a:wordpress:wordpress"
            ],
        }))

    def test_fallback_finds_by_guessing_without_versions(self):
        self.storage.list_directories.return_value = []
        self.reader.load_mapping({
            "cpe:2.3:a:doryphores:audio_player": "plugins/audio-player",
        })
        self.reader.groups = ["plugins", "themes"]

        self.assertEqual("plugins/audio-player", self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:doryphores:audio_player",
                "cpe:2.3:a:wordpress:wordpress"
            ],
        }))

    def test_fallback_to_wordpress_if_nothing_else(self):
        self.storage.list_directories.return_value = []
        self.reader.groups = ["plugins", "themes"]

        self.assertEqual("wordpress", self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress"
            ],
        }))

    def test_do_not_fallback_to_wordpress_if_other_options_need_finding(self):
        self.storage.list_directories.return_value = []
        self.reader.groups = ["plugins", "themes"]

        self.assertIsNone(self.reader.identify_target({
            "vulnerable_configuration": [
                "cpe:2.3:a:doryphores:audio_player",
                "cpe:2.3:a:wordpress:wordpress"
            ],
        }))

    def test_extract_from_source_control(self):
        self.assertEqual("plugins/better-wp-security",
                         self.reader.identify_from_url("http://plugins.svn.wordpress.org/better-wp-security"))
        self.assertEqual("plugins/better-wp-security",
                         self.reader.identify_from_url("https://plugins.svn.wordpress.org/better-wp-security/trunk/"))
        self.assertEqual("themes/twentyeleven",
                         self.reader.identify_from_url("http://themes.svn.wordpress.org/twentyeleven/trunk/"))

    def test_extract_from_wordpress_extend(self):
        self.assertEqual("plugins/better-wp-security",
                         self.reader.identify_from_url("http://wordpress.org/extend/plugins/better-wp-security"))
        self.assertEqual("plugins/better-wp-security",
                         self.reader.identify_from_url("https://www.wordpress.org/extend/plugins/better-wp-security/"))
        self.assertEqual("themes/twentyeleven",
                         self.reader.identify_from_url("http://wordpress.org/extend/themes/twentyeleven/changelog"))

    def test_extract_from_wordpress_no_extend(self):
        self.assertEqual("plugins/better-wp-security",
                         self.reader.identify_from_url("http://wordpress.org/plugins/better-wp-security"))
        self.assertEqual("plugins/better-wp-security",
                         self.reader.identify_from_url("https://www.wordpress.org/plugins/better-wp-security/"))
        self.assertEqual("themes/twentyeleven",
                         self.reader.identify_from_url("http://wordpress.org/themes/twentyeleven/changelog"))


class CPEMapperTest(TestCase):

    def setUp(self):
        self.mapper = CPEMapper(storage=MagicMock())

    def test_initial_state_not_loaded(self):
        self.assertFalse(self.mapper.loaded)

    def test_lookup_matches_with_versions(self):
        self.mapper.load({
            "cpe:2.3:a:wordpress:wordpress": "wordpress",
            "cpe:2.3:a:wordpress:wordpress_mu": "mu",
        })
        self.assertTrue(self.mapper.loaded)
        self.assertEqual("wordpress", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.assertEqual("mu", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress_mu:1.4.5"))
        self.assertIsNone(self.mapper.lookup("cpe:2.3:a:wordpress:wordpress"))

        self.assertIsNone(self.mapper.lookup("cpe:2.3:a:wr:woess"))

    def test_lookup_can_ignore_version(self):
        self.mapper.load({
            "cpe:2.3:a:wordpress:wordpress": "wordpress",
        })
        self.assertEqual("wordpress", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress", ignore_version=True))

    def test_cannot_load_same_key_multiple_times(self):
        self.mapper.load({
            "cpe:2.3:a:wordpress:wordpress": "wordpress",
        })
        with self.assertRaises(KeyError):
            self.mapper.load({
                "cpe:2.3:a:wordpress:wordpress": "plugins/plugin-x",
            })

    def test_load_from_meta_with_cpe_names(self):
        meta = Meta(key="hello", cpe_names=["cpe:2.3:a:wordpress:wordpress"])
        self.mapper.load_meta(meta)
        self.assertEqual("hello", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress:1.4.5"))

    def test_load_from_meta_without_cpe_names(self):
        meta = Meta(key="hello")
        self.mapper.load_meta(meta)
        self.assertTrue(self.mapper.loaded)

    def test_load_from_metas_when_mapper_not_loaded(self):
        meta = Meta(key="hello", cpe_names=["cpe:2.3:a:wordpress:wordpress"])
        self.mapper.storage.list_meta.return_value = [meta]

        self.assertEqual("hello", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.assertEqual("hello", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.assertEqual("hello", self.mapper.lookup("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.mapper.storage.list_meta.assert_called_once_with()
