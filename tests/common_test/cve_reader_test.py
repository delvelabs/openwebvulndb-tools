# openwebvulndb-tools: A collection of tools to maintain vulnerability databases
# Copyright (C) 2016-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from unittest import TestCase
from unittest.mock import MagicMock, call
from datetime import datetime
from fixtures import freeze_time

from openwebvulndb.common.errors import VulnerabilityNotFound
from openwebvulndb.common.models import Meta, VulnerabilityList, Reference, Vulnerability
from openwebvulndb.common.models import VersionList, VersionRange
from openwebvulndb.common.cve import CVEReader, CPEMapper, RangeGuesser


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
        self.assertEqual("wordpress", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.assertEqual("mu", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress_mu:1.4.5"))
        self.assertIsNone(self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress"))

        self.assertIsNone(self.mapper.lookup_cpe("cpe:2.3:a:wr:woess"))

    def test_lookup_can_ignore_version(self):
        self.mapper.load({
            "cpe:2.3:a:wordpress:wordpress": "wordpress",
        })
        self.assertEqual("wordpress", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress", ignore_version=True))

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
        self.assertEqual("hello", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress:1.4.5"))

    def test_load_from_meta_without_cpe_names(self):
        meta = Meta(key="hello")
        self.mapper.load_meta(meta)
        self.assertTrue(self.mapper.loaded)

    def test_load_from_metas_when_mapper_not_loaded(self):
        meta = Meta(key="hello", cpe_names=["cpe:2.3:a:wordpress:wordpress"])
        self.mapper.storage.list_meta.return_value = [meta]

        self.assertEqual("hello", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.assertEqual("hello", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.assertEqual("hello", self.mapper.lookup_cpe("cpe:2.3:a:wordpress:wordpress:1.4.5"))
        self.mapper.storage.list_meta.assert_called_once_with()

    def test_load_from_meta_with_hints(self):
        meta = Meta(key="hello", hints=[
            Reference(type="cve", id="1234-1234"),
            Reference(type="test", id="11211"),
        ])
        self.mapper.load_meta(meta)
        self.assertTrue(self.mapper.loaded)

        self.assertEqual("hello", self.mapper.lookup_id("CVE-1234-1234"))
        self.assertIsNone(self.mapper.lookup_id("11211"))


class LookupVulnerabilityTest(TestCase):

    def setUp(self):
        self.manager = MagicMock()
        self.reader = CVEReader(storage=MagicMock(), vulnerability_manager=self.manager)
        self.reader.load_mapping(
            cpe_mapping={
                "cpe:2.3:a:wordpress:wordpress": "wordpress",
                "cpe:2.3:a:wordpress:wordpress_mu": "mu",
            }
        )

    def test_lookup_does_not_exist(self):
        self.manager.find_vulnerability.side_effect = VulnerabilityNotFound()
        self.manager.get_producer_list.return_value = VulnerabilityList(producer="CVEReader", key="wordpress")

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "cvss": 6.7,
            "cwe": "CWE-79",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
            "references": [
                "http://example.com/133",
            ]
        })
        self.manager.find_vulnerability.assert_called_with("wordpress",
                                                           match_reference=Reference(type="cve", id="1234-2334"))
        self.manager.flush.assert_called_with()
        self.manager.get_producer_list.assert_called_with("CVEReader", "wordpress")
        self.assertEqual(v.id, "CVE-1234-2334")
        self.assertEqual(v.title, "Some Text")
        self.assertEqual(v.description, "Some Text")
        self.assertEqual(v.cvss, 6.7)
        self.assertEqual(v.reported_type, "CWE-79")

        self.assertEqual("1234-2334", v.references[0].id)
        self.assertEqual("http://example.com/133", v.references[1].url)

    def test_lookup_based_on_hints(self):
        self.reader.load_mapping(hint_mapping={
            "9999-9999": "plugins/contact-form",
        })
        self.manager.find_vulnerability.side_effect = VulnerabilityNotFound()
        self.manager.get_producer_list.return_value = VulnerabilityList(producer="CVEReader",
                                                                        key="plugins/contact-form")

        v = self.reader.read_one({
            "id": "CVE-9999-9999",
            "summary": "Some Text",
            "cvss": 6.7,
            "cwe": "CWE-79",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress",
            ],
            "references": [
                "http://example.com/133",
            ]
        })
        self.manager.find_vulnerability.assert_called_with("plugins/contact-form",
                                                           match_reference=Reference(type="cve", id="9999-9999"))
        self.manager.flush.assert_called_with()
        self.manager.get_producer_list.assert_called_with("CVEReader", "plugins/contact-form")
        self.assertEqual(v.id, "CVE-9999-9999")
        self.assertEqual(v.title, "Some Text")
        self.assertEqual(v.description, "Some Text")
        self.assertEqual(v.cvss, 6.7)
        self.assertEqual(v.reported_type, "CWE-79")

        self.assertEqual("9999-9999", v.references[0].id)
        self.assertEqual("http://example.com/133", v.references[1].url)

    def test_only_override_description_when_old(self):
        vuln = Vulnerability(id="X",
                             title="My Title",
                             reported_type="SQLi",
                             description="A description")
        self.manager.find_vulnerability.return_value = vuln

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "cwe": "CWE-199",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        })

        self.assertIs(vuln, v)
        self.manager.flush.assert_called_with()
        self.assertEqual(v.title, "My Title")
        self.assertEqual(v.reported_type, "SQLi")
        self.assertEqual(v.description, "Some Text")

    def test_unknown_is_nothing(self):
        vuln = Vulnerability(id="X",
                             title="My Title",
                             reported_type="Unknown",
                             description="A description")
        self.manager.find_vulnerability.return_value = vuln

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "cwe": "CWE-199",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        })

        self.assertIs(vuln, v)
        self.manager.flush.assert_called_with()
        self.assertEqual(v.title, "My Title")
        self.assertEqual(v.reported_type, "CWE-199")
        self.assertEqual(v.description, "Some Text")

    @freeze_time("2016-08-25")  # Much after the vuln update
    def test_apply_skips_if_no_update_is_required(self):
        initial = datetime.now()
        vuln = Vulnerability(id="X",
                             title="My Title",
                             description="A description",
                             updated_at=initial)

        self.manager.find_vulnerability.return_value = vuln

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "last-modified": "2016-08-10T12:29:12.813-04:00",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        })

        self.assertIs(vuln, v)
        self.assertEqual(vuln.description, "A description")
        self.assertEqual(vuln.updated_at, initial)

    def test_apply_skips_if_no_update_is_required_with_legacy_data(self):
        initial = datetime.now()
        vuln = Vulnerability(id="X",
                             title="My Title",
                             description="A description",
                             updated_at=initial)

        self.manager.find_vulnerability.return_value = vuln

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "Modified": "2016-08-10T12:29:12.813-04:00",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        })

        self.assertIs(vuln, v)
        self.assertEqual(vuln.description, "A description")
        self.assertEqual(vuln.updated_at, initial)

    @freeze_time("2016-07-25")  # Much prior the vuln update
    def test_update_time_is_good(self):
        initial = datetime.now()
        vuln = Vulnerability(id="X",
                             title="My Title",
                             description="A description",
                             updated_at=initial)

        self.manager.find_vulnerability.return_value = vuln

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "last-modified": "2016-08-10T12:29:12.813-04:00",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        })

        self.assertIs(vuln, v)
        self.assertGreater(vuln.updated_at, initial)

    def test_guess_versions(self):
        vuln = Vulnerability(id="X",
                             description="A description")
        self.manager.find_vulnerability.return_value = vuln
        self.reader.range_guesser = MagicMock()
        self.reader.range_guesser.guess.return_value = [
            VersionRange(introduced_in="1.0"),
        ]

        v = self.reader.read_one({
            "id": "CVE-1234-2334",
            "summary": "Some Text",
            "vulnerable_configuration": [
                "cpe:2.3:a:wordpress:wordpress:4.4.3",
                "cpe:2.3:a:wordpress:wordpress:4.4.4",
            ],
        })

        self.reader.range_guesser.load.assert_called_with("wordpress")
        self.reader.range_guesser.guess.assert_called_with("Some Text", [
            "cpe:2.3:a:wordpress:wordpress:4.4.3",
            "cpe:2.3:a:wordpress:wordpress:4.4.4",
        ])
        self.assertEqual(v.affected_versions, [
            VersionRange(introduced_in="1.0"),
        ])


class RangeGuesserTest(TestCase):

    def setUp(self):
        self.guesser = RangeGuesser(storage=MagicMock())
        self.guess = self.guesser.guess

    def test_from_summary(self):
        self.assertIn(VersionRange(fixed_in="2.4.5"), self.guess("XSS before 2.4.5 - critical", []))

    def test_with_complex_summary(self):
        summary = "Cross-site scripting (XSS) vulnerability in the wptexturize function in WordPress before 3.7.5, 3.8.x before 3.8.5, and 3.9.x before 3.9.3 allows remote attackers to inject arbitrary web script or HTML via crafted use of shortcode brackets in a text field, as demonstrated by a comment or a post."  # noqa
        result = list(self.guess(summary, []))
        self.assertEqual(result, [
            VersionRange(fixed_in="3.7.5"),
            VersionRange(introduced_in="3.8", fixed_in="3.8.5"),
            VersionRange(introduced_in="3.9", fixed_in="3.9.3"),
        ])

    def test_complex_summary_with_major(self):
        summary = "Cross-site scripting (XSS) vulnerability in the media-playlists feature in WordPress before 3.9.x before 3.9.3 and 4.x before 4.0.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors."  # noqa
        result = list(self.guess(summary, []))
        self.assertEqual(result, [
            VersionRange(introduced_in="3.9", fixed_in="3.9.3"),
            VersionRange(introduced_in="4", fixed_in="4.0.1"),
        ])

    def test_summary_always_has_precedence(self):
        self.guesser.known_versions = ["2.4.5", "3.5"]
        result = list(self.guess("XSS before 2.4.5 - critical", [
            "cpe:2.3:a:wordpress:wordpress:2.4.3",
            "cpe:2.3:a:wordpress:wordpress:2.4.4",
            "cpe:2.3:a:wordpress:wordpress:3.4.5",
        ]))
        self.assertIn(VersionRange(fixed_in="2.4.5"), result)
        self.assertNotIn(VersionRange(fixed_in="3.5"), result)

    def test_from_summary_not_explicit_enough(self):
        self.assertNotIn(VersionRange(fixed_in="2.4.5"), self.guess("XSS in 2.4.5 - critical", []))

    def test_next_revision_is_fixing_things(self):
        self.guesser.known_versions = ["2.4.3", "2.4.4", "3.4.6", "3.5"]
        self.assertIn(VersionRange(fixed_in="3.4.6"), self.guess("XSS - critical", [
            "cpe:2.3:a:wordpress:wordpress:2.4.3",
            "cpe:2.3:a:wordpress:wordpress:2.4.4",
            "cpe:2.3:a:wordpress:wordpress:3.4.5",
        ]))

    def test_next_minor_is_known_version(self):
        self.guesser.known_versions = ["2.4.3", "2.4.4", "3.5"]
        self.assertIn(VersionRange(fixed_in="3.5"), self.guess("XSS - critical", [
            "cpe:2.3:a:wordpress:wordpress:2.4.3",
            "cpe:2.3:a:wordpress:wordpress:2.4.4",
            "cpe:2.3:a:wordpress:wordpress:3.4.5",
        ]))

    def test_fix_does_not_appear_to_be_released(self):
        self.guesser.known_versions = ["2.4.3", "2.4.4"]
        self.assertNotIn(VersionRange(fixed_in="3.5"), self.guess("XSS - critical", [
            "cpe:2.3:a:wordpress:wordpress:2.4.3",
            "cpe:2.3:a:wordpress:wordpress:2.4.4",
            "cpe:2.3:a:wordpress:wordpress:3.4.5",
        ]))

    def test_bad_version(self):
        self.guesser.known_versions = ["2.4.3", "2.4.4"]
        self.assertNotIn(VersionRange(fixed_in="3.5"), self.guess("XSS - critical", [
            "cpe:2.3:a:wordpress:wordpress:-",
        ]))

    def test_versions_not_found(self):
        self.guesser.storage.read_versions.side_effect = FileNotFoundError()
        self.guesser.known_versions = ["2.4.3", "2.4.4"]
        self.guesser.load("anything")

        self.assertEqual([], self.guesser.known_versions)

    def test_versions_found(self):
        vlist = VersionList(key="anything", producer="test")
        vlist.get_version("1.0", create_missing=True)
        vlist.get_version("1.2", create_missing=True)
        self.guesser.storage.read_versions.return_value = vlist
        self.guesser.known_versions = ["2.4.3", "2.4.4"]
        self.guesser.load("anything")

        self.assertEqual(["1.0", "1.2"], self.guesser.known_versions)
