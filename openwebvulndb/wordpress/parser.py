import json
from .errors import PluginNotFound, ThemeNotFound
from ..common.logs import logger
from ..common import Meta, Repository


class Parser:

    def parse(self, response):
        try:
            data = json.loads(response)

            key = self.key_pattern.format(**data)
            name = self.name_pattern.format(**data)
            url = self.url_pattern.format(**data)
            svn = self.repository_pattern.format(**data)
            repositories = [
                Repository(type=self.repository_type, location=svn),
            ]

            return Meta(key=key,
                        name=name,
                        url=url,
                        repositories=repositories)
        except TypeError:
            raise self.exception('Expected string input')
        except json.decoder.JSONDecodeError:
            raise self.exception('Invalid JSON received')
        except KeyError as e:
            raise self.exception('Required data missing')
        except Exception as e:
            logger.exception(e)
            raise self.exception()


class PluginParser(Parser):

    exception = PluginNotFound
    name_pattern = "{name}"
    key_pattern = "plugins/{slug}"
    url_pattern = "https://wordpress.org/plugins/{slug}/"
    repository_type = "subversion"
    repository_pattern = "https://plugins.svn.wordpress.org/{slug}/"


class ThemeParser(Parser):

    exception = ThemeNotFound
    name_pattern = "{name}"
    key_pattern = "themes/{slug}"
    url_pattern = "https://wordpress.org/themes/{slug}/"
    repository_type = "subversion"
    repository_pattern = "https://themes.svn.wordpress.org/{slug}/"
