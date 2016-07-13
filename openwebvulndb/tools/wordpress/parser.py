import json
from .errors import PluginNotFound
from ...common.logs import logger
from ...models import Meta, Repository


class PluginParser:

    def parse(self, response):
        try:
            data = json.loads(response)
            key = "plugins/{slug}".format(slug=data['slug'])
            url = "https://wordpress.org/plugins/{slug}/".format(slug=data['slug'])
            svn = "https://plugins.svn.wordpress.org/{slug}/".format(slug=data['slug'])
            repositories = [
                Repository(type="subversion", location=svn),
            ]

            return Meta(key=key,
                        name=data["name"],
                        url=url,
                        repositories=repositories)
        except TypeError:
            raise PluginNotFound('Expected string input')
        except json.decoder.JSONDecodeError:
            raise PluginNotFound('Invalid JSON received')
        except KeyError as e:
            raise PluginNotFound('Required data missing')
        except Exception as e:
            logger.exception(e)
            raise PluginNotFound()
