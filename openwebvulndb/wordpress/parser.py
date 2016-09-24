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

import json
from .errors import PluginNotFound, ThemeNotFound
from ..common.logs import logger
from ..common import Meta, Repository


class Parser:

    def create_meta(self, reraise=False, **kwargs):
        name = self.apply(self.name_pattern, reraise=reraise, **kwargs)

        key = self.apply(self.key_pattern, reraise=reraise, **kwargs)
        url = self.apply(self.url_pattern, reraise=reraise, **kwargs)
        svn = self.apply(self.repository_pattern, reraise=reraise, **kwargs)

        repositories = [
            Repository(type=self.repository_type, location=svn),
        ] if svn is not None else []

        return Meta(key=key,
                    name=name,
                    url=url,
                    repositories=repositories)

    def apply(self, pattern, *, reraise, **kwargs):
        try:
            return pattern.format(**kwargs)
        except:
            if reraise:
                raise
            else:
                return None

    def parse(self, response):
        try:
            data = json.loads(response)

            return self.create_meta(reraise=True, **data)
        except TypeError:
            raise self.exception('Expected string input, got {data}'.format(data=response))
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
    url_pattern = "{homepage}"
    repository_type = "subversion"
    repository_pattern = "https://plugins.svn.wordpress.org/{slug}/"


class ThemeParser(Parser):

    exception = ThemeNotFound
    name_pattern = "{name}"
    key_pattern = "themes/{slug}"
    url_pattern = "{homepage}"
    repository_type = "subversion"
    repository_pattern = "https://themes.svn.wordpress.org/{slug}/"
