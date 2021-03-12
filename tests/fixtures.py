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

import unittest
from unittest.mock import MagicMock, Mock
import asyncio
from functools import wraps
from os.path import join, dirname
from aiohttp.test_utils import loop_context
from aiohttp import ClientResponse as BaseClientResponse
from aiohttp.helpers import TimerNoop

from easyinject import Injector

try:
    from freezegun import freeze_time
except ImportError:
    def freeze_time(time):
        def setup(f):
            return unittest.skip("freezegun is required")(f)

        return setup


def ClientResponse(method, url, *,
                   writer=None, continue100=None, timer=None, request_info=None,
                   traces=None, loop=None, session=None):
    return BaseClientResponse(method, url,
                              writer=writer or Mock(),
                              continue100=continue100,
                              timer=timer or TimerNoop(),
                              request_info=request_info or Mock(),
                              traces=traces or [],
                              loop=loop or asyncio.get_event_loop(),
                              session=session or None)


def file_path(relative, file):
    return join(dirname(relative), file)


def read_file(relative, file):
    full_path = file_path(relative, file)
    with open(full_path, 'r') as fp:
        return fp.read()


def async_test():
    def setup(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            with loop_context() as loop:
                injector = Injector(loop=loop,
                                    fake_future=lambda: fake_future)
                asyncio.get_child_watcher().attach_loop(loop)
                loop.run_until_complete(injector.call(f, *args, **kwargs))
        return wrapper
    return setup


def fake_future(result, loop):
    f = asyncio.Future(loop=loop)
    f.set_result(result)
    return f


class ClientSessionMock:

    def __init__(self, get_response=None, post_response=None, get_exception=None, post_exception=None):
        self.get = MagicMock(return_value=AsyncContextManagerMock(), side_effect=get_exception)
        self.post = MagicMock(return_value=AsyncContextManagerMock(), side_effect=post_exception)
        self.get_response = get_response or MagicMock()
        self.post_response = post_response or MagicMock()

    def __setattr__(self, name, value):
        if name == "get_response":
            self.get.return_value.aenter_return = value
        elif name == "post_response":
            self.post.return_value.aenter_return = value
        super().__setattr__(name, value)


class AsyncContextManagerMock:

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for key in ('aenter_return', 'aexit_return'):
            setattr(self, key, kwargs[key] if key in kwargs else MagicMock())

    async def __aenter__(self):
        return self.aenter_return

    async def __aexit__(self, *args):
        return self.aexit_return
