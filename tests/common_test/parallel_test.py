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
from fixtures import async_test
import async_timeout
from aiohttp.test_utils import make_mocked_coro

from openwebvulndb.common.parallel import BackgroundRunner, ParallelWorker


class ParallelTest(TestCase):

    def multiply(self, a, b):
        return a * b

    @async_test()
    async def test_default_runner(self):
        self.assertEqual(await BackgroundRunner.default(self.multiply, 2, 3), 6)
        self.assertEqual(await BackgroundRunner.default(self.multiply, 2, b=4), 8)
        self.assertEqual(await BackgroundRunner.default(self.multiply, b=3, a=4), 12)

    @async_test()
    async def test_configured_runner(self, loop):
        runner = BackgroundRunner(loop, size=5)

        self.assertEqual(await runner.run(self.multiply, 2, 3), 6)
        self.assertEqual(await runner.run(self.multiply, 2, b=4), 8)
        self.assertEqual(await runner.run(self.multiply, b=3, a=4), 12)

    def test_no_loop_uses_default(self):
        runner = BackgroundRunner(None)
        self.assertIs(runner.run, BackgroundRunner.default)

    @async_test()
    async def test_consume_do_not_block_on_exception(self, loop):
        async def coro_with_exception():
            raise Exception()

        coro = make_mocked_coro()
        worker = ParallelWorker(1, loop=loop)
        await worker.request(coro_with_exception)
        await worker.request(coro)
        with async_timeout.timeout(0.01):
            await worker.wait()

        coro.assert_called_once_with()
