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

import asyncio
import async_timeout
from functools import partial
from concurrent.futures import ThreadPoolExecutor

from .logs import logger


class ParallelWorker:

    def __init__(self, worker_count, *, loop, name="Worker", timeout_per_job=None):
        self.loop = loop
        self.name = name
        self.queue = asyncio.Queue(loop=loop)
        self.workers = [loop.create_task(self.consume(i)) for i in range(worker_count)]
        self.timeout_per_job = timeout_per_job

    async def request(self, coroutine, *args, **kwargs):
        await self.queue.put((coroutine, args, kwargs))

    async def consume(self, n):
        while True:
            coroutine, args, kwargs = await self.queue.get()

            try:
                logger.debug("{} {} picked up a task.".format(self.name, n))
                if self.timeout_per_job is not None:
                    task = self.loop.create_task(coroutine(*args, **kwargs))
                    try:
                        with async_timeout.timeout(timeout=self.timeout_per_job):
                            await task
                    except asyncio.TimeoutError:
                        logger.warn("Job timed out in %s: %s, %s", self.name, args, kwargs)
                        self._handle_task_timeout(task)
                else:
                    await coroutine(*args, **kwargs)
            except Exception as e:
                logger.exception(e)
            finally:
                self.queue.task_done()

    async def wait(self):
        try:
            await self.queue.join()
        finally:
            for task in self.workers:
                try:
                    task.cancel()
                except:
                    pass

    def _handle_task_timeout(self, task):
        try:
            task.result()
        except asyncio.CancelledError:
            pass


class BackgroundRunner:
    @staticmethod
    async def default(callback, *args, **kwargs):
        # Not actually running anything in the background, just pretending to
        return callback(*args, **kwargs)

    def __init__(self, loop, size=10):
        if loop is None:
            self.run = self.default
        else:
            self.loop = loop
            self.executor = ThreadPoolExecutor(max_workers=size)

    async def run(self, callback, *args, **kwargs):
        return await self.loop.run_in_executor(self.executor, partial(callback, *args, **kwargs))
