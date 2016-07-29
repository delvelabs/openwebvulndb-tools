import asyncio
from .logs import logger


class ParallelWorker:

    def __init__(self, worker_count, *, loop, name="Worker"):
        self.loop = loop
        self.name = name
        self.queue = asyncio.Queue(loop=loop)
        self.workers = [loop.create_task(self.consume(i)) for i in range(worker_count)]

    async def request(self, coroutine, *args, **kwargs):
        await self.queue.put((coroutine, args, kwargs))

    async def consume(self, n):
        while True:
            coroutine, args, kwargs = await self.queue.get()

            try:
                logger.debug("{} {} picked up a task.".format(self.name, n))
                await coroutine(*args, **kwargs)
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
