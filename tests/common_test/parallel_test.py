from unittest import TestCase
from fixtures import async_test

from openwebvulndb.common.parallel import BackgroundRunner


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
