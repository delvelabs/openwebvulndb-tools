import contextlib
import asyncio
from functools import wraps
from os.path import join, dirname
from aiohttp.test_utils import loop_context
import gc


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
                asyncio.get_child_watcher().attach_loop(loop)
                loop.run_until_complete(f(*args, loop=loop, **kwargs))
        return wrapper
    return setup


def fake_future(result, loop):
    f = asyncio.Future(loop=loop)
    f.set_result(result)
    return f
