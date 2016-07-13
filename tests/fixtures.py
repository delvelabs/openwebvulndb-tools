import contextlib
import asyncio
from functools import wraps
from os.path import join, dirname
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
                loop.run_until_complete(f(*args, loop=loop, **kwargs))
        return wrapper
    return setup


def fake_future(result, loop):
    f = asyncio.Future(loop=loop)
    f.set_result(result)
    return f


# Borrowed from aiohttp.test_utils , waiting for release
@contextlib.contextmanager
def loop_context():
    """a contextmanager that creates an event_loop, for test purposes.
    handles the creation and cleanup of a test loop.
    """
    loop = setup_test_loop()
    yield loop
    teardown_test_loop(loop)


def setup_test_loop():
    """create and return an asyncio.BaseEventLoop
    instance. The caller should also call teardown_test_loop,
    once they are done with the loop.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


def teardown_test_loop(loop):
    """teardown and cleanup an event_loop created
    by setup_test_loop.
    :param loop: the loop to teardown
    :type loop: asyncio.BaseEventLoop
    """
    is_closed = getattr(loop, 'is_closed')
    if is_closed is not None:
        closed = is_closed()
    else:
        closed = loop._closed
    if not closed:
        loop.call_soon(loop.stop)
        loop.run_forever()
        loop.close()
    gc.collect()
    asyncio.set_event_loop(None)
