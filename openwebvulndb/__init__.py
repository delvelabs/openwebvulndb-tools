import asyncio
import aiohttp
from .common import Injector, Storage, RepositoryChecker

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               repository_checker=RepositoryChecker,
               aiohttp_session=aiohttp.ClientSession)
