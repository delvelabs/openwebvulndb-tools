import asyncio
import aiohttp
from .common import Injector, Storage, RepositoryChecker, Subversion

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               repository_checker=RepositoryChecker,
               subversion=Subversion,
               aiohttp_session=aiohttp.ClientSession)
