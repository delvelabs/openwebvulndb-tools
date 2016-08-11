import asyncio
import aiohttp
from easyinject import Injector
from .common import Storage, RepositoryChecker, Subversion, VulnerabilityManager, RepositoryHasher
from .common.parallel import BackgroundRunner

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               background_runner=BackgroundRunner,
               repository_checker=RepositoryChecker,
               subversion=Subversion,
               vulnerability_manager=VulnerabilityManager,
               aiohttp_session=aiohttp.ClientSession,
               repository_hasher=RepositoryHasher)
