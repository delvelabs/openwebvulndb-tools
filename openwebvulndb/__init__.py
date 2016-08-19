import asyncio
import aiohttp
from easyinject import Injector
from .common import Storage, RepositoryChecker, Subversion, VulnerabilityManager, RepositoryHasher
from .common.parallel import BackgroundRunner
from .common.cve import CVEReader

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               background_runner=BackgroundRunner,
               repository_checker=RepositoryChecker,
               cve_reader=CVEReader,
               subversion=Subversion,
               vulnerability_manager=VulnerabilityManager,
               aiohttp_session=aiohttp.ClientSession,
               repository_hasher=RepositoryHasher)
