import asyncio
import aiohttp
from .common import Injector, Storage

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               httpsession=aiohttp.ClientSession)
