import asyncio
from argparse import ArgumentParser

from .common import Injector, Storage
from .wordpress import WordPressRepository


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("module", choices=['wordpress'])
parser.add_argument("action")

args = parser.parse_args()


app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               wordpress_repository=WordPressRepository)


if args.module == "wordpress" and args.action == "list_plugins":
    app.loop.run_until_complete(app.wordpress_repository.perform_plugin_lookup())


if args.module == "wordpress" and args.action == "list_themes":
    app.loop.run_until_complete(app.wordpress_repository.perform_theme_lookup())
