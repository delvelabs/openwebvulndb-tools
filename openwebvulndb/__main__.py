import asyncio
from argparse import ArgumentParser


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("module", choices=['wordpress'])
parser.add_argument("action")

args = parser.parse_args()


from .common import Injector, Storage

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop)


if args.module == "wordpress" and args.action == "list_plugins":
    from .wordpress import WordPressRepository

    repo = app.create(WordPressRepository)
    app.loop.run_until_complete(repo.perform_lookup())
