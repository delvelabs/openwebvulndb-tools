from argparse import ArgumentParser

from openwebvulndb import app
from .repository import WordPressRepository


def list_plugins(loop, repository):
    loop.run_until_complete(repository.perform_plugin_lookup())

def list_themes(loop, repository):
    loop.run_until_complete(repository.perform_theme_lookup())


operations = dict(list_themes=list_themes,
                  list_plugins=list_plugins)


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
args = parser.parse_args()


try:
    app = app.sub(repository=WordPressRepository)
    app.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
