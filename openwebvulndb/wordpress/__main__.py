from argparse import ArgumentParser

from openwebvulndb import app
from .repository import WordPressRepository
from .vane import VaneImporter


def list_plugins(loop, repository):
    loop.run_until_complete(repository.perform_plugin_lookup())


def list_themes(loop, repository):
    loop.run_until_complete(repository.perform_theme_lookup())


def vane_import(vane_importer, input_path):
    if not input_path:
        raise Exception("Options required: input_path")
    vane_importer.load(input_path)
    vane_importer.manager.flush()


operations = dict(list_themes=list_themes,
                  list_plugins=list_plugins,
                  vane_import=vane_import)


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument('-i', '--input-path', dest='input_path',
                    help='Data source path (vane import)')
args = parser.parse_args()


try:
    local = app.sub(repository=WordPressRepository,
                    vane_importer=VaneImporter,
                    input_path=args.input_path)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
