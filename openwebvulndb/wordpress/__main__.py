from argparse import ArgumentParser
from random import shuffle
from os.path import join

from openwebvulndb import app
from .repository import WordPressRepository
from .vane import VaneImporter, VaneVersionRebuild
from ..common.parallel import ParallelWorker


def list_plugins(loop, repository):
    loop.run_until_complete(repository.perform_plugin_lookup())
    loop.run_until_complete(repository.mark_popular_plugins())


def list_themes(loop, repository):
    loop.run_until_complete(repository.perform_theme_lookup())
    loop.run_until_complete(repository.mark_popular_themes())


def vane_import(vane_importer, input_path):
    if not input_path:
        raise Exception("Options required: input_path")
    vane_importer.load(input_path)
    vane_importer.manager.flush()


def vane_export(vane_importer, storage, input_path):
    if not input_path:
        raise Exception("Options required: input_path")
    vane_importer.dump(input_path)

    rebuild = VaneVersionRebuild(join(input_path, "wp_versions.xml"))
    rebuild.update(storage.read_versions("wordpress"))
    rebuild.write()


def populate_versions(loop, repository_hasher, storage):
    async def load_input():
        worker = ParallelWorker(8, loop=loop)
        meta = storage.read_meta("wordpress")
        await worker.request(repository_hasher.collect_from_meta, meta)

        meta = storage.read_meta("mu")
        await worker.request(repository_hasher.collect_from_meta, meta)

        # When restarting the job, shuffle so that we don't spend so much time doing those already done
        task_list = list(storage.list_meta("plugins")) + list(storage.list_meta("themes"))
        shuffle(task_list)

        for meta in task_list:
            await worker.request(repository_hasher.collect_from_meta, meta, prefix_pattern="wp-content/{meta.key}")

        await worker.wait()

    loop.run_until_complete(load_input())


def load_cve(loop, cve_reader, input_file):
    cve_reader.groups = ["plugins", "themes"]
    data = cve_reader.read_file(input_file)
    for entry in data:
        target = cve_reader.identify_target(entry)
        if target is None:
            print(entry)
        else:
            pass


operations = dict(list_themes=list_themes,
                  list_plugins=list_plugins,
                  vane_import=vane_import,
                  vane_export=vane_export,
                  populate_versions=populate_versions,
                  load_cve=load_cve)

parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument('-i', '--input-path', dest='input_path',
                    help='Data source path (vane import)')
parser.add_argument('-f', '--input-file', dest='input_file',
                    help='Cached input file')
args = parser.parse_args()


try:
    local = app.sub(repository=WordPressRepository,
                    vane_importer=VaneImporter,
                    input_path=args.input_path,
                    input_file=args.input_file)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
