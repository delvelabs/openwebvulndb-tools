from argparse import ArgumentParser
from random import shuffle

from openwebvulndb import app
from .repository import WordPressRepository
from .vane import VaneImporter
from ..common.parallel import ParallelWorker


def list_plugins(loop, repository):
    loop.run_until_complete(repository.perform_plugin_lookup())


def list_themes(loop, repository):
    loop.run_until_complete(repository.perform_theme_lookup())


def vane_import(vane_importer, input_path):
    if not input_path:
        raise Exception("Options required: input_path")
    vane_importer.load(input_path)
    vane_importer.manager.flush()


def populate_versions(loop, repository_hasher, storage):
    async def load_input():
        worker = ParallelWorker(8, loop=loop)
        meta = storage.read_meta("wordpress")

        await worker.request(repository_hasher.collect_from_meta, meta)

        # When restarting the job, shuffle so that we don't spend so much time doing those already done
        task_list = list(storage.list_meta("plugins")) + list(storage.list_meta("themes"))
        shuffle(task_list)

        for meta in task_list:
            await worker.request(repository_hasher.collect_from_meta, meta, prefix_pattern="wp-content/{meta.key}")

        await worker.wait()

    loop.run_until_complete(load_input())


def find_identity_files(storage, input_key):
    versions = storage.read_versions(input_key)

    from collections import defaultdict
    file_map = defaultdict(list)
    for v in versions.versions:
        for s in v.signatures:
            file_map[s.path].append(s.hash)

    data = [(len(set(values)), len(values), path) for path, values in file_map.items()]
    data.sort(reverse=True)
    for uniques, total, path in data:
        print("%s/%s    %s" % (uniques, total, path))

    print("Total version count: %s" % len(versions.versions))

operations = dict(list_themes=list_themes,
                  list_plugins=list_plugins,
                  vane_import=vane_import,
                  populate_versions=populate_versions,
                  find_identity_files=find_identity_files)


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument('-i', '--input-path', dest='input_path',
                    help='Data source path (vane import)')
parser.add_argument('-k', '--key', dest='input_key', default="wordpress",
                    help='Software key for targetting specific plugins or themes')
args = parser.parse_args()


try:
    local = app.sub(repository=WordPressRepository,
                    vane_importer=VaneImporter,
                    input_path=args.input_path,
                    input_key=args.input_key)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
