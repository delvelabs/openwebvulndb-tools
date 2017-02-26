# openwebvulndb-tools: A collection of tools to maintain vulnerability databases
# Copyright (C) 2016-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from argparse import ArgumentParser
from random import shuffle
from os.path import join, dirname

from openwebvulndb import app
from .repository import WordPressRepository
from .vane import VaneImporter, VaneVersionRebuild
from ..common.parallel import ParallelWorker
from ..common.securityfocus.database_tools import update_securityfocus_database, create_securityfocus_database, download_vulnerability_entry
from .vane2.exporter import Exporter
from ..common.logs import logger


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


def vane2_export(storage, input_path):
    if input_path:
        input_path = join(dirname(__file__), input_path)
    else:
        input_path = dirname(__file__)

    exporter = Exporter(storage)

    equal_versions = exporter.export_wordpress(input_path)
    for version in equal_versions:
        logger.info(version)

    exporter.export_plugins(input_path, only_popular=True)
    exporter.export_plugins(input_path, only_vulnerable=True)
    exporter.export_plugins(input_path)

    exporter.export_themes(input_path, only_popular=True)
    exporter.export_themes(input_path, only_vulnerable=True)
    exporter.export_themes(input_path)

    exporter.export_vulnerabilities(input_path)


def populate_versions(loop, repository_hasher, storage):
    async def load_input():
        worker = ParallelWorker(8, loop=loop, timeout_per_job=1800)  # Half an hour at most
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
    if input_file:
        cve_reader.read_file(input_file)
    else:
        loop.run_until_complete(cve_reader.read_api("http://cve.circl.lu/api/search/wordpress/wordpress"))


operations = dict(list_themes=list_themes,
                  list_plugins=list_plugins,
                  vane_import=vane_import,
                  vane_export=vane_export,
                  vane2_export=vane2_export,
                  populate_versions=populate_versions,
                  load_cve=load_cve,
                  update_securityfocus_database=update_securityfocus_database,
                  create_securityfocus_database=create_securityfocus_database,
                  download_vulnerability_entry=download_vulnerability_entry
                  )

parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument("--dest-folder", dest="dest_folder")
parser.add_argument("--id", dest="bugtraq_id", help="The bugtraq id of the vulnerability to fetch.")
parser.add_argument('-i', '--input-path', dest='input_path',
                    help='Data source path (vane import)')
parser.add_argument('-f', '--input-file', dest='input_file',
                    help='Cached input file')

args = parser.parse_args()

try:
    local = app.sub(repository=WordPressRepository,
                    vane_importer=VaneImporter,
                    input_path=args.input_path,
                    input_file=args.input_file,
                    bugtraq_id=args.bugtraq_id,
                    dest_folder=args.dest_folder)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
