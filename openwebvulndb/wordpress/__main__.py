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

import os
from argparse import ArgumentParser
from os.path import join
from datetime import date, timedelta

from openwebvulndb import app
from openwebvulndb.common.release import GitHubRelease
from .repository import WordPressRepository
from .vane import VaneImporter, VaneVersionRebuild
from .vane2.exporter import Exporter
from ..common.config import EXPORT_PATH
from ..common.logs import logger
from ..common.parallel import ParallelWorker
from ..common.securityfocus.database_tools import update_securityfocus_database, download_vulnerability_entry
from ..common.versionbuilder import VersionBuilder


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


def vane2_export(storage, aiohttp_session, loop, create_release=False, target_commitish=None, release_version=None):
    export_path = EXPORT_PATH
    os.makedirs(export_path, exist_ok=True)
    exporter = Exporter(storage)

    environment_variables = ["VANE2_REPO_OWNER", "VANE2_REPO_NAME", "VANE2_REPO_PASSWORD"]
    for env_variable in environment_variables:
        if env_variable not in os.environ:
            logger.error("%s environment variable must be defined to push Vane2 data to repository." % env_variable)
            return

    exporter.export_wordpress(export_path)
    exporter.dump_meta("wordpress", export_path)

    exporter.export_plugins(export_path, only_popular=True)
    exporter.export_plugins(export_path, only_vulnerable=True)
    exporter.export_plugins(export_path)
    exporter.dump_meta("plugins", export_path)

    exporter.export_themes(export_path, only_popular=True)
    exporter.export_themes(export_path, only_vulnerable=True)
    exporter.export_themes(export_path)
    exporter.dump_meta("themes", export_path)
    
    exporter.export_vulnerabilities(export_path)

    github_release = GitHubRelease(aiohttp_session)
    github_release.set_repository_settings(os.environ["VANE2_REPO_OWNER"], os.environ["VANE2_REPO_PASSWORD"],
                                           os.environ["VANE2_REPO_NAME"])
    try:
        loop.run_until_complete(github_release.release_data(export_path, "vane2_data_", create_release,
                                                            target_commitish, release_version or str(date.today())))
        logger.info("Vane data successfully released.")
    except (Exception, RuntimeError, ValueError) as e:
        logger.exception(e)
    aiohttp_session.close()


def populate_versions(loop, repository_hasher, storage, subversion, interval, wp_only):
    async def load_input():
        worker = ParallelWorker(8, loop=loop, timeout_per_job=1800)  # Half an hour at most
        meta = storage.read_meta("wordpress")
        await worker.request(repository_hasher.collect_from_meta, meta)
        if not wp_only:
            meta = storage.read_meta("mu")
            await worker.request(repository_hasher.collect_from_meta, meta)

            plugins = await subversion.get_plugins_with_new_release(date.today() - timedelta(days=interval))
            themes = await subversion.get_themes_with_new_release(date.today() - timedelta(days=interval))
            task_list = plugins | themes
            metas = list(storage.list_meta("plugins")) + list(storage.list_meta("themes"))
            existing_keys = {meta.key for meta in metas}
            task_list &= existing_keys

            for key in task_list:
                meta = storage.read_meta(key)
                await worker.request(repository_hasher.collect_from_meta, meta, prefix_pattern="wp-content/{meta.key}")
        await worker.wait()

    loop.run_until_complete(load_input())


def load_cve(loop, cve_reader, input_file):
    cve_reader.groups = ["plugins", "themes"]
    if input_file:
        cve_reader.read_file(input_file)
    else:
        loop.run_until_complete(cve_reader.read_api("http://cve.circl.lu/api/search/wordpress/wordpress"))


def change_version_format(storage):
    version_builder = VersionBuilder()
    for key, path, dirs, files in storage.walk():
        if "versions.json" in files:
            version_list = storage.read_version_list(key)
            file_list = version_builder.create_file_list_from_version_list(version_list, producer=version_list.producer)
            if file_list is None:
                storage.remove(key, "versions.json")
            else:
                storage.write_versions(file_list)

operations = dict(list_themes=list_themes,
                  list_plugins=list_plugins,
                  vane_import=vane_import,
                  vane_export=vane_export,
                  vane2_export=vane2_export,
                  populate_versions=populate_versions,
                  load_cve=load_cve,
                  update_securityfocus_database=update_securityfocus_database,
                  download_vulnerability_entry=download_vulnerability_entry,
                  change_version_format=change_version_format
                  )

parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument("--dest-folder", dest="dest_folder")
parser.add_argument("--id", dest="bugtraq_id", help="The bugtraq id of the vulnerability to fetch.")
parser.add_argument("--pages-to-fetch", dest="vulnerabilities_pages_to_fetch",
                    help="Amount of pages of latest vulnerabilities on security focus website to fetch to update "
                         "the database (1 by default, -1 for all pages).", default=1, type=int)
parser.add_argument("-i", "--input-path", dest="input_path",
                    help="Data source path (vane import)")
parser.add_argument("-f", "--input-file", dest="input_file",
                    help="Cached input file")
parser.add_argument("--create-release", dest="create_release", action="store_true", help="Create a new GitHub release")
parser.add_argument("--target-commitish", dest="target_commitish", help="Branch name or SHA number of the commit used "
                                                                        "for the new release", default="master")
parser.add_argument("--release-version", dest="release_version", help="Version number for the new release. The "
                                                                      "current is used by default.")
parser.add_argument("--interval", dest="interval", help="The interval in days since the last update of plugins and "
                                                        "themes versions. 30 days by default", default=30, type=int)
parser.add_argument("-w", "--wp-only", dest="wp_only", help="Only populate versions for WordPress core, skip plugins "
                                                            "and themes", action="store_true")

args = parser.parse_args()

try:
    local = app.sub(repository=WordPressRepository,
                    vane_importer=VaneImporter,
                    input_path=args.input_path,
                    input_file=args.input_file,
                    bugtraq_id=args.bugtraq_id,
                    vulnerabilities_pages_to_fetch=args.vulnerabilities_pages_to_fetch,
                    dest_folder=args.dest_folder,
                    create_release=args.create_release,
                    target_commitish=args.target_commitish,
                    release_version=args.release_version,
                    interval=args.interval,
                    wp_only=args.wp_only,
                    )
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
