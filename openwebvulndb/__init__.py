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

import asyncio
import aiohttp
from easyinject import Injector
from .common import Storage, RepositoryChecker, Subversion, VulnerabilityManager, RepositoryHasher
from .common.parallel import BackgroundRunner
from .common.cve import CVEReader
from .wordpress.vane2.release import GitHubRelease

app = Injector(storage=Storage,
               loop=asyncio.get_event_loop,
               background_runner=BackgroundRunner,
               repository_checker=RepositoryChecker,
               cve_reader=CVEReader,
               subversion=Subversion,
               vulnerability_manager=VulnerabilityManager,
               aiohttp_session=aiohttp.ClientSession,
               repository_hasher=RepositoryHasher,
               github_release=GitHubRelease)
