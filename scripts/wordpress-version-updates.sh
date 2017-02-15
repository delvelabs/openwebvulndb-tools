#!/bin/bash

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

# Script used in CI

export LANG=en_US.UTF-8
export LC_NAME=en_CA.UTF-8

source bin/activate

git checkout master
git pull

pip install --ignore-installed -r requirements.txt

python -m openwebvulndb.wordpress list_plugins
python -m openwebvulndb.wordpress list_themes
python -m openwebvulndb.wordpress populate_versions

pushd data
git add -A
git commit -m 'Updating data'
popd
