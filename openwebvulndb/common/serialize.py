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

import json


def serialize(schema, data, *, indent=4):
    data, errors = schema.dump(data)
    clean_walk(data)
    return json.dumps(data, indent=indent), errors


def clean_walk(data):
    if isinstance(data, list):
        for item in data:
            clean_walk(item)
    elif isinstance(data, dict):
        to_remove = set()
        for key, val in data.items():
            if val is None or val == []:
                to_remove.add(key)
            else:
                clean_walk(val)

        for key in to_remove:
            del data[key]
