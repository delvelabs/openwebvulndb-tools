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

from packaging.version import parse


class VersionCompare:

    @staticmethod
    def sorted(list):
        return [str(v) for s, v in sorted((parse(v), v) for v in list)]

    @classmethod
    def next_minor(cls, version):
        def manipulate(version):
            release = version._version.release

            if len(release) == 1:
                major = release[0]
                minor = 0
            elif len(release) >= 2:
                major = release[0]
                minor = release[1]
            version._version = version._version._replace(release=(major, minor + 1))

        return cls._apply_next(version, manipulate)

    @classmethod
    def next_revision(cls, version):
        def manipulate(version):
            release = version._version.release

            minor = 0
            revision = 0
            if len(release) >= 1:
                major = release[0]
            if len(release) >= 2:
                minor = release[1]
            if len(release) >= 3:
                revision = release[2]

            version._version = version._version._replace(release=(major, minor, revision + 1))

        return cls._apply_next(version, manipulate)

    @staticmethod
    def _apply_next(version, manipulate):
        offset = 0
        if version[0] == ".":
            version = "0" + version
            offset = 1

        version = parse(version)
        if isinstance(version._version, str):
            raise TypeError(version)

        manipulate(version)
        return version.base_version[offset:]
