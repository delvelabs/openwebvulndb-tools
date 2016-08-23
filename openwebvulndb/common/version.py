from packaging.version import parse


class VersionCompare:

    @staticmethod
    def sorted(list):
        return [str(v) for s, v in sorted((parse(v), v) for v in list)]

    @staticmethod
    def next_minor(version):
        offset = 0
        if version[0] == ".":
            version = "0" + version
            offset = 1

        version = parse(version)
        if isinstance(version._version, str):
            raise TypeError(version)

        release = version._version.release

        if len(release) == 1:
            major = release[0]
            minor = 0
        elif len(release) >= 2:
            major = release[0]
            minor = release[1]
        version._version = version._version._replace(release=(major, minor + 1))
        return version.base_version[offset:]
