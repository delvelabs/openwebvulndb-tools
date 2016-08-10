from packaging.version import parse


class VersionCompare:

    @staticmethod
    def sorted(list):
        return [str(s) for s in sorted(parse(v) for v in list)]

    @staticmethod
    def next_minor(version):
        version = parse(version)
        release = version._version.release

        if len(release) == 1:
            major = release[0]
            minor = 0
        elif len(release) >= 2:
            major = release[0]
            minor = release[1]
        version._version = version._version._replace(release=(major, minor + 1))
        return version.base_version
