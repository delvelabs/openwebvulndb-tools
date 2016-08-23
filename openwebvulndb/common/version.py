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
