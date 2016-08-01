from packaging.version import parse


class VersionCompare:

    @staticmethod
    def sorted(list):
        print(sorted(parse(v) for v in list))
        return [str(s) for s in sorted(parse(v) for v in list)]
