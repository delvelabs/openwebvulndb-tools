

class NetworkError(Exception):
    pass


class VersionNotFound(Exception):
    pass


class VulnerabilityNotFound(Exception):
    pass


class SoftwareNotFound(Exception):
    pass


class ExecutionFailure(Exception):
    pass


class DirectoryExpected(ExecutionFailure):
    # SVN related
    pass
