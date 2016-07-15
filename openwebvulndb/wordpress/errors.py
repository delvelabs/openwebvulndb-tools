from ..common.errors import SoftwareNotFound, NetworkError


class PluginNotFound(SoftwareNotFound):
    pass


class RepositoryUnreachable(NetworkError):
    pass
