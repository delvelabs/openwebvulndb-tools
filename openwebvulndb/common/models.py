

class Model:

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "{name}({content})".format(name=self.__class__.__name__,
                                          content=str(self.__dict__)[1:-1])


class Meta(Model):

    def __init__(self, *, key, name, url=None, repositories=None):
        self.key = key
        self.name = name
        self.url = url
        self.repositories = repositories or []


class Repository(Model):

    def __init__(self, *, type, location):
        self.type = type
        self.location = location
