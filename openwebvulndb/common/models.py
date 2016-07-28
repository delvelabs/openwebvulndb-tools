from .errors import VulnerabilityNotFound


class Model:

    def __init__(self, **kwargs):
        self.init(**kwargs)
        self._dirty = False

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "{name}({content})".format(name=self.__class__.__name__,
                                          content=str(self.__dict__)[1:-1])

    def __setattr__(self, attr, value):
        # Not fully initalized yet, let anything happen
        if not hasattr(self, '_dirty'):
            super().__setattr__(attr, value)
            return

        # If the attribute is not declared after initialization, we don't want it
        if not hasattr(self, attr):
            raise AttributeError(attr)

        # If the value is different, change it and flag dirty
        if getattr(self, attr) != value:
            super().__setattr__(attr, value)
            super().__setattr__('_dirty', True)

    def clean(self):
        super().__setattr__('_dirty', False)
        for c in self.children:
            c.clean()

    @property
    def dirty(self):
        return self._dirty or any(c.dirty for c in self.children)

    @property
    def children(self):
        return []


class Meta(Model):

    def init(self, *, key, name=None, url=None, repositories=None):
        self.key = key
        self.name = name
        self.url = url
        self.repositories = repositories or []


class Repository(Model):

    def init(self, *, type, location):
        self.type = type
        self.location = location


class VulnerabilityList(Model):

    def init(self, *, producer, key, vulnerabilities=None):
        self.producer = producer
        self.key = key
        self.vulnerabilities = vulnerabilities or []

    def get_vulnerability(self, id, *, create_missing=False):
        id = str(id)

        for v in self.vulnerabilities:
            if v.id == id:
                return v

        if not create_missing:
            raise VulnerabilityNotFound(id)

        vuln = Vulnerability(id=id)
        self.vulnerabilities.append(vuln)
        return vuln

    @property
    def children(self):
        return self.vulnerabilities


class Vulnerability(Model):

    def init(self, *, id, title=None, references=None, updated_at=None, created_at=None):
        self.id = id
        self.title = title
        self.updated_at = updated_at
        self.created_at = created_at
        self.references = references or []

    @property
    def children(self):
        return self.references


class Reference(Model):

    def init(self, *, type=None, id=None, url=None):
        self.type = type
        self.id = id
        self.url = url
