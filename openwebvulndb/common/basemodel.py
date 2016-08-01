


def _clean(item):
    return {key: value for key, value in item.__dict__.items() if key[0] != "_"}


class Model:

    def __init__(self, **kwargs):
        self.init(**kwargs)
        self._dirty = False

    def __eq__(self, other):
        # Skip internal properties (such as _dirty) on equality checks

        return _clean(self) == _clean(other)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "{name}({content})".format(name=self.__class__.__name__,
                                          content=str(_clean(self))[1:-1])

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
