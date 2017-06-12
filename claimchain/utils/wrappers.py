import hippiehug
from hippiehug.Utils import binary_hash

from .encodings import ensure_binary


class Blob(bytes):
    @property
    def hid(self):
        return binary_hash(self)


def _check_hash(key, value):
    if value.hid != key:
        raise ValueError('Hash of the value is not the lookup key')


class ObjectStore(object):
    """
    >>> store = ObjectStore()
    >>> blob = Blob(b'test')
    >>> store.add(blob)
    >>> store[blob.hid]
    b'test'
    """
    def __init__(self, backend=None):
        self.backend = backend
        if backend is None:
            self.backend = {}

    def __getitem__(self, lookup_key):
        value = self.backend[lookup_key]
        _check_hash(lookup_key, value)
        return value

    def __setitem__(self, lookup_key, value):
        _check_hash(lookup_key, value)
        self.backend[lookup_key] = value

    def add(self, value):
        lookup_key = value.hid
        self.backend[lookup_key] = value


class Chain(object):
    def __init__(self, object_store=None):
        self.object_store = object_store or ObjectStore()


class Tree(object):
    """
    Wrapper to enable map interface on top of Hippiehug trees

    >>> tree = Tree()
    >>> tree[b'label'] = Blob(b'test')
    >>> tree[b'label']
    b'test'
    >>> b'label' in tree
    True
    >>> tree1 = Tree(tree.object_store, root_hash=tree.root_hash)
    >>> b'label' in tree1
    True
    >>> tree.evidence(b'label') is not None
    True
    """
    def __init__(self, object_store=None, root_hash=None):
        self.object_store = object_store
        if object_store is None:
            self.object_store = ObjectStore()
        self.tree = hippiehug.Tree(self.object_store, root_hash=root_hash)

    @property
    def root_hash(self):
        return self.tree.root()

    def __getitem__(self, lookup_key):
        lookup_key = ensure_binary(lookup_key)

        _, evidence = self.tree.evidence(key=lookup_key)
        value_hash = evidence[-1].item
        if evidence[-1].key != lookup_key:
            raise KeyError(lookup_key)
        return self.tree.store[value_hash]

    def __setitem__(self, lookup_key, value):
        lookup_key = ensure_binary(lookup_key)
        if not hasattr(value, 'hid'):
            raise TypeError('Value is not a valid object.')

        self.tree.add(key=lookup_key, item=value)
        _, evidence = self.tree.evidence(key=lookup_key)
        assert self.tree.is_in(value, key=lookup_key)
        value_hash = evidence[-1].item
        assert value_hash == value.hid
        self.tree.store[value_hash] = value

    def __contains__(self, lookup_key):
        lookup_key = ensure_binary(lookup_key)
        _, evidence = self.tree.evidence(key=lookup_key)
        leaf = evidence[-1]
        return leaf.key == lookup_key

    def evidence(self, lookup_key):
        return self.tree.evidence(key=lookup_key)
