import hippiehug
from hippiehug.Utils import binary_hash

from .encodings import ensure_binary


# TODO: Move to hippiehug 1.0
# TODO: Move the tests out of doctests


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
        self._backend = backend
        if backend is None:
            self._backend = {}

        # Check hashes if it is a plain dictionary
        if not isinstance(self._backend, ObjectStore):
            for lookup_key, value in self._backend.items():
                _check_hash(lookup_key, value)
        else:
            # If input is another ObjectStore, unwrap the
            # underlying dictionary
            self._backend = self._backend._backend

    def __getitem__(self, lookup_key):
        value = self._backend[lookup_key]
        _check_hash(lookup_key, value)
        return value

    def get(self, lookup_key):
        try:
            return self._backend[lookup_key]
        except KeyError:
            return None

    def __setitem__(self, lookup_key, value):
        _check_hash(lookup_key, value)
        self._backend[lookup_key] = value

    def keys(self):
        return self._backend.keys()

    def values(self):
        return self._backend.values()

    def items(self):
        return self._backend.items()

    def add(self, value):
        lookup_key = value.hid
        self._backend[lookup_key] = value



# TODO: (Higher priority) move this to hippiehug classes themselves
def serialize_object(obj):
    """
    Serialize blobs, hippiehug tree nodes, and hippiehug chain blocks

    >>> block = hippiehug.Block([])
    >>> len(serialize_object(block))
    4
    >>> node = hippiehug.Nodes.Branch(b'pivot', b'left', b'right')
    >>> len(serialize_object(node))
    3
    >>> leaf = hippiehug.Nodes.Leaf(b'item', b'key')
    >>> len(serialize_object(leaf))
    2
    >>> blob = Blob(b'content')
    >>> serialize_object(blob) == blob
    True

    .. warning::

    There is no guarantee this is in sync with hippiehug, i.e., this
    is the serialization hippiehug employs internally. This will eventually
    move inside the hippiehug library.

    """
    if isinstance(obj, hippiehug.Nodes.Leaf):
        return (obj.key, obj.item)
    elif isinstance(obj, hippiehug.Nodes.Branch):
        return (obj.pivot, obj.left_branch, obj.right_branch)
    elif isinstance(obj, hippiehug.Block):
        return (obj.index, obj.fingers, obj.items, obj.aux)
    elif isinstance(obj, Blob):
        return obj


class Chain(object):
    def __init__(self, object_store=None):
        self.object_store = object_store or ObjectStore()


class Tree(object):
    """
    Wrapper to enable map interface on top of Hippiehug trees

    >>> tree = Tree()
    >>> b'label' in tree
    False
    >>> tree[b'label']
    Traceback (most recent call last):
    KeyError: b'label'
    >>> tree[b'label'] = Blob(b'test')
    >>> tree[b'label']
    b'test'
    >>> b'label' in tree
    True

    Creating a tree from existing storage:

    >>> tree1 = Tree(tree.object_store, root_hash=tree.root_hash)
    >>> b'label' in tree1
    True
    >>> tree.evidence(b'label') is not None
    True

    Adding multiple items at once:

    >>> b'label1' in tree
    False
    >>> b'label2' in tree
    False
    >>> tree.update({'label1': Blob(b'test1'), 'label2': Blob(b'test2')})
    >>> b'label1' in tree
    True
    >>> b'label2' in tree
    True
    >>> tree[b'label1']
    b'test1'
    >>> tree[b'label2']
    b'test2'
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
        _, evidence = self.evidence(lookup_key)
        if not evidence or evidence[-1].key != lookup_key:
            raise KeyError(lookup_key)
        value_hash = evidence[-1].item
        return self.tree.store[value_hash]

    def __setitem__(self, lookup_key, value):
        """
        Add value with given lookup key.

        TODO: Add transactions. If this fails or stops at some point,
        storage will be left in a screwed up state.

        :param value: An object with ``hid`` property (e.g. ``Blob`` object)
        """
        lookup_key = ensure_binary(lookup_key)
        if not hasattr(value, 'hid'):
            raise TypeError('Value is not a valid object.')

        self.tree.add(key=lookup_key, item=value)
        _, evidence = self.evidence(lookup_key)
        assert self.tree.is_in(value, key=lookup_key)
        value_hash = evidence[-1].item

        # This should only happen if hashing here and in hippiehug
        # become inconsistent because of internal changes in hippiehug
        # TODO: Remove when hashing when changes here are moved to
        # hippiehug
        assert value_hash == value.hid

        self.tree.store[value_hash] = value

    def update(self, items):
        """
        Add multiple values.

        TODO: Add transactions. If this fails or stops at some point,
        storage will be left in a screwed up state.

        :param items: dictionary, where the values are objects with
                      ``hid`` property (e.g. ``Blob`` objects)
        """
        items = {ensure_binary(key): value for key, value in items.items()}
        for value in items.values():
            if not hasattr(value, 'hid'):
                raise TypeError('Value is not a valid object.')
            self.tree.store[value.hid] = value

        if len(items) > 0:
            self.tree.multi_add(list(items.values()), list(items.keys()))

    def __contains__(self, lookup_key):
        lookup_key = ensure_binary(lookup_key)
        _, evidence = self.evidence(lookup_key)
        return evidence != [] and evidence[-1].key == lookup_key

    def evidence(self, lookup_key):
        result = self.tree.evidence(key=lookup_key)
        if not result:
            result = None, []
        return result


def check_evidence(root_hash, evidence, lookup_key):
    """
    >>> tree = Tree()
    >>> tree[b'label'] = Blob(b'test')
    >>> root_hash, evidence = tree.evidence(b'label')
    >>> check_evidence(root_hash, evidence, b'label')
    True
    >>> check_evidence(root_hash, evidence, b'label1')
    False
    """
    lookup_key = ensure_binary(lookup_key)
    store = {node.identity(): node for node in evidence}
    tree = Tree(store, root_hash=root_hash)
    return lookup_key in tree
