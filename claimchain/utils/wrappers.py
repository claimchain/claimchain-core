from hippiehug import Tree
from .encodings import ensure_binary


class VerifiableMap(object):
    """
    Wrapper to enable map interface on top of Hippiehug trees

    >>> tree = Tree()
    >>> vmap = VerifiableMap(tree)
    >>> vmap['label'] = 'test'
    >>> vmap['label']
    b'test'
    >>> 'label' in vmap
    True
    """

    def __init__(self, hippiehug_tree):
        self.tree = hippiehug_tree

    def __getitem__(self, lookup_key):
        lookup_key = ensure_binary(lookup_key)

        _, evidence = self.tree.evidence(key=lookup_key)
        value_hash = evidence[-1].item
        if evidence[-1].key != lookup_key:
            raise KeyError(lookup_key)
        return self.tree.store[value_hash]

    def __setitem__(self, lookup_key, value):
        lookup_key = ensure_binary(lookup_key)
        value = ensure_binary(value)

        self.tree.add(key=lookup_key, item=value)
        _, evidence = self.tree.evidence(key=lookup_key)
        assert self.tree.is_in(value, key=lookup_key)
        value_hash = evidence[-1].item
        self.tree.store[value_hash] = value

    def __contains__(self, lookup_key):
        lookup_key = ensure_binary(lookup_key)

        _, evidence = self.tree.evidence(key=lookup_key)
        leaf = evidence[-1]
        return leaf.key == lookup_key
