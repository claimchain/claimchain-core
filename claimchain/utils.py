import six
from base58 import b58encode, b58decode
from petlib.pack import encode, decode
from hippiehug import Tree


def ensure_binary(s):
    """
    >>> ensure_binary(b"test")
    b'test'
    >>> ensure_binary(u"test")
    b'test'
    """
    if not isinstance(s, six.binary_type):
        s = s.encode('utf-8')
    return s


def bytes2ascii(s):
    """
    >>> bytes2ascii(b"test")
    '3yZe7d'
    """
    return b58encode(s)


def ascii2bytes(s):
    """
    >>> ascii2bytes('3yZe7d')
    b'test'
    """
    return b58decode(s)


def pet2ascii(p):
    """
    >>> from petlib.ec import EcGroup, EcPt
    >>> G = EcGroup()
    >>> pt = EcPt(G)
    >>> pet2ascii(pt)
    '3Xw3vNAdCmDLs'
    """
    return b58encode(encode(p))


def ascii2pet(s):
    """
    >>> ascii2pet('3Xw3vNAdCmDLs')
    EcPt(00)
    """
    return decode(b58decode(s))


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
