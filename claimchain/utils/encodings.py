import six
from base58 import b58encode, b58decode
from petlib.pack import encode, decode


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
