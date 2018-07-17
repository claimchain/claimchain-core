"""
Crypto utils.
"""
from hashlib import sha512
from petlib.bn import Bn


def hash_to_bn(msg):
    """
    :param bytes msg: Message to hash
    """
    return Bn.from_binary(sha512(msg).digest())

