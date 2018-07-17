"""
Containers for cryptographic key material.
"""

import os
import base64
import attr

from hashlib import sha256

from defaultcontext import with_default_context
from petlib.cipher import Cipher
from petlib.ec import EcGroup, EcPt
from petlib.pack import encode, decode

from claimchain.utils import pet2ascii, ascii2pet


@with_default_context(use_empty_init=True)
@attr.s
class PublicParams(object):
    """Public parameters of the system."""
    ec_group = attr.ib(default=attr.Factory(EcGroup))
    hash_func = attr.ib(default=attr.Factory(lambda: sha256))
    enc_cipher = attr.ib(default=attr.Factory(lambda: Cipher("aes-128-gcm")))
    enc_key_size = attr.ib(default=16)
    prf_key_size = attr.ib(default=16)
    lookup_key_size = attr.ib(default=8)
    nonce_size = attr.ib(default=16)


@attr.s
class Keypair(object):
    """Asymmetric key pair.

    :param pk: Public key
    :param sk: Private key
    """
    pk = attr.ib()
    sk = attr.ib(default=None)

    @staticmethod
    def generate():
        """Generate a key pair."""
        pp = PublicParams.get_default()
        G = pp.ec_group
        sk = G.order().random()
        pk = sk * G.generator()
        return Keypair(sk=sk, pk=pk)


@attr.s
class PrfKey(object):
    """Symmetric PRF key.

    :param sk: The key
    """
    sk = attr.ib()

    @staticmethod
    def generate():
        """Generate a key."""
        pp = PublicParams.get_default()
        sk = os.urandom(pp.prf_key_size)
        return PrfKey(sk=sk)


@with_default_context
@attr.s
class LocalParams(object):
    """ClaimChain user's cryptographic material.

    :param Keypair vrf: VRF key pair
    :param Keypair sig: Signing key pair
    :param Keypair dh: DH key pair
    :param Keypair rescue: Rescue key pair (not used)
    """
    vrf = attr.ib(default=None)
    sig = attr.ib(default=None)
    dh = attr.ib(default=None)
    prf = attr.ib(default=None)
    rescue = attr.ib(default=None)

    @staticmethod
    def generate():
        """Generate key pairs."""
        pp = PublicParams.get_default()
        return LocalParams(
            vrf = Keypair.generate(),
            sig = Keypair.generate(),
            dh = Keypair.generate(),
            prf = PrfKey.generate(),
            rescue = Keypair.generate()
        )

    def public_export(self):
        """Export public keys to dictionary."""
        return self._export(private=False)

    def private_export(self):
        """Export public and private keys to dictionary."""
        return self._export(private=True)

    def _export(self, private=False):
        result = {}
        for name, attr in asdict(self, recurse=False).items():
            if isinstance(attr, Keypair):
                result[name + '_pk'] = pet2ascii(attr.pk)
                if private:
                    result[name + '_sk'] = pet2ascii(attr.sk)
            elif isinstance(attr, PrfKey) and private:
                result[name + '_sk'] = attr.sk

        return result

    @staticmethod
    def from_dict(exported):
        """Import from dictionary.

        :param dict exported: Exported params
        """
        def maybe_decode(encoded_point):
            if encoded_point is not None:
                return ascii2pet(encoded_point)

        def maybe_load_keypair(prefix):
            keypair = Keypair(
                    pk = maybe_decode(exported.get(prefix + '_pk')),
                    sk = maybe_decode(exported.get(prefix + '_sk')))
            if keypair.pk is not None or keypair.sk is not None:
                return keypair

        def maybe_load_prf_key(prefix):
            keypair = PrfKey(sk=exported.get(prefix + '_sk'))
            if keypair.sk is not None:
                return keypair

        params = LocalParams()
        params.vrf = maybe_load_keypair('vrf')
        params.sig = maybe_load_keypair('sig')
        params.dh = maybe_load_keypair('dh')
        params.prf = maybe_load_prf_key('prf')
        params.rescue = maybe_load_keypair('rescue')
        return params

