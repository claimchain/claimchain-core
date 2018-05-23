"""
Containers for key material.
"""

import base64

from hashlib import sha256

from attr import asdict, attrs, attrib, Factory
from defaultcontext import with_default_context
from petlib.cipher import Cipher
from petlib.ec import EcGroup, EcPt
from petlib.pack import encode, decode

from claimchain.utils import pet2ascii, ascii2pet


@with_default_context(use_empty_init=True)
@attrs
class PublicParams(object):
    """Public parameters of the system."""
    ec_group = attrib(default=Factory(EcGroup))
    hash_func = attrib(default=Factory(lambda: sha256))
    enc_cipher = attrib(default=Factory(lambda: Cipher("aes-128-gcm")))
    enc_key_size = attrib(default=16)
    lookup_key_size = attrib(default=8)
    nonce_size = attrib(default=16)


@attrs
class Keypair(object):
    """Asymmetric key pair.

    :param pk: Public key
    :param sk: Private key
    """
    pk = attrib()
    sk = attrib(default=None)

    @staticmethod
    def generate():
        """Generate a key pair."""
        pp = PublicParams.get_default()
        G = pp.ec_group
        s = G.order().random()
        return Keypair(sk=s, pk=s * G.generator())


@with_default_context
@attrs
class LocalParams(object):
    """ClaimChain user's cryptographic material.

    :param Keypair vrf: VRF key pair
    :param Keypair sig: Signing key pair
    :param Keypair dh: DH key pair
    :param Keypair rescue: Rescue key pair (not used)
    """
    vrf = attrib(default=None)
    sig = attrib(default=None)
    dh = attrib(default=None)
    rescue = attrib(default=None)

    @staticmethod
    def generate():
        """Generate key pairs."""
        return LocalParams(
            vrf = Keypair.generate(),
            sig = Keypair.generate(),
            dh = Keypair.generate(),
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

        params = LocalParams()
        params.vrf = maybe_load_keypair('vrf')
        params.sig = maybe_load_keypair('sig')
        params.dh = maybe_load_keypair('dh')
        params.rescue = maybe_load_keypair('rescue')
        return params

