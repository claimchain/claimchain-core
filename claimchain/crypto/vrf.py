"""
Implementation of a CONIKS's verifiable random function scheme.
"""

from attr import attrs, attrib
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode
from profiled import profiled

from hashlib import sha256

from claimchain.utils import ensure_binary
from claimchain.crypto.utils import hash_to_bn
from claimchain.crypto.params import PublicParams, LocalParams


@attrs
class VrfContainer(object):
    """VRF value (hash) and proof.

    :param bytes value: Exported VRF value (hash)
    :param bytes proof: Exported VRF proof
    """
    value = attrib()
    proof = attrib()


@profiled
def compute_vrf(message):
    """Compute VRF.

    Produces a VRF value (hash) and a proof.

    :param bytes message: Message
    :return: :py:class:`VrfContainer`
    """
    pp = PublicParams.get_default()
    local_params = LocalParams.get_default()
    message = ensure_binary(message)

    G = pp.ec_group
    g = G.generator()
    z = G.hash_to_point(message)

    sk = local_params.vrf.sk
    pk = local_params.vrf.pk

    h = sk * z

    r = G.order().random()
    R = r * g
    Hr = r * z
    c = hash_to_bn(encode([g, z, pk, h, R, Hr]))
    s = r.mod_sub(c * sk, G.order())
    return VrfContainer(value=h.export(), proof=encode((c, s)))


@profiled
def verify_vrf(pk, vrf, message):
    """Verify a VRF.

    Checks whether a VRF value and a proof correspond to the message.

    :param petlib.EcPt pk: VRF public key
    :param VrfContainer vrf: VRF value and proof
    :param bytes message: Message
    """

    pp = PublicParams.get_default()
    message = ensure_binary(message)

    G = pp.ec_group
    g = G.generator()
    z = G.hash_to_point(message)

    h = EcPt.from_binary(vrf.value, G)
    c, s = decode(vrf.proof)
    R = s * g + c * pk
    Hr = s * z + c * h
    c_prime = hash_to_bn(encode([g, z, pk, h, R, Hr]))
    return c_prime == c

