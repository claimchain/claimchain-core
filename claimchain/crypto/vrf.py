from attr import attrs, attrib
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from hashlib import sha256

from .params import PublicParams, LocalParams


@attrs
class VrfContainer(object):
    value = attrib()
    proof = attrib()


def do_vrf_compute( message, local_params=None, pp=None):
    pp = pp or PublicParams.get_default()
    local_params = local_params or LocalParams.get_default()

    G = pp.ec_group
    g = G.generator()
    k = local_params.vrf.sk
    pub = local_params.vrf.pk
    h = G.hash_to_point(b"1||" + message)
    v = k * h
    r = G.order().random()
    R = r * g
    Hr = r * h
    s = Bn.from_binary(sha256(encode([g, h, pub, v, R, Hr])).digest())
    t = (r - s * k) % G.order()
    return VrfContainer(value=v.export(), proof=encode((s, t)))


def do_vrf_verify(pub, vrf, message, pp=None):
    pp = pp or PublicParams.get_default()

    G = pp.ec_group
    g = G.generator()
    h = G.hash_to_point(b"1||" + message)
    v = EcPt.from_binary(vrf.value, G)
    s, t = decode(vrf.proof)
    R = t*g + s*pub
    Hr = t*h + s*v
    s2 = Bn.from_binary(sha256(encode([g, h, pub, v, R, Hr])).digest())
    return s2 == s
