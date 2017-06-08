from attr import attrs, attrib
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from hashlib import sha256

from .params import PublicParams, LocalParams
from ..utils import profiled


@attrs
class VrfContainer(object):
    value = attrib()
    proof = attrib()


@profiled
def compute_vrf(message):
    pp = PublicParams.get_default()
    local_params = LocalParams.get_default()

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


@profiled
def verify_vrf(pub, vrf, message):
    pp = PublicParams.get_default()

    G = pp.ec_group
    g = G.generator()
    h = G.hash_to_point(b"1||" + message)
    v = EcPt.from_binary(vrf.value, G)
    s, t = decode(vrf.proof)
    R = t*g + s*pub
    Hr = t*h + s*v
    s2 = Bn.from_binary(sha256(encode([g, h, pub, v, R, Hr])).digest())
    return s2 == s
