# The claimchain core package

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from hashlib import sha256

model_claim_block = {
	"Version": "1.0",
	"Metadata": None,
	"TreeHead": None,
	"ChainInfo": None
}

def VRF_compute(G, k, pub, message):
	g = G.generator()
	h = G.hash_to_point("1||" + message)
	v = k * h
	r = G.order().random()
	R = r * g
	Hr = r * h
	s = Bn.from_binary(sha256(encode([ g, h, pub, v, R, Hr ])).digest())
	t = (r - s * k) % G.order()
	return v.export(), encode((s, t))

def VRF_verify(G, pub, message, value, proof):
	g = G.generator()
	h = G.hash_to_point("1||" + message)
	v = EcPt.from_binary(value, G)
	s, t = decode(proof)
	R = t*g + s*pub
	Hr = t*h + s*v
	s2 = Bn.from_binary(sha256(encode([ g, h, pub, v, R, Hr ])).digest())
	return s2 == s


def void():
	pass