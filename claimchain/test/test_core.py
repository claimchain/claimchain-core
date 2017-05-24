from petlib.ec import EcGroup
from .. import VRF_compute, VRF_verify

def test_access():
	assert True

def test_VRF():
	G = EcGroup()
	k = G.order().random()
	pub = k * G.generator()
	value, proof = VRF_compute(G, k, pub, "test@test.com")
	assert VRF_verify(G, pub, "test@test.com", value, proof)
