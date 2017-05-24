from petlib.ec import EcGroup
from .. import VRF_compute, VRF_verify, encode_claim, decode_claim

def test_access():
	assert True

def test_VRF():
	G = EcGroup()
	k = G.order().random()
	pub = k * G.generator()
	value, proof = VRF_compute(G, k, pub, "test@test.com")
	assert VRF_verify(G, pub, "test@test.com", value, proof)

def test_encode_claim():
	G = EcGroup()
	k = G.order().random()
	pub = k * G.generator()
	nonce = "xxx"
	claim_key = "george@gmail.com"
	claim_body = "XXXXX"

	enc = encode_claim(G, pub, k, nonce, claim_key, claim_body)
	vrfkey, lookupkey, encrypted_body, tag  = enc

	decode_claim(G, pub, nonce, claim_key, vrfkey, encrypted_body, tag)