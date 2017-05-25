from petlib.ec import EcGroup
from .. import VRF_compute, VRF_verify, encode_claim, decode_claim
from .. import encode_capability, decode_capability, lookup_capability


def test_access():
	assert True


def test_VRF():
	G = EcGroup()
	k = G.order().random()
	pub = k * G.generator()
	value, proof = VRF_compute(G, k, pub, b"test@test.com")
	assert VRF_verify(G, pub, b"test@test.com", value, proof)


def test_encode_claim():
	G = EcGroup()
	k = G.order().random()
	pub = k * G.generator()
	nonce = b"xxx"
	claim_key = b"george@gmail.com"
	claim_body = b"XXXXX"

	enc = encode_claim(G, pub, k, nonce, claim_key, claim_body)
	vrfkey, lookupkey, encrypted_body  = enc

	claim2 = decode_claim(G, pub, nonce, claim_key, vrfkey, encrypted_body)
	assert claim2 == claim_body


def test_encode_cap():
	G = EcGroup()
	ka = G.order().random()
	puba = ka * G.generator()
	kb = G.order().random()
	pubb = kb * G.generator()

	nonce = b"xxx"
	claim_key = b"yyy"
	vrfkey = b"zzz"

	key, ciphertext = encode_capability(G, ka, pubb, nonce, claim_key, vrfkey)

	key2 = lookup_capability(G, puba, kb, nonce, claim_key)
	assert key == key2

	vrfkey2 = decode_capability(G, puba, kb, nonce, claim_key, ciphertext)
	assert vrfkey == vrfkey2
