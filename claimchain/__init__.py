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

from petlib.cipher import Cipher

def encode_claim(G, pub, k, nonce, claim_key, claim_body):
	aes = Cipher("aes-128-gcm")
	nkey = encode([nonce, claim_key])
	vrfkey, proof = VRF_compute(G, k, pub, nkey)
	lookup_key = sha256("LKey||" + vrfkey).digest()[:8]
	encryption_key = sha256("EKey||" + vrfkey).digest()[:16]

	claim = encode([proof, claim_body])
	encbody, tag = aes.quick_gcm_enc(encryption_key, b"\x00"*16, claim)

	return (vrfkey, lookup_key, encbody, tag)

def decode_claim(G, pub, nonce, claim_key, vrfkey, encrypted_body, tag):
	aes = Cipher("aes-128-gcm")
	nkey = encode([nonce, claim_key])
	
	# vrfkey, proof = VRF_compute(G, k, pub, nkey)
	lookup_key = sha256("LKey||" + vrfkey).digest()[:8]
	encryption_key = sha256("EKey||" + vrfkey).digest()[:16]

	#claim = encode([vrfkey, proof, claim_key, claim_body])
	decbody = aes.quick_gcm_dec(encryption_key, b"\x00"*16, encrypted_body, tag)
	[proof, claim_body] = decode(decbody)

	nkey = encode([nonce, claim_key])
	if not VRF_verify(G, pub, nkey, vrfkey, proof):
		raise Exception("Wrong VRF Value")

	return claim_body