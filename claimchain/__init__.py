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

	all_body = encode([encbody, tag])

	return (vrfkey, lookup_key, all_body)

def decode_claim(G, pub, nonce, claim_key, vrfkey, claim_ciphertext):
	aes = Cipher("aes-128-gcm")
	nkey = encode([nonce, claim_key])
	[encrypted_body, tag] = decode(claim_ciphertext)
	
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

def lookup_capability(G, DHa, DHb_sec, nonce, claim_key):
	aes = Cipher("aes-128-gcm")
	Kab = sha256((DHb_sec * DHa).export()).digest()[:16]

	secret_lookup = sha256("lookup|%s|%s|%s" % (Kab, nonce, claim_key)).digest()
	return secret_lookup

def encode_capability(G, DHa_sec, DHb, nonce, claim_key, vrfkey):
	aes = Cipher("aes-128-gcm")
	Kab = sha256((DHa_sec * DHb).export()).digest()[:16]

	secret_lookup = sha256("lookup|%s|%s|%s" % (Kab, nonce, claim_key)).digest()
	secret_key = sha256("key|%s|%s|%s" % (Kab, nonce, claim_key)).digest()[:16]

	encbody, tag = aes.quick_gcm_enc(secret_key, b"\x00"*16, vrfkey)
	return secret_lookup, encode([encbody, tag])

def decode_capability(G, DHa, DHb_sec, nonce, claim_key, ciphertext):
	aes = Cipher("aes-128-gcm")
	Kab = sha256((DHb_sec * DHa).export()).digest()[:16]

	# secret_lookup = sha256("lookup|%s|%s|%s" % (Kab, nonce, claim_key)).digest()
	secret_key = sha256("key|%s|%s|%s" % (Kab, nonce, claim_key)).digest()[:16]

	encbody, tag = decode(ciphertext)
	body = aes.quick_gcm_dec(secret_key, b"\x00"*16, encbody, tag)
	return body