from petlib.ec import EcGroup
from .. import VRF_compute, VRF_verify, encode_claim, decode_claim
from .. import encode_capability, decode_capability, lookup_capability

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
	vrfkey, lookupkey, encrypted_body  = enc

	claim2 = decode_claim(G, pub, nonce, claim_key, vrfkey, encrypted_body)
	assert claim2 == claim_body

def test_encode_cap():
	G = EcGroup()
	ka = G.order().random()
	puba = ka * G.generator()
	kb = G.order().random()
	pubb = kb * G.generator()

	nonce = "xxx"
	claim_key = "yyy"
	vrfkey = "zzz"

	key, ciphertext = encode_capability(G, ka, pubb, nonce, claim_key, vrfkey)

	key2 = lookup_capability(G, puba, kb, nonce, claim_key)
	assert key == key2

	vrfkey2 = decode_capability(G, puba, kb, nonce, claim_key, ciphertext)
	assert vrfkey == vrfkey2

from os import urandom
from binascii import hexlify
from petlib.ec import EcGroup
from petlib.pack import encode
import time
import random

def rhex(l):
	return hexlify(urandom(l))[:l]

def generate_test_load():
	G = EcGroup()
	labels = ["%s@%s.com" % (rhex(8), rhex(8)) for _ in range(200)]
	heads = [urandom(20) for _ in range(200)]
	secrets = [G.order().random() for _ in range(200)]
	g = G.generator()
	pubkeys = [s * g for s in secrets]

	all_data = (labels, heads, secrets, pubkeys)

	friends = {}
	for f in range(200):
		cap = random.sample(range(200), 5)
		friends[f] = cap

	return G, friends, all_data


def test_gen_load():
	G, friends, all_data = generate_test_load()
	(labels, heads, secrets, pubkeys) = all_data

	nonce = "now1"
	k = G.order().random()
	pub = k * G.generator()

	t0 = time.time()
	c0 = 0
	enc_claims = []
	all_vrfs = []
	for claim_key, claim_body in zip(labels, heads):
		c0 += 1
		enc = encode_claim(G, pub, k, nonce, claim_key, claim_body)
		vrfkey, lookupkey, encrypted_body  = enc
		enc_claims += [(lookupkey, encrypted_body) ]

		all_vrfs += [vrfkey]
	t1 = time.time()
	print("\n\t\tTiming per encoded claim: %1.1f ms" % ((t1-t0) / c0 * 1000))

	t0 = time.time()
	c0 = 0
	capabilities = []
	cap_index = {}
	for f in friends:
		fpub = pubkeys[f]
		for fof in friends[f]:
			c0 += 1
			claim_key = labels[fof]
			vrfkey = all_vrfs[fof]
			cap_key, cap_ciphertext = encode_capability(G, k, fpub, nonce, claim_key, vrfkey)
			capabilities += [(cap_key, cap_ciphertext)]
			cap_index[(f, fof)] = (cap_key, cap_ciphertext)
	t1 = time.time()
	print("\t\tTiming per encoded capab: %1.1f ms" % ((t1-t0) / c0 * 1000))

	data = encode([enc_claims, capabilities])
	print("\t\tData length: %1.1f kb" % (len(data) / 1024.0))
	
	from hippiehug import Tree, Leaf, Branch

	t0 = time.time()
	# Build our non-equivocable tree
	t = Tree()
	for k,v in enc_claims + capabilities:
		t.add(key=k, item=v)

	t1 = time.time()
	print("\t\tTiming for non-equiv. tree: %1.1f ms" % ((t1-t0) * 1000))

	# Pick a target proof to produce
	f1 = random.choice(friends.keys())
	f2 = random.choice(friends[f1])

	(cap_key, cap_ciphertext) = cap_index[(f1, f2)]
	(lookupkey, encrypted_body) = enc_claims[f2]

	root, E1 = t.evidence(key=cap_key)
	_, E2 = t.evidence(key=lookupkey)

	evidence_store = dict((e.identity(), e) for e in E1+E2)
	t2 = Tree(evidence_store, root)

	assert t2.is_in(key=cap_key, item=cap_ciphertext)
	assert t2.is_in(key=lookupkey, item=encrypted_body)

	# Serialize evidence:
	Evidence = []
	for e in E1 + E2:
		if isinstance(e, Leaf):
			Evidence += [(e.key, e.item)]
		elif isinstance(e, Branch):
			Evidence += [(e.pivot, e.left_branch, e.right_branch)]
		else:
			pass

	# Measure its size
	import zlib
	Ebin = encode(Evidence)
	print("\t\tSize ofr 1 proof: %s bytes (compressed %s bytes)" % (len(Ebin),len(Ebin_com)))

