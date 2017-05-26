from os import urandom
from binascii import hexlify
from petlib.pack import encode
import time
import random

from claimchain import default_ec_group as G
from claimchain import VRF_compute, VRF_verify, encode_claim, decode_claim
from claimchain import encode_capability, decode_capability, lookup_capability


def rhex(l):
	return hexlify(urandom(l))[:l]


def generate_test_load(nb_friends=200, nb_per_friend=5):
	labels = [b"%s@%s.com" % (rhex(8), rhex(8)) for _ in range(nb_friends)]
	heads = [urandom(20) for _ in range(nb_friends)]
	secrets = [G.order().random() for _ in range(nb_friends)]
	g = G.generator()
	pubkeys = [s * g for s in secrets]

	all_data = (labels, heads, pubkeys)

	friends_graph = {}
	for f in range(nb_friends):
		cap = random.sample(range(nb_friends), nb_per_friend)
		friends_graph[f] = cap

	return friends_graph, all_data


def test_simulation():
	friends_graph, all_data = generate_test_load()
	(labels, heads, pubkeys) = all_data

	nonce = b"now1"
	k = G.order().random()
	pub = k * G.generator()

	t0 = time.time()
	c0 = 0
	enc_claims = []
	all_vrfs = []
	for claim_key, claim_body in zip(labels, heads):
		c0 += 1
		c0 += 1
		enc = encode_claim(G, pub, k, nonce, claim_key, claim_body)
		vrfkey, lookupkey, encrypted_body = enc
		enc_claims += [(lookupkey, encrypted_body)]
		all_vrfs += [vrfkey]
	t1 = time.time()
	print("\n\t\tTiming per encoded claim: %1.1f ms" % ((t1-t0) / c0 * 1000))

	t0 = time.time()
	c0 = 0
	capabilities = []
	cap_index = {}
	for f in friends_graph:
		fpub = pubkeys[f]
		for fof in friends_graph[f]:
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

	t2 = time.time()
	# Build our non-equivocable tree
	t = Tree()
	for k,v in enc_claims + capabilities:
		t.add(key=k, item=v)

	t1 = time.time()
	print("\t\tTiming for non-equiv. tree: %1.1f ms" % ((t1-t0) * 1000))

	# Pick a target proof to produce
	f1 = random.choice(list(friends_graph.keys()))
	f2 = random.choice(list(friends_graph[f1]))

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

	import zlib
	Ebin = encode(Evidence)
	Ebin_com = zlib.compress(Ebin,9)
	print("\t\tSize for 1 proof: %s bytes (compressed %s bytes)" % (len(Ebin),len(Ebin_com)))

