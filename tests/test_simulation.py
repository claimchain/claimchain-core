import time
import json
import random

from os import urandom
from binascii import hexlify
from hashlib import sha256

from hippiehug import Chain
from hippiehug import Tree, Leaf, Branch
from petlib.pack import encode
from petlib.ecdsa import do_ecdsa_setup, do_ecdsa_sign, do_ecdsa_verify
from msgpack import packb

from claimchain.core import encode_claim, decode_claim
from claimchain.core import encode_capability, decode_capability, get_capability_lookup_key
from claimchain.crypto import LocalParams, PublicParams


def rhex(l):
    return hexlify(urandom(l))[:l]


def generate_test_data(nb_friends=200, nb_per_friend=5):
    labels = [b"%s@%s.com" % (rhex(8), rhex(8)) for _ in range(nb_friends)]
    heads = [urandom(20) for _ in range(nb_friends)]
    pp = PublicParams.get_default()
    G = pp.ec_group

    params_per_friend = [LocalParams.generate() for _ in range(nb_friends)]
    pubkeys = [params.dh.pk for params in params_per_friend]
    all_data = (labels, heads, pubkeys)

    friends_graph = {}
    for f in range(nb_friends):
        cap = random.sample(range(nb_friends), nb_per_friend)
        friends_graph[f] = cap

    return friends_graph, all_data


def test_simulation():
    friends_graph, all_data = generate_test_data()
    (labels, heads, pubkeys) = all_data

    nonce = b"42"
    with LocalParams.generate().as_default() as params:

        # Encode claims
        t0 = time.time()
        c0 = 0
        enc_claims = []
        vrfs = []
        for claim_label, claim_body in zip(labels, heads):
            c0 += 1
            c0 += 1
            enc = encode_claim(nonce, claim_label, claim_body)
            vrf_value, lookup_key, encrypted_claim = enc
            enc_claims += [(lookup_key, encrypted_claim)]
            vrfs += [vrf_value]
        t1 = time.time()
        print("\n\t\tTiming per encoded claim: %1.1f ms" % ((t1-t0) / c0 * 1000))

        # Encode capabilities
        t0 = time.time()
        c0 = 0
        capabilities = []
        cap_index = {}
        for friend in friends_graph:
            friend_dh_pk = pubkeys[friend]
            for fof in friends_graph[friend]:
                c0 += 1
                claim_label = labels[fof]
                vrf_value = vrfs[fof]
                cap_lookup_key, encrypted_cap = encode_capability(
                        friend_dh_pk, nonce, claim_label, vrf_value)
                capabilities += [(cap_lookup_key, encrypted_cap)]
                cap_index[(friend, fof)] = (cap_lookup_key, encrypted_cap)
        t1 = time.time()
        print("\t\tTiming per encoded capab: %1.1f ms" % ((t1-t0) / c0 * 1000))

        data = encode([enc_claims, capabilities])
        print("\t\tData length: %1.1f kb" % (len(data) / 1024.0))

        # Build our non-equivocable tree
        t0 = time.time()
        tree = Tree()
        for k, v in enc_claims + capabilities:
            tree.add(key=k, item=v)

        t1 = time.time()
        print("\t\tTiming for building non-equiv. tree: %1.1f ms" % ((t1-t0) * 1000))

        # Build a chain and a block
        store = {}
        t0 = time.time()
        chain = Chain(store)
        payload = {
            'version': 1,
            'nonce': nonce.decode('ascii'),
            'metadata': params.public_export(),
            'claim_map': hexlify(tree.root()).decode('ascii')
        }

        # Sign payload
        G = PublicParams.get_default().ec_group
        digest = sha256(json.dumps(payload).encode('ascii')).digest()
        kinv_rp = do_ecdsa_setup(G, params.sig.sk)
        sig = do_ecdsa_sign(G, params.sig.sk, digest, kinv_rp=kinv_rp)
        assert do_ecdsa_verify(G, params.sig.pk, sig, digest)

        # Seal block
        block_content = (payload, hexlify(encode(sig)))
        # print(block_content)
        chain.multi_add([block_content])

        # Pack block
        block = store[chain.head]
        packed_block = packb(
                ("S", block.sequence, block.fingers, block.length, block.items))
        print("\t\tPacked block size: %1.1f bytes" % (len(packed_block)))

        t1 = time.time()
        print("\t\tTiming for building a block: %1.1f ms" % (t1-t0))

        # Pick a target proof to produce
        f1 = random.choice(list(friends_graph.keys()))
        f2 = random.choice(list(friends_graph[f1]))

        (cap_lookup_key, encrypted_cap) = cap_index[(f1, f2)]
        (claim_lookup_key, encrypted_claim) = enc_claims[f2]

        root, e1 = tree.evidence(key=cap_lookup_key)
        _, e2 = tree.evidence(key=claim_lookup_key)

        evidence_store = {e.identity(): e for e in e1+e2}
        t2 = Tree(evidence_store, root)

        assert t2.is_in(key=cap_lookup_key, item=encrypted_cap)
        assert t2.is_in(key=claim_lookup_key, item=encrypted_claim)

        # Serialize evidence:
        evidence = []
        for e in e1 + e2:
            if isinstance(e, Leaf):
                evidence += [(e.key, e.item)]
            elif isinstance(e, Branch):
                evidence += [(e.pivot, e.left_branch, e.right_branch)]
            else:
                pass

        import zlib
        bin_evidence = encode(evidence)
        bin_evidence_compressed = zlib.compress(bin_evidence, 9)
        print("\t\tSize for one proof: %s bytes (compressed %s bytes)" %
                (len(bin_evidence), len(bin_evidence_compressed)))

