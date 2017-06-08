import os
import time
import json
import random

from os import urandom
from binascii import hexlify
from pprint import pprint
from hashlib import sha256

from hippiehug import Chain
from hippiehug import Tree, Leaf, Branch
from petlib.pack import encode
from petlib.ecdsa import do_ecdsa_setup, do_ecdsa_sign, do_ecdsa_verify
from msgpack import packb

from claimchain.state import Payload, State, View
from claimchain.core import encode_claim, decode_claim
from claimchain.core import encode_capability, decode_capability, get_capability_lookup_key
from claimchain.crypto import LocalParams, PublicParams, sign, Keypair
from claimchain.utils import pet2ascii


def rhex(l):
    return hexlify(urandom(l))[:l]


def generate_test_data(nb_friends=200, nb_per_friend=5):
    labels = [b"%s@%s.com" % (rhex(8), rhex(8)) for _ in range(nb_friends)]
    heads = [urandom(20) for _ in range(nb_friends)]
    pp = PublicParams.get_default()
    G = pp.ec_group

    params_per_friend = [LocalParams.generate() for _ in range(nb_friends)]
    pubkeys = [params.dh.pk for params in params_per_friend]
    privkeys = [params.dh.sk for params in params_per_friend]
    all_data = (labels, heads, pubkeys, privkeys)

    friends_graph = {}
    for f in range(nb_friends):
        cap = random.sample(range(nb_friends), nb_per_friend)
        friends_graph[f] = cap

    return friends_graph, all_data


import pytest


@pytest.mark.skip
def test_e2e_timings():
    friends_graph, all_data = generate_test_data()
    (labels, heads, pubkeys, privkeys) = all_data

    with LocalParams.generate().as_default() as params:
        nonce = os.urandom(PublicParams.get_default().nonce_size)

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
        for lookup_key, enc_item in enc_claims + capabilities:
            tree.add(key=lookup_key, item=enc_item)
            _, evidence = tree.evidence(key=lookup_key)
            assert tree.is_in(enc_item, key=lookup_key)
            enc_item_hash = evidence[-1].item
            tree.store[enc_item_hash] = enc_item

        t1 = time.time()
        print("\t\tTiming for building non-equiv. tree: %1.1f ms" % ((t1-t0) * 1000))

        # Build a chain and a block
        t0 = time.time()
        c0 = 200
        for _ in range(c0):
            chain = Chain(tree.store)
            payload = Payload.build(tree, nonce).export()

            def sign_block(block):
                sig = sign(block.hash())
                block.aux = pet2ascii(sig)

            chain.multi_add([payload], pre_commit_fn=sign_block)

            # Pack block
            block = chain.store[chain.head]
            packed_block = packb(
                    ("S", block.index, block.fingers, block.items, block.aux))

        t1 = time.time()

        print("\t\tTiming for building a block: %1.1f ms" % ((t1-t0) / c0 * 1000))
        print("\t\tPacked block size: %d bytes" % (len(packed_block)))

        t0 = time.time()
        c0 = 0

        # Pick a random reader
        for reader in friends_graph:
            reader_params = LocalParams(
                    dh=Keypair(sk=privkeys[reader], pk=pubkeys[reader]))
            for reader_friend in friends_graph[reader]:
                claim_label = labels[reader_friend]
                with reader_params.as_default():
                    view = View(chain)
                    c0 += 1
                    head = view[labels[reader_friend]]
                    assert head == heads[reader_friend]

        t1 = time.time()
        print("\t\tTiming for retrieving a claim by label: %1.1f ms" %
                ((t1-t0) / c0 * 1000))

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
                evidence += [(e.key, e.item, tree.store[e.item])]
            elif isinstance(e, Branch):
                evidence += [(e.pivot, e.left_branch, e.right_branch)]
            else:
                pass

        import zlib
        bin_evidence = encode(evidence)
        bin_evidence_compressed = zlib.compress(bin_evidence, 9)
        print("\t\tSize for one proof: %s bytes (compressed %s bytes)" %
                (len(bin_evidence), len(bin_evidence_compressed)))

        print("\t\tPayload:")
        pprint(payload)
