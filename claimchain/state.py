import os
from datetime import datetime
from base64 import b64encode
from hashlib import sha256
from collections import defaultdict

from attr import attrs, attrib, Factory
from msgpack import packb, unpackb
from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode
from petlib.ecdsa import do_ecdsa_setup, do_ecdsa_sign, do_ecdsa_verify
from hippiehug import Chain
from hippiehug import Tree

from claimchain.core import get_capability_lookup_key
from claimchain.core import encode_claim, decode_claim, encode_capability, decode_capability
from claimchain.crypto import PublicParams, LocalParams
from claimchain.utils import bytes2ascii, pet2ascii


PROTOCOL_VERSION = 1


class State(object):
    def __init__(self):
        self._claim_content_by_label = {}
        self._caps_by_reader_pk = defaultdict(set)

    def commit(self, chain, nonce=None, encode_all_labels_in_caps=False):
        nonce = nonce or os.urandom(PublicParams.get_default().nonce_size)

        enc_items_mapping = {}
        vrf_value_by_label = {}

        # Encode claims
        for claim_label, claim_content in self._claim_content_by_label.items():
            vrf_value, lookup_key, enc_claim = encode_claim(
                    nonce, claim_label, claim_content)
            enc_items_mapping[lookup_key] = enc_claim
            vrf_value_by_label[claim_label] = vrf_value

        # Encode capabilities
        if not encode_all_labels_in_caps:
            existing_claim_labels = set(self._claim_content_by_label.keys())
        for reader_dh_pk, caps in self._caps_by_reader_pk.items():
            if not encode_all_labels_in_caps:
                caps = caps.intersection(existing_claim_labels)
            for claim_label in caps:
                vrf_value = vrf_value_by_label[claim_label]
                lookup_key, enc_cap = encode_capability(
                        reader_dh_pk, nonce, claim_label, vrf_value)
                enc_items_mapping[lookup_key] = enc_cap

        # Put all the encrypted items in a new tree
        tree = Tree(store=chain.store)
        for lookup_key, enc_item in enc_items_mapping.items():
            tree.add(key=lookup_key, item=enc_item)

        # Construct payload
        payload = {
            "version": PROTOCOL_VERSION,
            "timestamp": str(datetime.utcnow()),
            "nonce": bytes2ascii(nonce),
            "metadata": LocalParams.get_default().public_export(),
            "mtr_hash": bytes2ascii(tree.root()),
        }

        # Sign the payload
        def sign_block(block):
            pp = PublicParams.get_default()
            params = LocalParams.get_default()
            G = pp.ec_group
            digest = pp.hash_func(packb(block.hid)).digest()
            kinv_rp = do_ecdsa_setup(G, params.sig.sk)
            sig = do_ecdsa_sign(G, params.sig.sk, digest, kinv_rp=kinv_rp)
            assert do_ecdsa_verify(G, params.sig.pk, sig, digest)
            block.aux = pet2ascii(sig)

        chain.multi_add([payload], pre_commit_fn=sign_block)
        return chain.head

    def clear(self):
        self._claim_content_by_label.clear()
        self._caps_by_reader_pk.clear()

    def _compute_claim_lookup_key(self, vrf):
        pp = PublicParams.get_default()
        return pp.hash_func(
                b"clm_lookup|" + vrf.value).digest()[:pp.short_hash_size]

    def _compute_claim_enc_key(self, vrf):
        pp = PublicParams.get_default()
        return pp.hash_func(
                b"clm_enc_key|" + vrf.value).digest()[:pp.enc_key_size]

    def __getitem__(self, label):
        return self._claim_content_by_label[label]

    def __setitem__(self, claim_label, claim_content):
        self._claim_content_by_label[claim_label] = claim_content

    def grant_access(self, reader_dh_pk, claim_labels):
        self._caps_by_reader_pk[reader_dh_pk].update(claim_labels)

    def revoke_access(self, reader_dh_pk, claim_labels):
        self._caps_by_reader_pk[reader_dh_pk].difference_update(claim_labels)

    def get_capabilities(self, reader_dh_pk):
        return list(self._caps_by_reader_pk[reader_dh_pk])

    def __repr__(self):
        return "State(nonce=%s, freeze=%s)" % (self.nonce, self.freeze)
