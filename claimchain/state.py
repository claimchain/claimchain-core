import os
from datetime import datetime
from base64 import b64encode
from hashlib import sha256
from collections import defaultdict

from attr import attrs, attrib, asdict, Factory

from hippiehug import Chain
from hippiehug import Tree

from claimchain.core import get_capability_lookup_key
from claimchain.core import encode_capability, decode_capability
from claimchain.core import encode_claim, decode_claim
from claimchain.crypto import PublicParams, LocalParams
from claimchain.crypto import sign, verify_signature
from claimchain.utils import bytes2ascii, ascii2bytes, pet2ascii, ascii2pet


PROTOCOL_VERSION = 1


@attrs
class Payload(object):
    metadata = attrib()
    mtr_hash = attrib()
    nonce = attrib(default=False)
    timestamp = attrib(default=Factory(lambda: str(datetime.utcnow())))
    version = attrib(default=PROTOCOL_VERSION)

    @staticmethod
    def build(tree, nonce=None):
        return Payload(nonce=bytes2ascii(nonce),
                       metadata=LocalParams.get_default().public_export(),
                       mtr_hash=bytes2ascii(tree.root()))
    @staticmethod
    def from_dict(exported):
        return Payload(**exported)

    def export(self):
        return asdict(self)


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
            _, evidence = tree.evidence(key=lookup_key)
            assert tree.is_in(enc_item, key=lookup_key)
            enc_item_hash = evidence[-1].item
            tree.store[enc_item_hash] = enc_item

        # Construct payload
        def sign_block(block):
            sig = sign(block.hash())
            block.aux = pet2ascii(sig)

        payload = Payload.build(tree=tree, nonce=nonce).export()
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
        self._caps_by_reader_pk[reader_dh_pk].update(set(claim_labels))

    def revoke_access(self, reader_dh_pk, claim_labels):
        self._caps_by_reader_pk[reader_dh_pk].difference_update(claim_labels)

    def get_capabilities(self, reader_dh_pk):
        return list(self._caps_by_reader_pk[reader_dh_pk])


class View(object):
    def __init__(self, chain):
        self._chain = chain
        self._block = chain.store[chain.head]
        self._load()
        self._validate()

    def _load(self):
        self._payload = Payload.from_dict(self._block.items[0])
        self._nonce = ascii2bytes(self._payload.nonce)
        self._params = LocalParams.from_dict(self._payload.metadata)
        self._tree = Tree(store=self._chain.store,
                root_hash=ascii2bytes(self._payload.mtr_hash))

    def _validate(self):
        owner_sig_pk = self._params.sig.pk
        sig = ascii2pet(self._block.aux)
        self._block.aux = None
        if not verify_signature(owner_sig_pk, sig, self._block.hash()):
            raise ValueError("Invalid signature.")

    def __getitem__(self, claim_label):
        owner_dh_pk = self._params.dh.pk
        cap_lookup_key = get_capability_lookup_key(
                owner_dh_pk, self._nonce, claim_label)

        # TODO: There are no integrity checks here
        _, evidence = self._tree.evidence(key=cap_lookup_key)
        cap_hash = evidence[-1].item
        if evidence[-1].key != cap_lookup_key:
            raise ValueError("Label does not exist or no permission to read.")
        cap = self._tree.store[cap_hash]
        vrf_value, claim_lookup_key = \
                decode_capability(owner_dh_pk, self._nonce, claim_label, cap)

        # TODO: There are no integrity checks here
        _, evidence = self._tree.evidence(key=claim_lookup_key)
        enc_claim_hash = evidence[-1].item
        if evidence[-1].key != claim_lookup_key:
            raise ValueError("Claim not found, but permission to read "
                             "the label exists.")
        enc_claim = self._tree.store[enc_claim_hash]
        claim = decode_claim(self._params.vrf.pk, self._nonce,
                claim_label, vrf_value, enc_claim)
        return claim
