import os
import warnings
from datetime import datetime
from base64 import b64encode
from hashlib import sha256
from collections import defaultdict

from attr import attrs, attrib, asdict, Factory

from hippiehug import Chain
from hippiehug import Tree

from .core import get_capability_lookup_key
from .core import encode_capability, decode_capability
from .core import encode_claim, decode_claim
from .crypto import PublicParams, LocalParams
from .crypto import sign, verify_signature
from .utils import bytes2ascii, ascii2bytes, pet2ascii, ascii2pet
from .utils import profiled
from .utils import Tree, Blob, ObjectStore


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
                       mtr_hash=bytes2ascii(tree.root_hash))
    @staticmethod
    def from_dict(exported):
        return Payload(**exported)

    def export(self):
        return asdict(self)


@profiled
def _build_tree(store, enc_items_map):
    tree = Tree(ObjectStore(store))
    enc_blob_map = {key: Blob(enc_item)
                    for key, enc_item in enc_items_map.items()
                    if not isinstance(enc_item, Blob)}
    tree.update(enc_blob_map)
    return tree


def _sign_block(block):
    sig = sign(block.hash())
    block.aux = pet2ascii(sig)


class State(object):
    def __init__(self):
        self._claim_content_by_label = {}
        self._caps_by_reader_pk = defaultdict(set)

        self._enc_items_map = {}
        self._vrf_value_by_label = {}
        self._payload = None
        self._tree = None

    def commit(self, target_chain, nonce=None):
        nonce = nonce or os.urandom(PublicParams.get_default().nonce_size)

        # Encode claims
        enc_items_map = {}
        vrf_value_by_label = {}
        for claim_label, claim_content in self._claim_content_by_label.items():
            vrf_value, lookup_key, enc_claim = encode_claim(
                    nonce, claim_label, claim_content)
            enc_items_map[lookup_key] = enc_claim
            vrf_value_by_label[claim_label] = vrf_value

        # Encode capabilities
        for reader_dh_pk, caps in self._caps_by_reader_pk.items():
            for claim_label in caps:
                try:
                    vrf_value = vrf_value_by_label[claim_label]
                except KeyError:
                    warnings.warn("VRF for %s not computed. "
                                  "Skipping adding a capability." \
                                  % claim_label)
                    break
                lookup_key, enc_cap = encode_capability(
                        reader_dh_pk, nonce, claim_label, vrf_value)
                enc_items_map[lookup_key] = enc_cap

        # Put all the encrypted items in a new tree
        tree = _build_tree(target_chain.store, enc_items_map)

        # Construct payload
        payload = Payload.build(tree=tree, nonce=nonce).export()
        target_chain.multi_add([payload], pre_commit_fn=_sign_block)

        self._payload = payload
        self._tree = tree
        self._enc_items_map = enc_items_map
        self._vrf_value_by_label = vrf_value_by_label

        return target_chain.head

    def clear(self):
        self._claim_content_by_label.clear()
        self._caps_by_reader_pk.clear()

        self._enc_items_map.clear()
        self._vrf_value_by_label.clear()
        self._payload = None
        self._tree = None

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
    def __init__(self, source_chain):
        self._chain = source_chain
        self._block = self._chain.store[self._chain.head]

        payload = Payload.from_dict(self._block.items[0])

        self._nonce = ascii2bytes(payload.nonce)
        self._params = LocalParams.from_dict(payload.metadata)

        self.tree = Tree(
                object_store=ObjectStore(self._chain.store),
                root_hash=ascii2bytes(payload.mtr_hash))

        self.validate()

    def validate(self):
        # TODO: This validation is incorrect for any block but the genesis
        owner_sig_pk = self._params.sig.pk
        raw_sig_backup = self._block.aux
        sig = ascii2pet(raw_sig_backup)
        self._block.aux = None
        if not verify_signature(owner_sig_pk, sig, self._block.hash()):
            self._block.aux = raw_sig_backup
            raise ValueError("Invalid signature.")
        self._block.aux = raw_sig_backup

    def _lookup_capability(self, claim_label):
        cap_lookup_key = get_capability_lookup_key(
                self._params.dh.pk, self._nonce, claim_label)

        # TODO: There are no integrity checks here
        try:
            cap = self.tree[cap_lookup_key]
        except KeyError:
            raise KeyError("Label does not exist or you don't have "
                           "permission to read.")
        return decode_capability(self._params.dh.pk, self._nonce,
                                 claim_label, cap)

    def _lookup_claim(self, claim_label, vrf_value, claim_lookup_key):
        # TODO: There are no integrity checks here
        try:
            enc_claim = self.tree[claim_lookup_key]
        except KeyError:
            raise KeyError("Claim not found, but permission to read the label "
                           "exists.")
        return decode_claim(self._params.vrf.pk, self._nonce,
                            claim_label, vrf_value, enc_claim)

    def __getitem__(self, claim_label):
        vrf_value, claim_lookup_key = self._lookup_capability(claim_label)
        claim = self._lookup_claim(claim_label, vrf_value, claim_lookup_key)
        return claim
