import json
import os
import warnings

import attr

from time import time
from collections import defaultdict

from hippiepug.chain import Chain, BlockBuilder
from hippiepug.tree import Tree, TreeBuilder

from .core import get_capability_lookup_key
from .core import encode_capability, decode_capability
from .core import encode_claim, decode_claim
from .core import _compute_claim_key
from .crypto import PublicParams, LocalParams
from .crypto import sign, verify_signature
from .utils import bytes2ascii, ascii2bytes, pet2ascii, ascii2pet
from .utils import profiled
from .utils import cached_property
from .utils import Tree, Blob, ObjectStore


PROTOCOL_VERSION = 2


@attr.s
class Metadata(object):
    params = attr.ib()
    identity_info = (default=None)


@attr.s
class Payload(object):
    mtr_hash  = attr.ib()
    metadata  = attr.ib()
    nonce     = attr.ib(default=False)
    timestamp = attr.ib(default=Factory(lambda: time()))
    version   = attr.ib(default=PROTOCOL_VERSION)

    @staticmethod
    def build(mtr_hash, nonce, identity_info=None):
        metadata = BlockMetadata(
                params=LocalParams.get_default().public_export(),
                identity_info=identity_info)
        return Payload(metadata=metadata,
                       mtr_hash=mtr_hash,
                       nonce=bytes2ascii(nonce))

    @staticmethod
    def from_dict(exported):
        raw_metadata = exported["metadata"]
        raw_payload = dict(exported)
        raw_payload['metadata'] = Metadata(**raw_metadata)
        return Payload(**raw_payload)

    def as_dict(self):
        return asdict(self)


class ClaimChainBlockBuilder(BlockBuilder)
    def pre_commit(self):
        """Substitute"""
        serialized_payload = json.dumps(self.payload.as_dict(), sort_keys=True)
        payload_hash = self.object_store.hash_object(serialized_payload)
        sig = self.sign(self.payload)


def _sign_block(block):
    sig = sign(block.hash())
    block.aux = pet2ascii(sig)


class ClaimChainState(object):
    def __init__(self, identity_info=None):
        self.identity_info = identity_info

        self._claim_content_by_label = {}
        self._caps_by_reader_pk = defaultdict(set)
        self._vrf_value_by_label = {}
        self._payload = None
        self._tree = None

    @property
    def tree(self):
        if self._tree is None:
            raise ValueError('State not committed yet.')
        return self._tree

    def commit(self, chain_store, tree_store=None, nonce=None):
        if tree_store is None:
            tree_store = chain_store
        if nonce is None:
            nonce = os.urandom(PublicParams.get_default().nonce_size)
        self._nonce = nonce

        tree_builder = TreeBuilder(tree_store)

        # Encode claims
        vrf_value_by_label = {}
        for claim_label, claim_content in self._claim_content_by_label.items():
            vrf_value, lookup_key, enc_claim = encode_claim(
                    nonce, claim_label, claim_content)
            tree_builder[lookup_key] = enc_claim
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
                tree_builder[lookup_key] = enc_cap

        # Put all the encrypted items in a new tree
        self._tree = tree_builder.commit()

        # Construct payload
        payload = Payload.build(
                mtr_hash=tree.root_hash,
                nonce=nonce,
                identity_info=self.identity_info)

        self._payload = payload
        self._vrf_value_by_label = vrf_value_by_label

        return chain.head

    def compute_evidence_keys(self, reader_dh_pk, claim_label):
        try:
            vrf_value = self._vrf_value_by_label[claim_label]
            cap_lookup_key = get_capability_lookup_key(
                    reader_dh_pk, self._nonce, claim_label)

            # Compute capability entry evidence
            _, raw_cap_evidence = self.tree.evidence(cap_lookup_key)
            claim_lookup_key = _compute_claim_key(vrf_value, mode='lookup')

            # Compute claim evidence
            _, raw_claim_evidence = self.tree.evidence(claim_lookup_key)
            object_keys = {obj.hid for obj in raw_cap_evidence} | \
                          {obj.hid for obj in raw_claim_evidence}

            # Add encoded capability and encoded claim value
            encoded_cap_hash = raw_cap_evidence[-1].item
            encoded_claim_hash = raw_claim_evidence[-1].item
            return object_keys | {encoded_claim_hash} | {encoded_cap_hash}
        except KeyError:
            return set()

    def clear(self):
        self._claim_content_by_label.clear()
        self._caps_by_reader_pk.clear()

        self._enc_items_map.clear()
        self._vrf_value_by_label.clear()
        self._payload = None
        self._tree = None

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


class ClaimChainView(object):
    def __init__(self, chain_store, tree_store):
        self.chain = source_chain
        self._latest_block = self.chain.store[self.chain.head]
        self._nonce = ascii2bytes(self.payload.nonce)
        if self.payload.mtr_hash is not None:
            self.tree = source_tree or Tree(
                    object_store=ObjectStore(self.chain.store),
                    root_hash=ascii2bytes(self.payload.mtr_hash))

            if ascii2bytes(self.payload.mtr_hash) != self.tree.root_hash:
                raise ValueError("Supplied tree doesn't match MTR in the chain.")

    @property
    def head(self):
        return self.chain.head

    @cached_property
    def payload(self):
        return Payload.from_dict(self._latest_block.items[0])

    @cached_property
    def params(self):
        return LocalParams.from_dict(self.payload.metadata.params)

    # TODO: This validation is incorrect for any block but the genesis
    def validate(self):
        owner_sig_pk = self.params.sig.pk
        raw_sig_backup = self._latest_block.aux
        sig = ascii2pet(raw_sig_backup)
        self._latest_block.aux = None
        if not verify_signature(owner_sig_pk, sig, self._latest_block.hash()):
            self._latest_block.aux = raw_sig_backup
            raise ValueError("Invalid signature.")
        self._latest_block.aux = raw_sig_backup

    def _lookup_capability(self, claim_label):
        cap_lookup_key = get_capability_lookup_key(
                self.params.dh.pk, self._nonce, claim_label)
        try:
            cap = self.tree[cap_lookup_key]
        except KeyError:
            raise KeyError("Label does not exist or you don't have "
                           "permission to read.")
        except AttributeError:
            raise ValueError("The chain does not have a claim map.")
        return decode_capability(self.params.dh.pk, self._nonce,
                                 claim_label, cap)

    def _lookup_claim(self, claim_label, vrf_value, claim_lookup_key):
        try:
            enc_claim = self.tree[claim_lookup_key]
        except KeyError:
            raise KeyError("Claim not found, but permission to read the label "
                           "exists.")
        except AttributeError:
            raise ValueError("The chain does not have a claim map.")
        return decode_claim(self.params.vrf.pk, self._nonce,
                            claim_label, vrf_value, enc_claim)

    def __getitem__(self, claim_label):
        vrf_value, claim_lookup_key = self._lookup_capability(claim_label)
        claim = self._lookup_claim(claim_label, vrf_value, claim_lookup_key)
        return claim

    def get(self, claim_label):
        try:
            return self[claim_label]
        except KeyError:
            return None
        except ValueError:
            return None

    def __hash__(self):
        return hash(self.head)
