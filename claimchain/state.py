# -*- coding: utf-8
"""
High-level ClaimChain interface.
"""

import os
import warnings
import attr

from time import time
from base64 import b64encode
from hashlib import sha256
from collections import defaultdict

from profiled import profiled

from hippiehug import Chain
from hippiehug import Tree

from .core import get_capability_lookup_key
from .core import encode_capability, decode_capability
from .core import encode_claim, decode_claim
from .core import _compute_claim_key, _salt_label, _generate_prf_key

from .crypto import PublicParams, LocalParams
from .crypto import sign, verify_signature
from .crypto.vrf import compute_vrf

from .utils import bytes2ascii, ascii2bytes, pet2ascii, ascii2pet
from .utils import cached_property
from .utils import Tree, Blob, ObjectStore


PROTOCOL_VERSION = 2


@attr.s
class Metadata(object):
    """Block metadata.

    :param params: Owner's cryptographic parameters.
    :param identity_info: Owner's identity info (public key)
    """
    params = attr.ib()
    identity_info = attr.ib(default=None)


@attr.s
class Payload(object):
    """Block payload.

    :param bytes mtr_hash: Hash of the Merkle tree root
    :param Metadata metadata: Block's metadata
    :param bytes nonce: Nonce
    :param timestamp: Unix-format timestamp
    :param int version: Protocol version
    """

    mtr_hash  = attr.ib()
    metadata  = attr.ib()
    nonce     = attr.ib(default=False)
    timestamp = attr.ib(default=attr.Factory(lambda: time()))
    version   = attr.ib(default=PROTOCOL_VERSION)

    @staticmethod
    def build(tree, nonce, identity_info=None):
        """Build a payload.

        :param tree: Tree object
        :param bytes nonce: Nonce
        :param identity_info: Owner's identity info (public key)
        """
        metadata = Metadata(
                params=LocalParams.get_default().public_export(),
                identity_info=identity_info)
        if tree.root_hash is not None:
            mtr_hash = bytes2ascii(tree.root_hash)
        else:
            mtr_hash = None
        return Payload(metadata=metadata,
                       mtr_hash=mtr_hash,
                       nonce=bytes2ascii(nonce))

    @staticmethod
    def from_dict(exported):
        """Import payload from dictionary.

        :param dict exported: Exported payload.
        """
        raw_metadata = exported["metadata"]
        raw_payload = dict(exported)
        raw_payload['metadata'] = Metadata(**raw_metadata)
        return Payload(**raw_payload)

    def export(self):
        """Export to dictionary."""
        return attr.asdict(self)


@profiled
def _build_tree(store, enc_items_map):
    if not isinstance(store, ObjectStore):
        store = ObjectStore(store)
    tree = Tree(store)
    enc_blob_map = {key: Blob(enc_item)
                    for key, enc_item in enc_items_map.items()
                    if not isinstance(enc_item, Blob)}
    tree.update(enc_blob_map)
    return tree


def _sign_block(block):
    sig = sign(block.hash())
    block.aux = pet2ascii(sig)


class State(object):
    """ClaimChain owner state.

    :param identity_info: Owner's identity info (public key)
    """

    def __init__(self, identity_info=None):
        self.identity_info = identity_info

        self._claim_content_by_label = {}
        self._caps_by_reader_pk = defaultdict(set)
        self._enc_items_map = {}
        self._aux_by_label = {}
        self._payload = None
        self._tree = None

    @property
    def tree(self):
        """Corresponding Merkle tree holding the claims and capabilities."""
        if self._tree is None:
            raise ValueError('State not committed yet.')
        return self._tree

    def commit(self, target_chain, tree_store=None, nonce=None):
        """Commit state to a chain.

        Constructs a new block and appends to a chain.

        :param hippiehug.Chain target_chain: Chain to which a block will be
                appended.
        :param utils.ObjectStore tree_store: Object store to hold tree nodes.
        :param bytes nonce: Nonce to include in the new block.
        """
        if tree_store is None:
            tree_store = target_chain.store
        self._nonce = nonce = \
                nonce or os.urandom(PublicParams.get_default().nonce_size)

        # Encode claims
        enc_items_map = {}
        aux_by_label = {}
        for claim_label, claim_content in self._claim_content_by_label.items():
            enc_data = encode_claim(claim_label, claim_content, nonce)
            vrf_value, claim_key, proof_key, lookup_key, enc_claim = enc_data
            enc_items_map[lookup_key] = enc_claim
            aux_by_label[claim_label] = (vrf_value, claim_key, proof_key)

        # Encode capabilities
        for reader_dh_pk, caps in self._caps_by_reader_pk.items():
            for claim_label in caps:
                try:
                    vrf_value, claim_key, proof_key = aux_by_label[claim_label]
                except KeyError:
                    warnings.warn("Claim %s not encoded. "
                                  "Skipping adding a capability." \
                                  % claim_label)
                    break

                lookup_key, enc_cap = encode_capability(
                        reader_dh_pk,
                        claim_label,
                        vrf_value,
                        claim_key,
                        proof_key,
                        nonce)
                enc_items_map[lookup_key] = enc_cap

        # Put all the encrypted items in a new tree
        tree = _build_tree(tree_store, enc_items_map)

        # Construct payload
        payload = Payload.build(
                tree=tree,
                identity_info=self.identity_info,
                nonce=nonce)
        target_chain.multi_add([payload.export()], pre_commit_fn=_sign_block)

        self._payload = payload
        self._tree = tree
        self._enc_items_map = enc_items_map
        self._aux_by_label = aux_by_label

        return target_chain.head

    def compute_evidence_keys(self, reader_dh_pk, claim_label):
        """List hashes of all nodes that prove inclusion of a claim label.

        :param petlib.EcPt reader_dh_pk: Reader's DH public key
        :param bytes claim_label: Claim label
        """
        try:
            vrf_value, _, _ = self._aux_by_label[claim_label]
            cap_lookup_key = get_capability_lookup_key(
                    reader_dh_pk, claim_label, self._nonce)

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
        """Clear buffer."""
        self._claim_content_by_label.clear()
        self._caps_by_reader_pk.clear()
        self._enc_items_map.clear()
        self._aux_by_label.clear()
        self._payload = None
        self._tree = None

    def __getitem__(self, label):
        """Get queued claim by label.

        :param label: Claim label
        """
        return self._claim_content_by_label[label]

    def __setitem__(self, claim_label, claim_content):
        """Add a claim with given label and content to be committed.

        :param bytes claim_label: Claim label
        :param bytes claim_content: Claim content
        """
        self._claim_content_by_label[claim_label] = claim_content

    def grant_access(self, reader_dh_pk, claim_labels):
        """Grant access for given claims a reader.

        :param petlib.EcPt reader_dh_pk: Reader's DH public key
        :param iterable claim_labels: List of claim labels
        """
        self._caps_by_reader_pk[reader_dh_pk].update(set(claim_labels))

    def revoke_access(self, reader_dh_pk, claim_labels):
        """Revoke access for given claims to a reader.

        :param petlib.EcPt reader_dh_pk: Reader's DH public key
        :param iterable claim_labels: List of claim labels
        """
        self._caps_by_reader_pk[reader_dh_pk].difference_update(claim_labels)

    def get_capabilities(self, reader_dh_pk):
        """List all labels accessibly by a reader.

        :param petlib.EcPt reader_dh_pk: Reader's DH public key
        """
        return list(self._caps_by_reader_pk[reader_dh_pk])


class View(object):
    """View of an existing ClaimChain."""

    def __init__(self, source_chain, source_tree=None):
        """
        :param hippiehug.Chain source_chain: Chain to view
        :param utils.Tree source_tree: Tree object if available
        """
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
        """Chain's head (latest block hash)."""
        return self.chain.head

    @cached_property
    def payload(self):
        """Chain's latest block payload."""
        return Payload.from_dict(self._latest_block.items[0])

    @cached_property
    def params(self):
        """Cryptographic params of the chain owner."""
        return LocalParams.from_dict(self.payload.metadata.params)

    # TODO: This validation is incorrect for any block but the genesis
    def validate(self):
        """Validate the chain.

        .. note ::
            Don't rely on this method. It's broken. ¯\\_(ツ)_/¯
        """
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
                self.params.dh.pk, claim_label, self._nonce)
        try:
            cap = self.tree[cap_lookup_key]
        except KeyError:
            raise KeyError("Label does not exist or you don't have "
                           "permission to read.")
        except AttributeError:
            raise ValueError("The chain does not have a claim map.")
        return decode_capability(
                self.params.dh.pk, claim_label, cap, self._nonce)

    def _lookup_claim(self, claim_lookup_key, claim_label, vrf_value,
                      claim_key, proof_key):
        try:
            enc_claim = self.tree[claim_lookup_key]
        except KeyError:
            raise KeyError("Claim not found, but permission to read the label "
                           "exists.")
        except AttributeError:
            raise ValueError("The chain does not have a claim map.")
        return decode_claim(self.params.vrf.pk, vrf_value, claim_label,
                            claim_key, proof_key, enc_claim, self._nonce)

    def __getitem__(self, claim_label):
        """Get claim by label.

        :param bytes claim_label: Claim label
        :raises: ``KeyError`` if claim not found or not accessible
        """
        # Recompute the VRF value if have access to the sk.
        if LocalParams.get_default().vrf.pk == self.params.vrf.pk:
            pp = PublicParams.get_default()
            salted_label = _salt_label(claim_label, self._nonce)
            vrf_bundle = compute_vrf(salted_label)
            claim_lookup_key = _compute_claim_key(vrf_bundle.value, 'lookup')
            claim_key = _generate_prf_key(salted_label, mode='enc')
            proof_key = _generate_prf_key(salted_label, mode='proof')
            claim = self._lookup_claim(claim_lookup_key, claim_label,
                    vrf_bundle.value, claim_key, proof_key)

        # Otherwise, query for the capability.
        else:
            lookup_data = self._lookup_capability(claim_label)
            claim_lookup_key, vrf_value, claim_key, proof_key = lookup_data
            claim = self._lookup_claim(claim_lookup_key, claim_label,
                                       vrf_value, claim_key, proof_key)
        return claim

    def get(self, claim_label):
        """Get claim by label.

        :param bytes claim_label: Claim label
        :return: Claim or ``None`` if not found or not accessible.
        """
        try:
            return self[claim_label]
        except KeyError:
            return None
        except ValueError:
            return None

    def __hash__(self):
        return hash(self.head)

