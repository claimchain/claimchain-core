import os
import base64

from collections import defaultdict
from enum import Enum

from attr import attrs, attrib
from hippiehug import Chain
from claimchain import State, View, LocalParams
from defaultcontext import with_default_context


class EncStatus(Enum):
    plaintext = 0
    stale = 1
    encrypted = 2


# Instead of using string 'public' as a shared secret for
# public claims, we assume there exist public DH key pair
# accessible by anybody --- for simplicity.
PUBLIC_READER_PARAMS = LocalParams.generate()

ENC_KEY_LABEL = 'my_encryption_key'
PUBLIC_READER_LABEL = 'public'


@with_default_context(use_empty_init=True)
@attrs
class SimulationParams(object):
    # Max buffer size for user after which she updates her chain.
    # If None, chains are never updated
    chain_update_buffer_size = attrib(default=None)

    # Max number of sent emails by a user after which she updates her key.
    # If None, keys are never updated
    key_update_every_nb_sent_emails = attrib(default=None)


@attrs
class GlobalState(object):
    pass


class Agent(object):
    def __init__(self, global_state):
        self.global_state = global_state
        self.params = LocalParams.generate()
        self.enc_key = None
        self.chain_store = {}
        self.tree_store = {}
        self.chain = Chain(self.chain_store)
        self.state = State()

        self.nb_sent_emails = 0

        self.views = {}
        self.cap_map = defaultdict(set)

        self.cap_buffer = {}
        self.view_buffer = {}

        self.email_store_caches = {}

        # Make the encryption key public right away
        self.cap_buffer[PUBLIC_READER_LABEL] = {ENC_KEY_LABEL}
        # Generate initial encryption key, and add first block
        # to the chain
        self.maybe_update_key(force=True)

    @property
    def head(self):
        return self.chain.head

    @property
    def key(self):
        return self.enc_key

    def add_expected_reader(self, reader, claim_label):
        if reader not in self.cap_buffer:
            self.cap_buffer[reader] = {claim_label}
        else:
            self.cap_buffer[reader].add(claim_label)

    def send_email(self, recipients):
        with self.params.as_default():
            relevant_object_keys = set()
            for recipient in recipients:
                # view = self.views.get(recipient)
                # head = self.chain.head

                # # If sender does not know of a recipient's enc key, the email is
                # # sent in clear text
                # if view is None or view.get(ENC_KEY_LABEL) is None:
                #     pass

                # Compute evidence paths
                accessible_labels = self.cap_map[recipient]
                evidence_keys = set()
                for claim_label in accessible_labels:
                    # NOTE: Can't use the fresh key even if available
                    view = self.views.get(recipient)
                    if view is not None:
                        recipient_dh_pk = view.params.dh.pk
                        evidence_keys.update(self.state.compute_evidence_keys(
                                recipient_dh_pk, claim_label))

                # Keys of all objects to be sent:
                # - Chain block
                # - Evidence nodes
                # NOTE: Requires that chain and tree use separate stores
                object_keys = set(self.chain_store.keys()) | evidence_keys

                if recipient not in self.email_store_caches:
                    self.email_store_caches[recipient] = set(object_keys)

                # If some of the objects were already sent, only send the diff
                else:
                    object_keys = object_keys - self.email_store_caches[recipient]
                relevant_object_keys.update(object_keys)

            # Add evidence for public claims
            public_labels = self.cap_map[PUBLIC_READER_LABEL]
            public_evidence_keys = set()
            for claim_label in public_labels:
                public_evidence_keys.update(self.state.compute_evidence_keys(
                    PUBLIC_READER_PARAMS.dh.pk, claim_label))

            # Merge all the evidences into one transmittable store
            relevant_object_keys.update(public_evidence_keys)
            email_store = {}
            for key in relevant_object_keys:
                value = self.chain_store.get(key) or self.tree_store.get(key)
                email_store[key] = value

            self.nb_sent_emails += 1
            return self.chain.head, email_store

    def receive_email(self, sender, head, email_store):
        with self.params.as_default():
            email_store = dict(email_store)
            sender_chain = Chain(email_store, root_hash=head)
            self.view_buffer[sender] = View(source_chain=sender_chain)

    def _maybe_get_from_view(self, view, claim_label):
        with self.params.as_default():
            claim = view.get(claim_label)
            if claim is not None:
                return claim
        with PUBLIC_READER_PARAMS.as_default():
            claim = view.get(claim_label)
        return claim

    def maybe_update_chain(self, force=False):
        with self.params.as_default():
            buffer_size_thresh = SimulationParams.get_default() \
                    .chain_update_buffer_size

            buffer_size = len(self.view_buffer)
            if force or (buffer_size_thresh is not None \
                         and buffer_size > buffer_size_thresh):

                # Get heads of views in the buffer into the claimchain state,
                # and move the buffer views into main views
                for friend, view in self.view_buffer.items():
                    claim = view.chain.head
                    if claim is not None:
                        self.state[friend] = claim
                    self.views[friend] = view

                # Flush the view buffer
                self.view_buffer.clear()

                # Get capabilities in the capability buffer into the claimchain
                # state, for those subjects whose keys are known.
                added_caps = []
                for friend, labels in self.cap_buffer.items():
                    friend_dh_pk = None
                    # If the buffer is for the public 'reader'
                    if friend == PUBLIC_READER_LABEL:
                        friend_dh_pk = PUBLIC_READER_PARAMS.dh.pk

                    # Else try to find the DH key in views
                    else:
                        view = self.views.get(friend)
                        if view is not None:
                            friend_dh_pk = view.params.dh.pk

                    if friend_dh_pk is not None:
                        self.state.grant_access(friend_dh_pk, labels)
                        self.cap_map[friend].update(labels)
                        added_caps.append(friend)

                for subject in added_caps:
                    del self.cap_buffer[subject]

                head = self.state.commit(target_chain=self.chain,
                        tree_store=self.tree_store)

    @staticmethod
    def generate_public_key():
        # 4096 random bits in base64
        return base64.b64encode(os.urandom(4096 // 8))

    def maybe_update_key(self, force=False):
        nb_sent_emails_thresh = SimulationParams.get_default() \
                .key_update_every_nb_sent_emails

        if force or (nb_sent_emails_thresh is not None and \
                     self.nb_sent_emails > nb_sent_emails_thresh):
            self.enc_key = new_enc_key = Agent.generate_public_key()
            self.state[ENC_KEY_LABEL] = self.enc_key
            self.maybe_update_chain(force=True)
