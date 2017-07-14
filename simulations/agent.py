import os
import base64
import warnings

from collections import defaultdict

from hippiehug import Chain
from claimchain import State, View, LocalParams
from claimchain.utils import ObjectStore

from .utils import SimulationParams


# Instead of using string 'public' as a shared secret for
# public claims, we assume there exist public DH key pair
# accessible by anybody --- for simplicity.
PUBLIC_READER_PARAMS = LocalParams.generate()

PUBLIC_READER_LABEL = 'public'


class GlobalState(object):
    def __init__(self, context):
        self.context = context
        self.agents = {}
        self.sent_email_count = 0
        self.encrypted_email_count = 0
        for user in self.context.senders:
            self.agents[user] = Agent(self)


def latest_timestamp_resolution_policy(views):
    # NOTE: Naive resolution policy that does not check for forks
    return max(views, key=lambda view: view.payload.timestamp)


class Agent(object):
    '''
    Simulated claimchain user in the online deployment mode.
    '''
    def __init__(self, global_state, conflict_resolution_policy=None):
        self.global_state = global_state
        self.conflict_resolution_policy = conflict_resolution_policy \
                or latest_timestamp_resolution_policy

        self.params = LocalParams.generate()
        self.chain_store = ObjectStore()
        self.tree_store = ObjectStore()
        self.chain = Chain(self.chain_store)
        self.state = State()

        self.nb_sent_emails = 0

        self.committed_caps = defaultdict(set)
        self.committed_views = {}
        self.queued_identity_info = None
        self.queued_caps = {}
        self.queued_views = {}

        self.global_views = defaultdict(dict)
        self.contacts_by_sender = defaultdict(set)

        self.sent_objects_by_recipient = {}
        self.global_store = ObjectStore()

        # Generate initial encryption key, and add first block
        # to the chain
        self.maybe_update_key(force=True)

    @property
    def head(self):
        return self.chain.head

    @property
    def current_enc_key(self):
        return self.state.identity_info

    @staticmethod
    def generate_public_key():
        # 4096 random bits in base64
        return base64.b64encode(os.urandom(4096 // 8))

    def add_expected_reader(self, reader, claim_labels):
        if reader not in self.queued_caps:
            self.queued_caps[reader] = set(claim_labels)
        else:
            self.queued_caps[reader].update(claim_labels)

    def get_latest_view(self, contact):
        policy = self.conflict_resolution_policy

        # Collect possible candidates
        latest_block_candidates = {}
        current_views = dict(self.committed_views)
        current_views.update(self.queued_views)
        for friend, view in current_views.items():
            if friend == contact:
                continue

            contact_head_candidate = self.get_contact_head_from_view(
                    view, contact)
            if contact_head_candidate is None:
                continue
            contact_latest_block_candidate = \
                    self.global_store[contact_latest_block_candidate]
            latest_block_candidates[contact_head_candidate] = \
                    contact_latest_block_candidate

        # Compute candidates views
        candidate_views = set()
        if contact in current_views:
            candidate_views.add(current_views[contact])
        for head_hash, latest_block in latest_block_candidates.items():
            chain = hippiehug.Chain(self.global_store, head=head_hash)
            candidate_views.add(View(chain))

        # Resolve conflicts using a policy
        view = policy(candidate_views)
        committed_view = self.committed_views.get(contact)
        if committed_view is not None and committed_view.head != view.head:
            self.queued_views[contact] = view
        return view

    def send_message(self, recipients):
        if len(recipients) == 0:
            return

        with self.params.as_default():
            local_object_keys = set()
            global_object_keys = set()

            # Check if any of the contacts or capability entries
            # that are relevant to the current message have
            # been updated. If yes, commit new block with the updates
            # before sending the message.
            # NOTE: This assumes that claims contain heads

            # TODO: This should be an update chain policy

            # # * Update chain if any public cap needs to be updated
            # if len(self.queued_caps[PUBLIC_READER_LABEL]) > 0:
            #     self.update_chain()
            public_contacts = self.committed_caps[PUBLIC_READER_LABEL]

            # # * Update chain if any relevant private cap needs to be updated
            # for recipient in recipients:
            #     for cap in self.queued_caps[recipient])
            #         self.update_chain()
            #         break

            private_contacts = set()
            for recipient in recipients:
                private_contacts.update(self.committed_caps[recipient])

            # # * Update chain if any contact that is to be shared in this
            # # message was updated.
            # relevant_contacts = private_contacts | public_contacts
            # # Resolve heads for all the contacts to be shared
            # for contact in relevant_contacts:
            #     _ = self.get_view(contact)

            # # If any were resolved to new versions, update chain
            # if len(relevant_contacts.intersection(self.queued_views)) > 0:
            #     self.update_chain()

            # Add own chain blocks
            # NOTE: Requires that chain and tree use separate stores
            local_object_keys.update(self.chain_store.keys())

            # Add evidence for public claims
            for contact in public_contacts:
                object_keys = self.state.compute_evidence_keys(
                        PUBLIC_READER_PARAMS.dh.pk, contact)
                local_object_keys.update(object_keys)
                contact_view = self.committed_views.get(contact)
                if contact_view is not None:
                    global_object_keys.add(contact_view.head)

            # Compute evidence that needs to be sent to all recipients
            for recipient in recipients:
                # NOTE: This assumes that claims contain heads
                accessible_contacts = self.committed_caps[recipient]
                for contact in accessible_contacts:
                    recipient_view = self.committed_views.get(recipient)
                    if recipient_view is None:
                        continue
                    contact_view = self.committed_views.get(contact)
                    if contact_view is not None:
                        # Add evidence for cross-references
                        recipient_dh_pk = recipient_view.params.dh.pk
                        evidence_keys = self.state.compute_evidence_keys(
                                recipient_dh_pk, contact)
                        local_object_keys.update(evidence_keys)

                        # Add contact's latest block
                        global_object_keys.add(contact_view.head)

            # Compute the minimal amount of objects that need to be sent in
            # this email
            relevant_keys = local_object_keys | global_object_keys
            object_keys_to_send = set()
            for recipient in recipients:
                if recipient not in self.sent_objects_by_recipient:
                    self.sent_objects_by_recipient[recipient] = relevant_keys
                    object_keys_to_send = relevant_keys
                else:
                    object_keys_for_recipient = relevant_keys.difference(
                            self.sent_objects_by_recipient[recipient])
                    object_keys_to_send |= object_keys_for_recipient

            # Gather the objects by keys
            message_store = {}
            for key in local_object_keys.intersection(object_keys_to_send):
                value = self.chain_store.get(key) or self.tree_store.get(key)
                if value is not None:
                    message_store[key] = value

            for key in global_object_keys.intersection(object_keys_to_send):
                value = self.global_store.get(key)
                if value is not None:
                    message_store[key] = value

            self.nb_sent_emails += 1
            return self.chain.head, public_contacts, message_store

    def get_accessible_contacts(self, sender, recipient, message_metadata,
                                other_recipients=None):
        contacts = self.contacts_by_sender[sender]
        sender_head, public_contacts, message_store = message_metadata
        other_recipients = set(other_recipients) - {sender, recipient}
        for recipient in other_recipients | public_contacts:
            contacts.add(recipient)
        return contacts

    def receive_message(self, sender, recipient, message_metadata,
                        other_recipients=None):
        sender_head, public_contacts, message_store = message_metadata
        if other_recipients is None:
            other_recipients = set()
        with self.params.as_default():
            sender_latest_block = message_store[sender_head]
            self.global_store[sender_head] = sender_latest_block
            sender_chain = Chain(message_store, root_hash=sender_head)
            self.queued_views[sender] = View(sender_chain)

            # Add relevant objects from the message store
            object_keys_to_copy = {sender_head}
            contacts = self.get_accessible_contacts(
                    sender, recipient, message_metadata, other_recipients)
            for contact in contacts:
                contact_head = self.get_contact_head_from_view(
                        sender_view, contact)
                if contact_head is None:
                    continue
                object_keys_to_copy.add(contact_head)
                self.global_views[sender][contact] = contact_head

            for object_key in object_keys_to_copy:
                block = message_store.get(object_key)
                if block is not None:
                    self.global_store[object_key] = block

            # Recompute the latest beliefs
            for contact in {sender} | contacts:
                self.get_latest_view(contact)

    def get_contact_head_from_view(self, view, claim_label):
        with self.params.as_default():
            claim = view.get(claim_label)
            if claim is not None:
                return claim
        with PUBLIC_READER_PARAMS.as_default():
            claim = view.get(claim_label)
        return claim

    def update_chain(self):
        with self.params.as_default():
            # Get heads of views in the buffer into the claimchain state,
            # and move the buffer views into main views
            for friend, view in self.queued_views.items():
                claim = view.chain.head
                if claim is not None:
                    self.state[friend] = claim

            # Get capabilities in the capability buffer into the claimchain
            # state, for those subjects whose keys are known.
            added_caps = []
            for friend, labels in self.queued_caps.items():
                friend_dh_pk = None
                # If the buffer is for the public 'reader'
                if friend == PUBLIC_READER_LABEL:
                    friend_dh_pk = PUBLIC_READER_PARAMS.dh.pk

                # Else try to find the DH key in views
                else:
                    view = self.get_latest_block(friend)
                    if view is not None:
                        friend_dh_pk = view.params.dh.pk

                if friend_dh_pk is not None:
                    self.state.grant_access(friend_dh_pk, labels)
                    self.committed_caps[friend].update(labels)
                    added_caps.append(friend)

            # Add the latest encryption key
            if self.queued_identity_info is not None:
                self.state.identity_info = self.queued_identity_info

            # Commit state
            head = self.state.commit(target_chain=self.chain,
                    tree_store=self.tree_store)

            # Flush the view and caps buffers
            for friend, view in self.queued_views.items():
                self.committed_views[friend] = view
            self.queued_views.clear()
            for subject in added_caps:
                del self.queued_caps[subject]

    def maybe_update_key(self, force=False):
        nb_sent_emails_thresh = SimulationParams.get_default() \
                .key_update_every_nb_sent_emails

        if force or (nb_sent_emails_thresh is not None and \
                     self.nb_sent_emails > nb_sent_emails_thresh):
            self.queued_identity_info = Agent.generate_public_key()
            self.update_chain()
