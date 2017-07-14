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
            self.agents[user] = Agent(user)


def latest_timestamp_resolution_policy(views):
    # NOTE: Naive resolution policy that does not check for forks
    return max(views, key=lambda view: view.payload.timestamp)


def immediate_chain_update_policy(agent, recipients):
    # Check if any of the contacts or capability entries
    # that are relevant to the current message have
    # been updated. If yes, commit new block with the updates
    # before sending the message.
    # NOTE: This assumes that claims contain heads

    # * Update chain if any public cap needs to be updated
    if len(agent.queued_caps[PUBLIC_READER_LABEL]) > 0:
        return True

    public_contacts = agent.committed_caps[PUBLIC_READER_LABEL]

    # * Update chain if any relevant private cap needs to be updated
    for recipient in recipients:
        if len(agent.queued_caps[recipient]) > 0:
            return True

    private_contacts = set()
    for recipient in recipients:
        private_contacts.update(agent.committed_caps[recipient])

    # * Update chain if any contact that is to be shared in this
    # message was updated.
    relevant_contacts = private_contacts | public_contacts
    if len(relevant_contacts.intersection(agent.queued_views)) > 0:
        return True


class Agent(object):
    '''
    Simulated claimchain user in the online deployment mode.
    '''
    def __init__(self, email,
                 conflict_resolution_policy=None,
                 chain_update_policy=None):

        self.email = email
        self.conflict_resolution_policy = conflict_resolution_policy \
                or latest_timestamp_resolution_policy
        self.chain_update_policy = chain_update_policy \
                or immediate_chain_update_policy

        self.params = LocalParams.generate()
        self.chain_store = ObjectStore()
        self.tree_store = ObjectStore()
        self.chain = Chain(self.chain_store)
        self.state = State()

        self.nb_sent_emails = 0

        self.committed_caps = defaultdict(set)
        self.committed_views = {}
        self.queued_identity_info = None
        self.queued_caps = defaultdict(set)
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

    def add_expected_reader(self, reader, contacts):
        if reader not in self.queued_caps:
            self.queued_caps[reader] = set(contacts)
        else:
            self.queued_caps[reader].update(contacts)

    def get_latest_view(self, contact):
        policy = self.conflict_resolution_policy

        # Collect possible candidates
        current_views = dict(self.committed_views)
        current_views.update(self.queued_views)
        candidate_views = set()
        if contact in current_views:
            candidate_views.add(current_views[contact])

        for friend in current_views:
            if friend == contact:
                continue
            candidate_view = self.global_views[friend].get(contact)
            if candidate_view is not None:
                candidate_views.add(candidate_view)

        # If no candidates, return None
        if len(candidate_views) == 0:
            return None

        # Otherwise, resolve conflicts using a policy
        view = policy(candidate_views)
        committed_view = self.committed_views.get(contact)
        if committed_view is not None and committed_view.head != view.head:
            self.queued_views[contact] = view
        return view

    def send_message(self, recipients):
        if len(recipients) == 0:
            return
        if not isinstance(recipients, set):
            recipients = set(recipients)

        with self.params.as_default():
            # TODO: Make an introduction policy
            for recipient in recipients - {self.email}:
                others = recipients - {self.email, recipient}
                self.add_expected_reader(recipient, others)

            policy = self.chain_update_policy
            if policy(self, recipients):
                self.update_chain()

            local_object_keys = set()
            global_object_keys = set()

            # Add own chain blocks
            # NOTE: Requires that chain and tree use separate stores
            local_object_keys.update(self.chain_store.keys())

            public_contacts = self.committed_caps[PUBLIC_READER_LABEL]

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

    def get_accessible_contacts(self, sender, message_metadata,
                                other_recipients=None):
        # NOTE: Assumes other people's introduction policy is the same
        contacts = self.contacts_by_sender[sender]
        sender_head, public_contacts, message_store = message_metadata
        other_recipients = set(other_recipients) - {sender, self.email}
        for recipient in other_recipients | public_contacts:
            contacts.add(recipient)
        return contacts

    def receive_message(self, sender, message_metadata,
                        other_recipients=None):
        sender_head, public_contacts, message_store = message_metadata
        if other_recipients is None:
            other_recipients = set()
        with self.params.as_default():
            # Merge stores temporarily
            merged_store = ObjectStore(self.global_store)
            for key, obj in message_store.items():
                merged_store[key] = obj

            sender_latest_block = merged_store[sender_head]
            self.global_store[sender_head] = sender_latest_block
            self.queued_views[sender] = View(
                    Chain(self.global_store, root_hash=sender_head))
            full_sender_view = View(
                    Chain(merged_store, root_hash=sender_head))

            # Add relevant objects from the message store
            contacts = self.get_accessible_contacts(
                    sender, message_metadata, other_recipients)
            for contact in contacts:
                contact_head = self.get_contact_head_from_view(
                        full_sender_view, contact)
                if contact_head is None:
                    continue
                contact_latest_block = message_store.get(contact_head)
                if contact_latest_block is not None:
                    self.global_store[contact_head] = contact_latest_block

                # NOTE: Assumes people send only contacts' latest blocks
                contact_chain = Chain(self.global_store, root_hash=contact_head)
                self.global_views[sender][contact] = View(contact_chain)

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
            for friend, contacts in self.queued_caps.items():
                if len(contacts) == 0:
                    continue

                friend_dh_pk = None
                # If the buffer is for the public 'reader'
                if friend == PUBLIC_READER_LABEL:
                    friend_dh_pk = PUBLIC_READER_PARAMS.dh.pk

                # Else try to find the DH key in views
                else:
                    view = self.get_latest_view(friend)
                    if view is not None:
                        friend_dh_pk = view.params.dh.pk

                if friend_dh_pk is not None:
                    self.state.grant_access(friend_dh_pk, contacts)
                    self.committed_caps[friend].update(contacts)
                    added_caps.append(friend)

            # Add the latest encryption key
            if self.queued_identity_info is not None:
                self.state.identity_info = self.queued_identity_info

            # Commit state
            head = self.state.commit(target_chain=self.chain,
                    tree_store=self.tree_store)

            # Flush the view and caps buffers and update current state
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
