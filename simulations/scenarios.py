import pickle

from enum import Enum
from collections import defaultdict

import numpy as np
import pandas as pd

from attr import Factory, attrs, attrib, evolve as clone
from defaultcontext import with_default_context

from .parse_enron import Message


enc_status = {"plaintext": 0, "stale": 1, "encrypted": 2}


class EncStatus(Enum):
    plaintext = 0
    stale = 1
    encrypted = 2


@with_default_context
@attrs
class SimulationParams(object):
    # One of 'dummy', 'real_code'
    mode = attrib(default='dummy')

    # Max buffer size for user after which she updates her chain.
    # If None, chains are never updated
    chain_update_buffer_size = attrib(default=None)

    # Max number of sent emails by a user after which she updates her key.
    # If None, keys are never updated
    key_update_every_nb_sent_emails = attrib(default=None)


class Context(object):
    def __init__(self, log, social_graph):
        self.log = log
        self.social_graph = social_graph

        # Set of the dataset users we know the full social graph for
        self.userset = set(self.social_graph.keys())

        # Set of all users that eventually send an email
        self.senders = {email.From for email in self.log}

        self.global_social_graph = {}
        for email in log:
            if email.From not in self.global_social_graph:
                self.global_social_graph[email.From] = {'friends': set()}

            recipients = email.To | email.Cc | email.Bcc - {email.From}
            for recipient in recipients:
                self.global_social_graph[email.From]['friends'].add(recipient)


@attrs
class View(object):
    key = attrib(default=None)
    head = attrib(default=None)

    def update_from_state(self, state):
        self.key = state.key
        self.head = state.head

    def update_from_view(self, other_view):
        self.key = other_view.key
        self.head = other_view.head


@attrs
class State(object):
    key = attrib(default=1)
    head = attrib(default=1)

    def update_head(self, global_state=None, claim_buffer=None):
        self.head += 1

    def update_key(self):
        self.key += 1


@attrs
class GlobalState(object):
    context                    = attrib()
    local_views                = attrib(default=Factory(dict))
    public_views               = attrib(default=Factory(dict))
    state_by_user              = attrib(default=Factory(dict))
    claim_buffer_by_user       = attrib(default=Factory(lambda: defaultdict(dict)))
    nb_sent_emails_by_user     = attrib(default=Factory(lambda: defaultdict(int)))
    sent_email_count           = attrib(default=0)
    encrypted_email_count      = attrib(default=0)

    def create_local_view(self, user, friend):
        self.local_views[(user, friend)] = View()

    def create_public_view(self, user, friend):
        self.public_views[(user, friend)] = View()

    def create_state(self, user):
        self.state_by_user[user] = State()

    def eval_propagation(self, mode='key'):
        '''
        Count how many entries for the friends of the userset users are
        up-to-date, stale, or not updated at all

        :param mode: One of ['key', 'head']
        '''
        assert mode in ['key', 'head']

        updated = 0
        stale = 0
        not_updated = 0

        for user in self.context.userset:
            for friend in self.context.social_graph[user]['friends']:
                # Do not count links derived from emails found in the Sent directories of the users
                # in the userset, when the sender address is not the main one of that user
                if (user, friend) not in self.local_views:
                    continue

                # If value is None, then user did not learn of her friend's updates
                mode_view = getattr(self.local_views[(user, friend)], mode)
                if mode_view is None:
                    not_updated += 1
                    continue

                # If the friend is not included in the userset, and value is greater than 0,
                # user knows of the head update at the beginning of time
                if friend not in self.context.userset:
                    updated += 1
                    continue

                # Else if friend is included in the userset, we check whether the user knows
                # of her friend's latest head, or an older, stale head
                if mode_view == getattr(self.state_by_user[friend], mode):
                    updated += 1
                else:
                    stale += 1

        return updated, stale, not_updated

    def record_sent_email(self, user, recipients):
        status = EncStatus.encrypted
        if user in self.context.userset:
            self.sent_email_count += 1
            self.encrypted_email_count += 1
            self.nb_sent_emails_by_user[user] += 1

        for recipient in recipients:
            view = self.local_views.get((user, recipient))

            # If sender does not know of a recipient's enc key, the email is
            # sent in clear text
            if (view is None or view.key is None):
                if user in self.context.userset:
                    self.encrypted_email_count -= 1
                    status = EncStatus.plaintext

            elif recipient in self.context.senders and \
                 view.key != self.state_by_user[recipient].key:
                status = EncStatus.stale
                # TODO: Why no break here?
                # break

        return status

    def maybe_update_chain(self, user, force=False):
        min_buffer_size = SimulationParams.get_default().chain_update_buffer_size

        if force or (min_buffer_size is not None \
                     and len(self.claim_buffer_by_user[user]) > min_buffer_size):
            for friend, view in self.claim_buffer_by_user[user].items():
                if (user, friend) not in self.public_views:
                    self.create_public_view(user, friend)
                self.public_views[(user, friend)].update_from_view(view)
            self.claim_buffer_by_user[user].clear()
            self.state_by_user[user].update_head()
            return True

        return False

    def maybe_update_key(self, user, force=False):
        min_nb_sent_emails = SimulationParams.get_default().key_update_every_nb_sent_emails

        if force or (min_nb_sent_emails is not None and \
                     self.nb_sent_emails_by_user[user] > min_nb_sent_emails):
            self.state_by_user[user].update_key()
            self.maybe_update_chain(user, force=True)
            return True

        return False


def create_global_state(context):
    '''Prepare the global state of the simulation'''
    global_state = GlobalState(context)

    # Initialize the latest known head dictionary
    for email in context.log:
        global_state.create_state(email.From)
        recipients = email.To | email.Cc | email.Bcc - {email.From}
        for recipient in recipients:
            global_state.create_local_view(email.From, recipient)
            global_state.create_public_view(email.From, recipient)

    return global_state


def simulate_autocrypt(context):
    '''Simulate Autocrypt

    * Public and private recipients learn of the sender's latest key
    '''
    print("Simulating Autocrypt:")
    print(SimulationParams.get_default())

    global_state = create_global_state(context)

    key_propagation_data = pd.DataFrame(columns=('Updated', 'Stale', 'Not updated'))
    encryption_status_data = pd.Series()

    for index, email in enumerate(context.log):
        recipients = email.To | email.Cc | email.Bcc - {email.From}

        global_state.maybe_update_key(email.From)

        encryption_status = global_state.record_sent_email(email.From, recipients)
        encryption_status_data.loc[index] = encryption_status

        # For all recipients, update their local dict entry for the sender
        sender_state = global_state.state_by_user[email.From]
        for recipient in recipients:
            if (recipient, email.From) in global_state.local_views:
                global_state.local_views[(recipient, email.From)] \
                        .update_from_state(sender_state)

        if index % 100 == 0:
            key_propagation_data.loc[index] = global_state.eval_propagation(mode='key')

    updated, stale, not_updated = global_state.eval_propagation(mode='key')

    print('Keys.   Updated: %d, Not updated: %d, Stale: %d' % (updated, not_updated, stale))
    print('Emails. Sent: %d, Encrypted: %d' % (
        global_state.sent_email_count,
        global_state.encrypted_email_count))

    return key_propagation_data, encryption_status_data


def simulate_claimchain_no_privacy(context):
    '''Simulate the static view of ClaimChain without privacy

        * Public and private recipients learn of the sender's latest head
        * Public and private recipients learn of the latest head of the friends of the sender
    '''
    print("Simulating the ClaimChain with public claims:")
    print(SimulationParams.get_default())

    global_state = create_global_state(context)

    key_propagation_data = pd.DataFrame(columns=('Updated', 'Stale', 'Not updated'))
    head_propagation_data = pd.DataFrame(columns=('Updated', 'Stale', 'Not updated'))
    encryption_status_data = pd.Series()

    for index, email in enumerate(context.log):
        recipients = email.To | email.Cc | email.Bcc - {email.From}

        global_state.maybe_update_key(email.From)
        global_state.maybe_update_chain(email.From)

        encryption_status = global_state.record_sent_email(email.From, recipients)
        encryption_status_data.loc[index] = encryption_status

        # For all recipients, update their local dict entry for the sender
        sender_state = global_state.state_by_user[email.From]
        for recipient in recipients.intersection(context.senders):

            # If recipient hasn't heard about sender, create view
            # TODO: Why not in global state initialization?
            if (recipient, email.From) not in global_state.local_views:
                global_state.create_local_view(recipient, email.From)

            # Update recipient's view with latest committed sender's state
            recipient_view_of_sender = global_state.local_views.get((recipient, email.From))
            if recipient_view_of_sender.head != sender_state.head:
                recipient_view_of_sender.update_from_state(sender_state)
                global_state.claim_buffer_by_user[recipient][email.From] = sender_state

        # Update the social graph entries of the recipients for their friends, if the sender
        # knows of a later head
        for recipient in recipients.intersection(context.senders):
            for friend in global_state.context.global_social_graph[recipient]['friends']:
                if (email.From, friend) not in global_state.public_views:
                    continue

                if (recipient, friend) not in global_state.local_views:
                    global_state.create_local_view(recipient, friend)

                recipient_view_of_friend = global_state.local_views[(recipient, friend)]
                sender_public_view_of_friend = global_state.public_views[(email.From, friend)]

                if recipient_view_of_friend.head != sender_public_view_of_friend.head:
                    recipient_view_of_friend.update_from_view(sender_public_view_of_friend)
                    global_state.claim_buffer_by_user[recipient][friend] = sender_public_view_of_friend

        if index % 100 == 0:
            key_propagation_data.loc[index] = global_state.eval_propagation(mode='key')
            head_propagation_data.loc[index] = global_state.eval_propagation(mode='head')

    updated, stale, not_updated = global_state.eval_propagation(mode='key')
    print('Keys:   Updated: %d, Not updated: %d, Stale: %d' % (updated, not_updated, stale))

    updated, stale, not_updated = global_state.eval_propagation(mode='head')
    print('Heads:  Updated: %d, Not updated: %d, Stale: %d' % (updated, not_updated, stale))

    print('Emails: Sent: %d, Encrypted: %d' % (
        global_state.sent_email_count,
        global_state.encrypted_email_count))

    return key_propagation_data, head_propagation_data, encryption_status_data


def simulate_claimchain_with_privacy(context):
    '''Simulate ClaimChain with support for private claims (introduction mode)

        * Public and private recipients learn of the sender's latest head
        * Sender grants access to public and private recipients to read the entries of public recipients in her ClaimChain
        * Recipients learn of the latest head of the friends of the sender that have the capability to access
    '''
    print("Simulating ClaimChain with private claims and introductions:")
    print(SimulationParams.get_default())

    global_state = create_global_state(context)
    introductions = {}

    key_propagation_data = pd.DataFrame(columns=('Updated', 'Stale', 'Not updated'))
    head_propagation_data = pd.DataFrame(columns=('Updated', 'Stale', 'Not updated'))
    encryption_status_data = pd.Series()

    for index, email in enumerate(context.log):
        public_recipients = email.To | email.Cc - {email.From}
        recipients = public_recipients | email.Bcc - {email.From}

        global_state.maybe_update_key(email.From)
        global_state.maybe_update_chain(email.From)

        encryption_status = global_state.record_sent_email(email.From, recipients)
        encryption_status_data.loc[index] = encryption_status

        # For all recipients, update their local dict entry for the sender
        sender_state = global_state.state_by_user[email.From]
        for recipient in recipients.intersection(context.senders):

            # If recipient hasn't heard about sender, create view
            if (recipient, email.From) not in global_state.local_views:
                global_state.create_local_view(recipient, email.From)

            # Update recipient's view with latest committed sender's state
            recipient_view_of_sender = global_state.local_views.get((recipient, email.From))
            if recipient_view_of_sender.head != sender_state.head:
                recipient_view_of_sender.update_from_state(sender_state)
                global_state.claim_buffer_by_user[recipient][email.From] = sender_state

        # Update introductions
        if email.From not in introductions:
            introductions[email.From] = {}
        for recipient in recipients:
            if recipient not in introductions[email.From]:
                introductions[email.From][recipient] = set()
            for public_recipient in public_recipients:
                introductions[email.From][recipient].add(public_recipient)

        # Update the social graph entries of the recipients for their friends, if the sender
        # knows of a later head
        for recipient in recipients.intersection(context.senders):
            if recipient not in introductions[email.From]:
                continue

            for friend in introductions[email.From][recipient]:
                if (email.From, friend) not in global_state.public_views:
                    continue

                if (recipient, friend) not in global_state.local_views:
                    global_state.create_local_view(recipient, friend)

                recipient_view_of_friend = global_state.local_views[(recipient, friend)]
                sender_public_view_of_friend = global_state.public_views[(email.From, friend)]

                if recipient_view_of_friend.head != sender_public_view_of_friend.head:
                    recipient_view_of_friend.update_from_view(sender_public_view_of_friend)
                    global_state.claim_buffer_by_user[recipient][friend] = sender_public_view_of_friend

        if index % 100 == 0:
            key_propagation_data.loc[index] = global_state.eval_propagation(mode='key')
            head_propagation_data.loc[index] = global_state.eval_propagation(mode='head')

    updated, stale, not_updated = global_state.eval_propagation(mode='key')
    print('Keys:   Updated: %d, Not updated: %d, Stale: %d' % (updated, not_updated, stale))

    updated, stale, not_updated = global_state.eval_propagation(mode='head')
    print('Heads:  Updated: %d, Not updated: %d, Stale: %d' % (updated, not_updated, stale))

    print('Emails: Sent: %d, Encrypted: %d' % (
        global_state.sent_email_count,
        global_state.encrypted_email_count))

    return key_propagation_data, head_propagation_data, encryption_status_data
