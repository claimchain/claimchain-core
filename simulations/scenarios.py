import pickle
import logging

import numpy as np
import pandas as pd

from attr import attrs, attrib


logging.basicConfig(level=logging.DEBUG)



parsed_logs_folder = 'Enron/parsing/'
social_graph = pickle.load(open(parsed_logs_folder + "social.pkl", "rb"))
log = pickle.load(open(parsed_logs_folder + "replay_log.pkl", "rb"))

enc_status = {"plaintext": 0, "stale": 1, "encrypted": 2}
email_status = {"stat_autocrypt": [], "stat_pub_claimchain": [], "stat_priv_claimchain": [], "dyn_autocrypt": [], "dyn_pub_claimchain": [], "dyn_priv_claimchain": []}


def make_global_graph(log):
    '''Construct a global social graph using the log of all emails'''
    global_graph = {}
    global_userset = set()

    for email in log:
        if email.From not in global_userset:
            global_userset.add(email.From)
            global_graph[email.From] = {'friends': set()}

        recipients = email.To | email.Cc | email.Bcc - {email.From}
        for recipient in recipients:
            global_graph[email.From]['friends'].add(recipient)

    return global_graph, global_userset


def prep_static_view(log, social_graph):
    '''Prepare the `userset`, `head_dict` and `key_dict` structs for the static view scenario

    In the static view scenario, all users update their encryption key at the beginning of time.
    We then simulate how the updated keys get propagated after replaying all messages in
    chronological order. We instantiate the `userset`, `key_dict` and `head_dict` structs as follows:

      * We include in `userset` the users that we have full access to their sent messages
      * We boostrap the social graph of each user in the userset with her future recipients
      * We create a `head_dict` struct to keep track of the latest known head of a user's friends
    '''
    # Set of the dataset users we know the full social graph for
    userset = set(social_graph.keys())

    # Initial state of the global [head, key] state
    local_dict = {}

    # Buffer to keep claims before they get published on the owner's ClaimChain
    claim_buffer = {}

    # Initialize the latest known head dictionary
    for email in log:
        local_dict[(email.From, email.From)] = [1, 1]
        claim_buffer[email.From] = {}

        recipients = email.To | email.Cc | email.Bcc - {email.From}
        for recipient in recipients:
            local_dict[(email.From, recipient)] = [0, 0]

    return userset, local_dict, local_dict, claim_buffer


def eval_propagation(prop_dict, term_index, social_graph, userset):
    '''Given `head_dict` or `key_dict`, count how many entries for the friends of
    the given userset users are up-to-date, stale, or not updated at all'''
    updated = 0
    stale = 0
    not_updated = 0

    for user in userset:
        for friend in social_graph[user]['friends']:
            # Do not count links derived from emails found in the Sent directories of the users
            # in the userset, when the sender address is not the main one of that user
            if (user, friend) not in prop_dict:
                continue

            # If entry value is 0, then user did not learn of her friend's updates
            if prop_dict[(user, friend)][term_index] == 0:
                not_updated += 1
                continue

            # If the friend is not included in the userset, and value is greater than 0,
            # user knows of the head update at the beginning of time
            if (friend, friend) not in prop_dict:
                updated += 1
            # Else if friend is included in the userset, we check whether the user knows
            # of her friend's latest head, or an older, stale head
            else:
                if prop_dict[(user, friend)][term_index] == prop_dict[(friend, friend)][term_index]:
                    updated += 1
                else:
                    stale += 1

    return updated, stale, not_updated


def append_block_policy(claim_buffer, user, local_dict, public_dict, force=False):
    if force or len(claim_buffer[user]) > 5:
        for contact, new_head in claim_buffer[user].items():
            public_dict[(user, contact)] = new_head
        claim_buffer[user] = {}
        local_dict[(user, user)][0] += 1
        public_dict[(user, user)][0] += 1

    return claim_buffer, local_dict, public_dict


def update_enc_email_status_cnt(user, userset, recipients, local_dict, sent_userset_cnt, enc_userset_cnt):
    status = enc_status["encrypted"]
    if user in userset:
        sent_userset_cnt += 1
        enc_userset_cnt += 1

    for recipient in recipients:
        try:
            # If sender does not know of a recipient's enc key, the email is
            # sent in clear text
            if local_dict[(user, recipient)][1] == 0:
                raise
        except:
            status = enc_status["plaintext"]
            if user in userset:
                enc_userset_cnt -= 1
            break
        if local_dict[(user, recipient)][1] < local_dict[(recipient, recipient)][1]:
            status = enc_status["stale"]

    return status, sent_userset_cnt , enc_userset_cnt


def simulate_static_autocrypt(social_graph, log):
    '''Simulate the static view of Autocrypt

        * Public and private recipients learn of the sender's latest head
    '''
    print("Simulating the static view scenario of Autocrypt:")

    userset, local_dict, _, _ = prep_static_view(log, social_graph)

    sent_userset_emails = 0
    enc_userset_emails = 0

    cnt = 0
    kp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))
    hp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))

    for index, email in enumerate(log):
        recipients = email.To | email.Cc | email.Bcc - {email.From}

        e_status, sent_userset_emails, enc_userset_emails = update_enc_email_status_cnt(email.From, userset, recipients, local_dict, sent_userset_emails, enc_userset_emails)
        email_status["stat_autocrypt"].append(e_status)

        # For all recipients, update their local dict entry for the sender
        for recipient in recipients:
            local_dict[(recipient, email.From)] = local_dict[email.From, email.From]

        if cnt % 100 == 0:
            updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
            kp.loc[cnt] = [not_updated, updated, stale]
            updated, stale, not_updated = eval_propagation(local_dict, 0, social_graph, userset)
            hp.loc[cnt] = [not_updated, updated, stale]

        cnt += 1

    updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
    print("Userset users know of %s updates of their friends, while %s entries were not updated."
          % (updated + stale, not_updated))
    print("%s out of the %s emails sent by users in the userset were encrypted." % (enc_userset_emails, sent_userset_emails))

    return kp, hp


def simulate_static_claimchain_no_privacy(social_graph, log):
    '''Simulate the static view of ClaimChain without privacy

        * Public and private recipients learn of the sender's latest head
        * Public and private recipients learn of the latest head of the friends of the sender
    '''
    print("Simulating the static view scenario of ClaimChain with public claims:")

    userset, local_dict, public_dict, claim_buffer = prep_static_view(log, social_graph)
    global_graph, _ = make_global_graph(log)

    sent_userset_emails = 0
    enc_userset_emails = 0

    cnt = 0
    kp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))
    hp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))

    for email in log:
        recipients = email.To | email.Cc | email.Bcc - {email.From}

        e_status, sent_userset_emails, enc_userset_emails = update_enc_email_status_cnt(email.From, userset, recipients, local_dict, sent_userset_emails, enc_userset_emails)
        email_status["stat_pub_claimchain"].append(e_status)

        claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict)

        # For all recipients, update their local dict entry for the sender
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if ( (recipient, email.From) not in local_dict or
                 local_dict[(recipient, email.From)][0] < public_dict[email.From, email.From][0]):
                local_dict[(recipient, email.From)] = public_dict[email.From, email.From]
                claim_buffer[recipient][email.From] = public_dict[email.From, email.From]

        # Update the social graph entries of the recipients for their friends, if the sender
        # knows of a later head
        for recipient in recipients:
            if recipient in global_graph:
                for friend in global_graph[recipient]['friends']:
                    if ((recipient, friend) not in local_dict and
                        local_dict[(recipient, friend)][0] < public_dict[(email.From, friend)][0]):
                        local_dict[(recipient, friend)] = public_dict[(email.From, friend)]
                        claim_buffer[recipient][email.From] = public_dict[email.From, friend]

        if cnt % 100 == 0:
            updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
            kp.loc[cnt] = [not_updated, updated, stale]
            updated, stale, not_updated = eval_propagation(local_dict, 0, social_graph, userset)
            hp.loc[cnt] = [not_updated, updated, stale]

        cnt += 1

    updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
    print("Userset users know of %s updates of their friends, while %s entries were not updated."
          % (updated + stale, not_updated))
    print("%s out of the %s emails sent by users in the userset were encrypted." % (enc_userset_emails, sent_userset_emails))

    return kp, hp


def simulate_static_claimchain_with_privacy(social_graph, log):
    '''Simulate the static view of ClaimChain with support for private claims (introduction mode)

        * Public and private recipients learn of the sender's latest head
        * Sender grants access to public and private recipients to read the entries of public recipients in her ClaimChain
        * Recipients learn of the latest head of the friends of the sender that have the capability to access
    '''
    print("Simulating the static view scenario of ClaimChain with private claims and introductions:")

    userset, local_dict, public_dict, claim_buffer = prep_static_view(log, social_graph)
    introductions = {}

    enc_userset_emails = 0
    sent_userset_emails = 0

    cnt = 0
    kp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))
    hp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))

    for index, email in enumerate(log):
        public_recipients = email.To | email.Cc - {email.From}
        recipients = public_recipients | email.Bcc - {email.From}

        e_status, sent_userset_emails, enc_userset_emails = update_enc_email_status_cnt(email.From, userset, recipients, local_dict, sent_userset_emails, enc_userset_emails)
        email_status["stat_priv_claimchain"].append(e_status)

        claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict)

        # For all recipients, update their local dict entry for the sender
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if ( (recipient, email.From) not in local_dict or
                 local_dict[(recipient, email.From)][0] < public_dict[email.From, email.From][0]):
                local_dict[(recipient, email.From)] = public_dict[email.From, email.From]
                claim_buffer[recipient][email.From] = public_dict[email.From, email.From]

        # Update introductions
        if email.From not in introductions:
            introductions[email.From] = {}

        for recipient in recipients:
            if recipient not in introductions[email.From]:
                    introductions[email.From][recipient] = set([])
            for public_recipient in public_recipients:
                introductions[email.From][recipient].add(public_recipient)

        # Update the social graph entries of the recipients for their friends, if the sender
        # knows of a later head and they have access to it
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if recipient in introductions[email.From]:
                for friend in introductions[email.From][recipient]:
                    try:
                        if local_dict[(recipient, friend)][0] < public_dict[(email.From, friend)][0]:
                            local_dict[(recipient, friend)] = public_dict[(email.From, friend)]
                            claim_buffer[recipient][friend] = public_dict[(email.From, friend)]
                    except:
                        continue

        if cnt % 100 == 0:
            updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
            kp.loc[cnt] = [not_updated, updated, stale]
            updated, stale, not_updated = eval_propagation(local_dict, 0, social_graph, userset)
            hp.loc[cnt] = [not_updated, updated, stale]

        cnt += 1


    updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
    print("Userset users know of %s updates of their friends, while %s entries were not updated."
          % (updated + stale, not_updated))
    print("%s out of the %s emails sent by users in the userset were encrypted." % (enc_userset_emails, sent_userset_emails))

    return kp, hp


def simulate_dynamic_autocrypt(social_graph, log):
    '''Simulate the dynamic view of Autocrypt

    * Public and private recipients learn of the sender's latest head
    '''
    print("Simulating the dynamic view scenario of Autocrypt:")

    userset, local_dict, public_dict, claim_buffer = prep_static_view(log, social_graph)

    sent_userset_emails = 0
    enc_userset_emails = 0

    cnt = 0
    kp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))
    hp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))

    cnt_sent_from = {}

    for index, email in enumerate(log):
        recipients = email.To | email.Cc | email.Bcc - {email.From}

        if email.From not in cnt_sent_from:
            cnt_sent_from[email.From] = 0
        cnt_sent_from[email.From] += 1

        if cnt_sent_from[email.From] % 50 == 0:
            local_dict[(email.From, email.From)][0] += 1
            claim_buffer[email.From][email.From] = local_dict[(email.From, email.From)]
            claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict, force=True)

        e_status, sent_userset_emails, enc_userset_emails = update_enc_email_status_cnt(email.From, userset, recipients, local_dict, sent_userset_emails, enc_userset_emails)
        email_status["dyn_autocrypt"].append(e_status)

        claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict)

        # For all recipients, update their local dict entry for the sender
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if ( (recipient, email.From) not in local_dict or
                 local_dict[(recipient, email.From)][0] < public_dict[email.From, email.From][0]):
                local_dict[(recipient, email.From)] = public_dict[email.From, email.From]
                claim_buffer[recipient][email.From] = public_dict[email.From, email.From]

        if cnt % 100 == 0:
            updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
            kp.loc[cnt] = [not_updated, updated, stale]
            updated, stale, not_updated = eval_propagation(local_dict, 0, social_graph, userset)
            hp.loc[cnt] = [not_updated, updated, stale]

        cnt += 1


    updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
    print("Userset users know of %s updates of their friends, while %s entries were not updated."
          % (updated + stale, not_updated))
    print("%s out of the %s emails sent by users in the userset were encrypted." % (enc_userset_emails, sent_userset_emails))

    return kp, hp


def simulate_dynamic_claimchain_no_privacy(social_graph, log):
    '''Simulate the dynamic view of ClaimChain without privacy

    * Public and private recipients learn of the sender's latest head
    * Public and private recipients learn of the latest head of the friends of the sender
    '''
    print("Simulating the dynamic view scenario of ClaimChain with public claims:")

    userset, local_dict, public_dict, claim_buffer = prep_static_view(log, social_graph)
    global_graph, global_userset = make_global_graph(log)

    sent_userset_emails = 0
    enc_userset_emails = 0

    cnt = 0
    kp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))
    hp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))

    cnt_sent_from = {}

    for index, email in enumerate(log):
        recipients = email.To | email.Cc | email.Bcc - {email.From}

        if email.From not in cnt_sent_from:
            cnt_sent_from[email.From] = 0
        cnt_sent_from[email.From] += 1

        if cnt_sent_from[email.From] % 50 == 0:
            local_dict[(email.From, email.From)][1] += 1
            claim_buffer[email.From][email.From] = local_dict[(email.From, email.From)]
            claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict, force=True)

        e_status, sent_userset_emails, enc_userset_emails = update_enc_email_status_cnt(email.From, userset, recipients, local_dict, sent_userset_emails, enc_userset_emails)
        email_status["dyn_pub_claimchain"].append(e_status)

        claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict)

        # For all recipients, update their local dict entry for the sender
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if ( (recipient, email.From) not in local_dict or
                 local_dict[(recipient, email.From)][0] < public_dict[email.From, email.From][0]):
                local_dict[(recipient, email.From)] = public_dict[email.From, email.From]
                claim_buffer[recipient][email.From] = public_dict[email.From, email.From]

        # Update the social graph entries of the recipients for their friends, if the sender
        # knows of a later head
        for recipient in recipients:
            if recipient in global_graph:
                for friend in global_graph[recipient]['friends']:
                    try:
                        if local_dict[(recipient, friend)][0] < public_dict[(email.From, friend)][0]:
                            local_dict[(recipient, friend)] = public_dict[(email.From, friend)]
                            claim_buffer[recipient][email.From] = public_dict[email.From, friend]
                    except:
                        continue

        if cnt % 100 == 0:
            updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
            kp.loc[cnt] = [not_updated, updated, stale]
            updated, stale, not_updated = eval_propagation(local_dict, 0, social_graph, userset)
            hp.loc[cnt] = [not_updated, updated, stale]

        cnt += 1


    updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
    print("Userset users know of %s updates of their friends, while %s entries were not updated."
          % (updated + stale, not_updated))
    print("%s out of the %s emails sent by users in the userset were encrypted." % (enc_userset_emails, sent_userset_emails))

    return kp, hp


def simulate_dynamic_claimchain_with_privacy(social_graph, log):
    '''Simulate the dynamic view of ClaimChain with support for private claims (introduction mode)

    * Public and private recipients learn of the sender's latest head
    * Sender grants access to public and private recipients to read the entries of public recipients in her ClaimChain
    * Recipients learn of the latest head of the friends of the sender that have the capability to access
    '''
    print("Simulating the dynamic view scenario of ClaimChain with private claims and introductions:")

    userset, local_dict, public_dict, claim_buffer = prep_static_view(log, social_graph)
    introductions = {}

    enc_userset_emails = 0
    sent_userset_emails = 0

    cnt = 0
    kp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))
    hp = pd.DataFrame(columns=('Not Updated', 'Updated', 'Stale'))

    cnt_sent_from = {}

    for index, email in enumerate(log):
        public_recipients = email.To | email.Cc - {email.From}
        recipients = public_recipients | email.Bcc - {email.From}

        if email.From not in cnt_sent_from:
            cnt_sent_from[email.From] = 0
        cnt_sent_from[email.From] += 1

        if cnt_sent_from[email.From] % 50 == 0:
            local_dict[(email.From, email.From)][1] += 1
            claim_buffer[email.From][email.From] = local_dict[(email.From, email.From)]
            claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict, force=True)

        e_status, sent_userset_emails, enc_userset_emails = update_enc_email_status_cnt(email.From, userset, recipients, local_dict, sent_userset_emails, enc_userset_emails)
        email_status["dyn_priv_claimchain"].append(e_status)

        claim_buffer, local_dict, public_dict = append_block_policy(claim_buffer, email.From, local_dict, public_dict)

        # Update introductions
        if email.From not in introductions:
            introductions[email.From] = {}

        for recipient in recipients:
            if recipient not in introductions[email.From]:
                    introductions[email.From][recipient] = set([])
            for public_recipient in public_recipients:
                introductions[email.From][recipient].add(public_recipient)

        # For all recipients, update their local dict entry for the sender
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if ( (recipient, email.From) not in local_dict or
                 local_dict[(recipient, email.From)][0] < public_dict[email.From, email.From][0]):
                local_dict[(recipient, email.From)] = public_dict[email.From, email.From]
                claim_buffer[recipient][email.From] = public_dict[email.From, email.From]

        # Update the social graph entries of the recipients for their friends, if the sender
        # knows of a later head and they have access to it
        for recipient in recipients:
            if recipient not in claim_buffer:
                continue
            if recipient in introductions[email.From]:
                for friend in introductions[email.From][recipient]:
                    try:
                        if local_dict[(recipient, friend)][0] < public_dict[(email.From, friend)][0]:
                            local_dict[(recipient, friend)] = public_dict[(email.From, friend)]
                            claim_buffer[recipient][friend] = public_dict[(email.From, friend)]
                    except:
                        continue

        if cnt % 100 == 0:
            updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
            kp.loc[cnt] = [not_updated, updated, stale]
            updated, stale, not_updated = eval_propagation(local_dict, 0, social_graph, userset)
            hp.loc[cnt] = [not_updated, updated, stale]

        cnt += 1


    updated, stale, not_updated = eval_propagation(local_dict, 1, social_graph, userset)
    print("Userset users know of %s updates of their friends, while %s entries were not updated."
          % (updated + stale, not_updated))
    print("%s out of the %s emails sent by users in the userset were encrypted." % (enc_userset_emails, sent_userset_emails))

    return kp, hp
