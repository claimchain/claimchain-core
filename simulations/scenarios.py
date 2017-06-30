import pandas as pd
from msgpack import packb

from claimchain.utils.wrappers import serialize_object

from .agent import Agent, SimulationParams, GlobalState


def serialize_store(store):
    keys = list(store.keys())
    values = [serialize_object(obj) for obj in store.values()]
    return packb((keys, values))


def serialize_caches(caches):
    return packb(list(caches))


def simulate_public_claimchain(context):
    print("Simulating the ClaimChain with public claims:")
    print(SimulationParams.get_default())

    global_state = GlobalState(context)

    key_propagation_data = pd.DataFrame(columns=('Updated', 'Stale'))
    head_propagation_data = pd.DataFrame(columns=('Updated', 'Stale'))
    encryption_status_data = pd.Series()

    sender_cache_data = {sender: pd.Series() for sender in context.senders}
    recipient_store_data = {sender: pd.Series() for sender in context.senders}
    bandwidth_data = {sender: pd.Series() for sender in context.senders}

    for index, email in enumerate(context.log):
        recipient_emails = email.To | email.Cc | email.Bcc - {email.From}

        user = global_state.agents[email.From]
        user.maybe_update_key()
        user.maybe_update_chain()

        # Allow recipients to access claims about each other
        for recipient_email in recipient_emails:
            others = recipient_emails - {recipient_email}
            user.add_expected_reader(recipient_email, others)

        # Send the email
        head, email_store = user.send_message(recipient_emails)

        # Record bandwidth and cache size
        if email.From in context.userset:
            packed_message = packb((head, serialize_store(email_store)))
            bandwidth_data[email.From].loc[index] = len(packed_message)

            packed_sender_cache = serialize_caches(user.sent_email_store_cache)
            sender_cache_data[email.From].loc[index] = len(packed_sender_cache)

        # Update states of recipients
        for recipient_email in recipient_emails.intersection(context.senders):
            recipient = global_state.agents[recipient_email]
            recipient.receive_message(email.From, head, email_store)

            # Record receiver store size
            packed_recipient_stores = \
                    packb([serialize_store(s) for s in recipient.stores.values()])
            recipient_store_data[recipient_email].loc[index] = \
                    len(packed_recipient_stores)

    return sender_cache_data, recipient_store_data, bandwidth_data
