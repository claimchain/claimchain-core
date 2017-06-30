from attr import attrs, attrib
from enum import Enum
from defaultcontext import with_default_context


class EncStatus(Enum):
    plaintext = 0
    stale = 1
    encrypted = 2


@with_default_context(use_empty_init=True)
@attrs
class SimulationParams(object):
    # Max buffer size for user after which she updates her chain.
    # If None, chains are never updated
    chain_update_buffer_size = attrib(default=5)

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

