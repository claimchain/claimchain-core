import pytest
import pickle

from .parse_enron import Message
from .utils import Context, SimulationParams

import __main__
__main__.Message = Message


parsed_logs_folder = 'Enron/parsing/'
log_entries_lim = 10000


@pytest.fixture
def log():
    with open(parsed_logs_folder + "replay_log.pkl", "rb") as f:
        yield pickle.load(f)[:log_entries_lim]


@pytest.fixture
def social_graph():
    with open(parsed_logs_folder + "social.pkl", "rb") as f:
        yield pickle.load(f)


@pytest.fixture
def default_params():
    with SimulationParams().as_default() as params:
        yield params


@pytest.fixture
def context(log, social_graph):
    return Context(log, social_graph)

