import os
import sys
import pytest
import pickle

import numpy as np

from .scenarios import *
from .parse_enron import Message

import __main__
__main__.Message = Message


parsed_logs_folder = 'Enron/parsing/'
log_entries_lim = 1000


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


def test_create_global_state(context, default_params):
    with SimulationParams().as_default():
        state = create_global_state(context)
        assert len(state.local_views) > 0
        assert len(state.state_by_user) == len(context.senders)
        assert state.local_views is not state.public_views



@pytest.mark.parametrize('mode', ['key', 'head'])
def test_eval_propagation(context, mode):
    with SimulationParams(mode=mode).as_default():
        state = create_global_state(context)
        updated, stale, not_updated = \
                state.eval_propagation(mode=mode)
        assert updated == 0
        assert stale == 0
        assert not_updated > 0


@pytest.mark.parametrize('params', [
        SimulationParams(key_update_every_nb_sent_emails=None),
        SimulationParams(key_update_every_nb_sent_emails=1),
    ])
def test_autocrypt_stale_propagation(context, params):
    with params.as_default():
        kp, ec = simulate_autocrypt(context)
        nb_stale_keys = np.sum(kp['Stale'])
        if params.key_update_every_nb_sent_emails is None:
            assert nb_stale_keys == 0
            assert EncStatus.stale not in ec.value_counts()
        else:
            assert nb_stale_keys > 0
            assert EncStatus.stale in ec.value_counts()


@pytest.mark.parametrize('params,any_stale_keys', [
        (SimulationParams(chain_update_buffer_size=10, key_update_every_nb_sent_emails=None), False),
        (SimulationParams(chain_update_buffer_size=10, key_update_every_nb_sent_emails=5), True)
    ])
def test_claimchain_no_privacy_propagation(context, params, any_stale_keys):
    with params.as_default():
        kp, hp, es = simulate_claimchain_no_privacy(context)

        nb_stale_keys = np.sum(kp['Stale'])
        assert (nb_stale_keys > 0) == any_stale_keys

        nb_stale_heads = np.sum(hp['Stale'])
        assert nb_stale_heads > 0


@pytest.mark.parametrize('params,any_stale_keys', [
        (SimulationParams(chain_update_buffer_size=10, key_update_every_nb_sent_emails=None), False),
        (SimulationParams(chain_update_buffer_size=10, key_update_every_nb_sent_emails=5), True)
    ])
def test_claimchain_with_privacy_propagation(context, params, any_stale_keys):
    with params.as_default():
        kp, hp, es = simulate_claimchain_with_privacy(context)

        nb_stale_keys = np.sum(kp['Stale'])
        assert (nb_stale_keys > 0) == any_stale_keys

        nb_stale_heads = np.sum(hp['Stale'])
        assert nb_stale_heads > 0
