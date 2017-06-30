import pytest

from .scenarios import *


def test_public_claimchain(context):
    enc_status_data, _, _, _ = simulate_public_claimchain(context)
    print(enc_status_data.value_counts())

