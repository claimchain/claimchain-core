import pytest

from .scenarios import *


def test_public_claimchain(context):
    _ = simulate_public_claimchain(context)

