import os
import tempfile

import pytest

from claimchain.crypto import PublicParams
from claimchain.data_utils import load_data, save_data


@pytest.fixture
def data_source():
    fixture_name = 'friends.yml'
    fixtures_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
            'fixtures')
    handle = open(os.path.join(fixtures_path, fixture_name), 'r')
    yield 'yaml', handle
    handle.close()


def test_load_data(data_source):
    format, source = data_source
    labels, heads, pubkeys = load_data(source, format=format)
    assert len(labels) == len(heads) == len(pubkeys) == 4


@pytest.mark.parametrize("format", ["json", "yaml"])
def test_save_data(format):
    pp = PublicParams.get_default()
    G = pp.ec_group

    labels = ['marios', 'george', 'carmela', 'bogdan']
    heads = [os.urandom(20) for _ in labels]
    pubkeys = [G.order().random() * G.generator() for _ in labels]
    data = labels, heads, pubkeys

    target = tempfile.TemporaryFile('w+')
    save_data(target, data, format=format)
    target.seek(0)

    labels1, heads1, pubkeys1 = load_data(target, format=format)
    assert labels == labels1
    assert heads == heads1
    assert pubkeys == pubkeys1
    target.close()
