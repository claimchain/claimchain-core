from binascii import hexlify, unhexlify

from petlib.ec import EcPt, EcGroup
from . import global_ec_group as G


def load_data(source, format='json'):
    """
    :param source: File reader object
    :param format: One of ['json', 'yaml']
    """
    if format == "yaml":
        import yaml
        raw_data = yaml.load(source)
    elif format == "json":
        import json
        raw_data = json.load(source)
    else:
        raise ValueError("Unknown format %s" % format)

    labels, heads, pubkeys = [], [], []
    for item in raw_data:
        labels.append(item['identity'])
        heads.append(unhexlify(item['latest_head']))
        pubkeys.append(EcPt.from_binary(unhexlify(item['dh_pk']), group=G))

    return labels, heads, pubkeys


def save_data(target, data, format='json'):
    out = []
    for label, head, pub in zip(*data):
        out.append(dict(
            identity=label,
            latest_head=hexlify(head).decode('ascii'),
            dh_pk=hexlify(pub.export()).decode('ascii')))

    if format == "yaml":
        import yaml
        yaml.dump(out, target)
    elif format == "json":
        import json
        json.dump(out, target)
    else:
        raise ValueError("Unknown format %s" % format)
