import six

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from claimchain.crypto import do_vrf_compute, do_vrf_verify, VrfContainer
from claimchain.crypto import PublicParams, LocalParams


def _ensure_binary(s):
    """
    >>> _ensure_binary(b"test")
    b"test"
    >>> _ensure_binary(u"test")
    b"test"
    """
    if not isinstance(s, six.binary_type):
        s = s.encode('utf-8')
    return s


def _compute_claim_key(vrf_value, mode='enc'):
    assert mode in ['enc', 'lookup'], ValueError('Invalid mode')
    pp = PublicParams.get_default()
    size = pp.enc_key_size if mode == 'enc' else pp.lookup_key_size
    mode = _ensure_binary(mode)
    return pp.hash_func(b"clm_%s|%s" % (mode, vrf_value)).digest()[:size]


def _compute_capability_key(nonce, shared_secret, claim_label, mode='enc'):
    assert mode in ['enc', 'lookup'], ValueError('Invalid mode')
    pp = PublicParams.get_default()
    size = pp.enc_key_size if mode == 'enc' else pp.lookup_key_size
    shared_secret_hash = pp.hash_func(shared_secret.export()).digest()
    mode = _ensure_binary(mode)
    return pp.hash_func(b"cap_%s|%s|%s|%s" %
            (mode, nonce, shared_secret_hash, claim_label)) \
            .digest()[:size]


def get_capability_lookup_key(owner_dh_pk, nonce, claim_label):
    claim_label = _ensure_binary(claim_label)
    pp = PublicParams.get_default()
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    shared_secret_key = pp.hash_func(shared_secret.export()).digest()
    return _compute_capability_key(
            nonce, shared_secret, claim_label, mode='lookup')


def encode_claim(nonce, claim_label, claim_content):
    claim_label = _ensure_binary(claim_label)
    claim_content = _ensure_binary(claim_content)

    pp = PublicParams.get_default()
    salted_label = encode([nonce, claim_label])
    vrf = do_vrf_compute(salted_label)
    lookup_key = _compute_claim_key(vrf.value, mode='lookup')
    enc_key = _compute_claim_key(vrf.value, mode='enc')

    claim = encode([vrf.proof, claim_content])
    enc_body, tag = pp.enc_cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, claim)

    enc_claim = encode([enc_body, tag])
    return (vrf.value, lookup_key, enc_claim)


def decode_claim(owner_vrf_pk, nonce, claim_label, vrf_value, encrypted_claim):
    claim_label = _ensure_binary(claim_label)

    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    salted_label = encode([nonce, claim_label])
    (encrypted_body, tag) = decode(encrypted_claim)

    lookup_key = _compute_claim_key(vrf_value, mode='lookup')
    enc_key = _compute_claim_key(vrf_value, mode='enc')
    raw_body = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, encrypted_body, tag)
    (proof, claim_content) = decode(raw_body)

    vrf = VrfContainer(value=vrf_value, proof=proof)
    if not do_vrf_verify(owner_vrf_pk, vrf, salted_label):
        raise Exception("Wrong VRF Value")

    return claim_content


def encode_capability(reader_dh_pk, nonce, claim_label, vrf_value):
    claim_label = _ensure_binary(claim_label)
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * reader_dh_pk

    lookup_key = _compute_capability_key(
            nonce, shared_secret, claim_label, mode='lookup')
    enc_key = _compute_capability_key(
            nonce, shared_secret, claim_label, mode='enc')

    enc_body, tag = cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, vrf_value)
    return lookup_key, encode([enc_body, tag])


def decode_capability(owner_dh_pk, nonce, claim_label, encrypted_capability):
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    enc_key = _compute_capability_key(
            nonce, shared_secret, claim_label, mode='enc')
    enc_body, tag = decode(encrypted_capability)
    vrf_value = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, enc_body, tag)
    claim_lookup_key = _compute_claim_key(vrf_value, mode='lookup')
    return vrf_value, claim_lookup_key
