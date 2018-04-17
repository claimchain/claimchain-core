from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from .crypto import compute_vrf, verify_vrf, VrfContainer
from .crypto import PublicParams, LocalParams
from .utils import ensure_binary, profiled


def _compute_claim_key(vrf_value, mode='enc'):
    if mode not in ['enc', 'lookup']:
        raise ValueError('Invalid mode')
    pp = PublicParams.get_default()
    size = pp.enc_key_size if mode == 'enc' else pp.lookup_key_size
    mode = ensure_binary(mode)
    return pp.hash_func(b"clm_%s|%s" % (mode, vrf_value)).digest()[:size]


def _compute_capability_key(nonce, shared_secret, claim_label, mode='enc'):
    if mode not in ['enc', 'lookup']:
        ValueError('Invalid mode')
    pp = PublicParams.get_default()
    size = pp.enc_key_size if mode == 'enc' else pp.lookup_key_size
    shared_secret_hash = pp.hash_func(shared_secret.export()).digest()
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    mode = ensure_binary(mode)
    return pp.hash_func(b"cap_%s|%s|%s|%s" %
            (mode, nonce, shared_secret_hash, claim_label)) \
            .digest()[:size]


def _salt_label(nonce, claim_label):
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    return b"lab_%s.%s" % (nonce, claim_label)


# TODO: Remove. Temporary fix for gdanezis/petlib#16
from petlib.bindings import _FFI
def _fix_bytes(tag):
    return bytes(_FFI.buffer(tag)[:])


@profiled
def get_capability_lookup_key(owner_dh_pk, nonce, claim_label):
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    pp = PublicParams.get_default()
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    shared_secret_key = pp.hash_func(shared_secret.export()).digest()
    return _compute_capability_key(
            nonce, shared_secret, claim_label, mode='lookup')


@profiled
def encode_claim(nonce, claim_label, claim_content):
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    claim_content = ensure_binary(claim_content)

    pp = PublicParams.get_default()
    salted_label = _salt_label(nonce, claim_label)
    vrf = compute_vrf(salted_label)
    lookup_key = _compute_claim_key(vrf.value, mode='lookup')
    enc_key = _compute_claim_key(vrf.value, mode='enc')

    claim = encode([vrf.proof, claim_content])
    enc_body, tag = pp.enc_cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, claim)
    tag = _fix_bytes(tag)

    enc_claim = encode([enc_body, tag])
    return (vrf.value, lookup_key, enc_claim)


@profiled
def decode_claim(owner_vrf_pk, nonce, claim_label, vrf_value, encrypted_claim):
    claim_label = ensure_binary(claim_label)

    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    salted_label = _salt_label(nonce, claim_label)
    (encrypted_body, tag) = decode(encrypted_claim)

    lookup_key = _compute_claim_key(vrf_value, mode='lookup')
    enc_key = _compute_claim_key(vrf_value, mode='enc')
    raw_body = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, encrypted_body, tag)
    (proof, claim_content) = decode(raw_body)

    vrf = VrfContainer(value=vrf_value, proof=proof)
    if not verify_vrf(owner_vrf_pk, vrf, salted_label):
        raise Exception("Wrong VRF Value")

    return claim_content


@profiled
def encode_capability(reader_dh_pk, nonce, claim_label, vrf_value):
    claim_label = ensure_binary(claim_label)
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
    tag = _fix_bytes(tag)

    return lookup_key, encode([enc_body, tag])


@profiled
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
