"""
Low-level operations for encoding and decoding claims and capabilities.
"""

import os

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode
from profiled import profiled

from .zk import compute_claim_proof, verify_claim_proof, ClaimProofContainer
from .crypto import PublicParams, LocalParams
from .utils import ensure_binary


def _compute_claim_key(key, mode='enc'):
    if mode not in ['enc', 'lookup']:
        raise ValueError('Invalid mode')
    pp = PublicParams.get_default()
    size = pp.enc_key_size if mode == 'enc' else pp.lookup_key_size
    mode = ensure_binary(mode)
    key = ensure_binary(key)
    return pp.hash_func(b"clm_%s|%s" % (mode, key)).digest()[:size]


def _compute_capability_key(shared_secret, claim_label, nonce, mode='enc'):
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


def _salt_label(claim_label, nonce):
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    return b"lab_%s.%s" % (nonce, claim_label)


# TODO: Remove. Temporary fix for gdanezis/petlib#16
from petlib.bindings import _FFI
def _fix_bytes(tag):
    return bytes(_FFI.buffer(tag)[:])


@profiled
def get_capability_lookup_key(owner_dh_pk, claim_label, nonce):
    """Compute capability lookup key.

    :param petlib.EcPt owner_dh_pk: Owner's DH public key
    :param bytes claim_label: Corresponding claim label
    :param bytes nonce: Nonce
    """
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    pp = PublicParams.get_default()
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    shared_secret_key = pp.hash_func(shared_secret.export()).digest()
    return _compute_capability_key(
            shared_secret, claim_label, nonce, mode='lookup')


@profiled
def encode_claim(claim_label, claim_content, nonce):
    """Encode claim.

    :param bytes claim_label: Claim label
    :param bytes claim_content: Claim content
    :param bytes nonce: Nonce
    """
    claim_content = ensure_binary(claim_content)

    pp = PublicParams.get_default()
    salted_label = _salt_label(claim_label, nonce)
    claim_proof = compute_claim_proof(salted_label, claim_content)
    lookup_key = _compute_claim_key(claim_proof.vrf_value, mode='lookup')

    claim_key = os.urandom(pp.enc_key_size)
    enc_key = _compute_claim_key(claim_key, mode='enc')

    claim = encode([claim_proof.proof, claim_content])
    encrypted_body, tag = pp.enc_cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, claim)
    tag = _fix_bytes(tag)

    encoded_claim = encode([encrypted_body, claim_proof.commitment, tag])
    return (claim_proof.vrf_value, claim_key, claim_proof.proof_key,
            lookup_key, encoded_claim)


@profiled
def decode_claim(owner_vrf_pk, vrf_value, claim_label, claim_key, proof_key,
                 encoded_claim, nonce):
    """Decode claim.

    :param petlib.EcPt owner_vrf_pk: Owner's VRF public key
    :param bytes vrf_value: Exported VRF value (hash)
    :param bytes claim_label: Claim label
    :param bytes claim_key: Claim encryption key
    :param bytes proof_key: Claim proof key
    :param bytes encoded_claim: Encoded claim
    :param bytes nonce: Nonce
    """
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    salted_label = _salt_label(claim_label, nonce)
    (encrypted_body, com, tag) = decode(encoded_claim)

    enc_key = _compute_claim_key(claim_key, mode='enc')
    raw_body = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, encrypted_body, tag)
    (proof, claim_content) = decode(raw_body)

    claim_proof = ClaimProofContainer(
            vrf_value=vrf_value,
            commitment=com,
            proof_key=proof_key,
            proof=proof)

    if not verify_claim_proof(owner_vrf_pk, claim_proof,
            salted_label, claim_content):
        raise Exception("Proof verification failed.")

    return claim_content


@profiled
def encode_capability(reader_dh_pk, claim_label, vrf_value, claim_key,
                      proof_key, nonce):
    """Encode capability.

    :param petlib.EcPt reader_dh_pk: Reader's VRF public key
    :param bytes claim_label: Corresponding claim label
    :param bytes vrf_value: Exported VRF value (hash)
    :param bytes claim_key: Claim encryption key
    :param bytes proof_key: Claim proof key
    :param bytes nonce: Nonce
    """
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * reader_dh_pk

    cap_lookup_key = _compute_capability_key(
            shared_secret, claim_label, nonce, mode='lookup')
    enc_key = _compute_capability_key(
            shared_secret, claim_label, nonce, mode='enc')

    cap_content = encode([vrf_value, claim_key, proof_key])

    enc_body, tag = cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, cap_content)
    tag = _fix_bytes(tag)

    return cap_lookup_key, encode([enc_body, tag])


@profiled
def decode_capability(owner_dh_pk, claim_label, encoded_cap, nonce):
    """Decode capability.

    :param petlib.EcPt owner_dh_pk: Owder's VRF public key
    :param bytes claim_label: Corresponding claim label
    :param bytes encoded_cap: Encoded capability
    :param bytes nonce: Nonce
    """
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    enc_key = _compute_capability_key(
            shared_secret, claim_label, nonce, mode='enc')
    enc_body, tag = decode(encoded_cap)
    raw_body = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, enc_body, tag)
    vrf_value, claim_key, proof_key = decode(raw_body)
    claim_lookup_key = _compute_claim_key(vrf_value, mode='lookup')
    return claim_lookup_key, vrf_value, claim_key, proof_key

