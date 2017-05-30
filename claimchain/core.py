# The claimchain core package

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode

from hashlib import sha256

from claimchain.crypto import do_vrf_compute, do_vrf_verify, VrfContainer
from claimchain.crypto import PublicParams, LocalParams


def encode_claim(nonce, claim_label, claim_body):
    pp = PublicParams.get_default()
    nkey = encode([nonce, claim_label])
    vrf = do_vrf_compute(nkey)
    lookup_key = sha256(b"clm_lookup|" + vrf.value).digest()[:pp.short_hash_size]
    enc_key = sha256(b"clm_enc_key|" + vrf.value).digest()[:pp.enc_key_size]

    claim = encode([vrf.proof, claim_body])
    encbody, tag = pp.enc_cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, claim)

    all_body = encode([encbody, tag])
    return (vrf.value, lookup_key, all_body)


def decode_claim(owner_vrf_pk, nonce, claim_label, vrf_value, encrypted_claim):
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    nkey = encode((nonce, claim_label))
    (encrypted_body, tag) = decode(encrypted_claim)

    lookup_key = sha256(b"clm_lookup|" + vrf_value).digest()[:pp.short_hash_size]
    enc_key = sha256(b"clm_enc_key|" + vrf_value).digest()[:pp.enc_key_size]

    raw_body = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, encrypted_body, tag)
    (proof, claim_body) = decode(raw_body)

    vrf = VrfContainer(value=vrf_value, proof=proof)
    if not do_vrf_verify(owner_vrf_pk, vrf, nkey):
        raise Exception("Wrong VRF Value")

    return claim_body


def get_capability_lookup_key(owner_dh_pk, nonce, claim_label):
    pp = PublicParams.get_default()
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    shared_secret_key = sha256(shared_secret.export()).digest()

    lookup_key = sha256(b"cap_lookup|%s|%s|%s" % (
        shared_secret_key, nonce, claim_label)).digest()[:pp.short_hash_size]
    return lookup_key


def encode_capability(reader_dh_pk, nonce, claim_label, vrf_value):
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    params = LocalParams.get_default()

    shared_secret = params.dh.sk * reader_dh_pk
    shared_secret_key = sha256(shared_secret.export()).digest()
    lookup_key = sha256(b"cap_lookup|%s|%s|%s" %
            (shared_secret_key, nonce, claim_label)).digest()[:pp.short_hash_size]
    enc_key = sha256(b"cap_enc_key|%s|%s|%s" %
            (shared_secret_key, nonce, claim_label)).digest()[:pp.enc_key_size]

    encbody, tag = cipher.quick_gcm_enc(
            enc_key, b"\x00"*pp.enc_key_size, vrf_value)
    return lookup_key, encode([encbody, tag])


def decode_capability(owner_dh_pk, nonce, claim_label, encrypted_capability):
    pp = PublicParams.get_default()
    cipher = pp.enc_cipher
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    shared_secret_key = sha256(shared_secret.export()).digest()

    enc_key = sha256(b"cap_enc_key|%s|%s|%s" %
            (shared_secret_key, nonce, claim_label)).digest()[:pp.enc_key_size]

    encbody, tag = decode(encrypted_capability)
    body = cipher.quick_gcm_dec(
            enc_key, b"\x00"*pp.enc_key_size, encbody, tag)
    return body
