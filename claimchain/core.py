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
    lookup_key = sha256(b"LKey||" + vrf.value).digest()[:8]
    encryption_key = sha256(b"EKey||" + vrf.value).digest()[:16]

    claim = encode([vrf.proof, claim_body])
    encbody, tag = pp.enc_cipher.quick_gcm_enc(
            encryption_key, b"\x00"*16, claim)

    all_body = encode([encbody, tag])
    return (vrf.value, lookup_key, all_body)


def decode_claim(owner_vrf_pk, nonce, claim_label, vrf_value, encrypted_claim):
    pp = PublicParams.get_default()
    aes = pp.enc_cipher
    nkey = encode((nonce, claim_label))
    (encrypted_body, tag) = decode(encrypted_claim)

    lookup_key = sha256(b"LKey||" + vrf_value).digest()[:8]
    encryption_key = sha256(b"EKey||" + vrf_value).digest()[:16]

    raw_body = aes.quick_gcm_dec(encryption_key, b"\x00"*16, encrypted_body, tag)
    (proof, claim_body) = decode(raw_body)

    vrf = VrfContainer(value=vrf_value, proof=proof)
    if not do_vrf_verify(owner_vrf_pk, vrf, nkey):
        raise Exception("Wrong VRF Value")

    return claim_body


def get_capability_lookup_key(owner_dh_pk, nonce, claim_label):
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    encryption_key = sha256(shared_secret.export()).digest()[:16]

    lookup_key = sha256(b"lookup|%s|%s|%s" % (
            encryption_key, nonce, claim_label)).digest()
    return lookup_key


def encode_capability(reader_dh_pk, nonce, claim_label, vrf_value):
    pp = PublicParams.get_default()
    aes = pp.enc_cipher
    params = LocalParams.get_default()

    shared_secret = params.dh.sk * reader_dh_pk
    shared_secret_key = sha256(shared_secret.export()).digest()[:16]
    # TODO: Why this is not truncated?
    lookup_key = sha256(b"lookup|%s|%s|%s" %
            (shared_secret_key, nonce, claim_label)).digest()
    encryption_key = sha256(b"key|%s|%s|%s" %
            (shared_secret_key, nonce, claim_label)).digest()[:16]

    encbody, tag = aes.quick_gcm_enc(encryption_key, b"\x00"*16, vrf_value)
    return lookup_key, encode([encbody, tag])


def decode_capability(owner_dh_pk, nonce, claim_label, encrypted_capability):
    pp = PublicParams.get_default()
    aes = pp.enc_cipher
    params = LocalParams.get_default()
    shared_secret = params.dh.sk * owner_dh_pk
    shared_secret_key = sha256(shared_secret.export()).digest()[:16]

    secret_key = sha256(b"key|%s|%s|%s" %
            (shared_secret_key, nonce, claim_label)).digest()[:16]

    encbody, tag = decode(encrypted_capability)
    body = aes.quick_gcm_dec(secret_key, b"\x00"*16, encbody, tag)
    return body
