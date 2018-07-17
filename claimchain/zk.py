"""
Claimchain zero-knowledge proofs.
"""
import os
import attr

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.pack import encode, decode
from profiled import profiled

from hashlib import sha512, sha256

from .crypto.params import PublicParams, LocalParams
from .utils import ensure_binary


@attr.s
class ClaimProofContainer(object):
    vrf_value = attr.ib()
    commitment = attr.ib()
    proof_key = attr.ib()
    proof = attr.ib()


def compute_claim_proof(nonce, claim_label, claim_body):
    """Compute a claim proof.

    Produces a VRF proof of the lookup key and the ZK proof of the claim content
    commitment correctness.
    """
    pp = PublicParams.get_default()
    local_params = LocalParams.get_default()
    nonce = ensure_binary(nonce)
    claim_label = ensure_binary(claim_label)
    claim_body = ensure_binary(claim_body)

    G = pp.ec_group
    g = G.generator()
    a = G.hash_to_point('a')
    b = G.hash_to_point('b')

    k = local_params.vrf.sk
    pk = local_params.vrf.pk
    v = G.hash_to_point(nonce + claim_label)

    h = k * v

    alpha = G.order().random()
    bind = Bn.from_binary(sha256(claim_body).digest()) * a
    com = alpha * b + bind

    r_sk = G.order().random()
    r_alpha = G.order().random()
    proof_key = os.urandom(pp.nonce_size)

    R_pk = r_sk * g
    R_h = r_sk * h
    R_com = r_alpha * b

    packed_challenge = [
        g, v, a, b,
        pk, h, com, bind,
        R_pk, R_h, R_com,
        proof_key
    ]

    c = Bn.from_binary(sha512(encode(packed_challenge)).digest())
    s_sk = (r_sk - c * k) % G.order()
    s_alpha = (r_alpha - c * alpha) % G.order()
    return ClaimProofContainer(
            vrf_value=h,
            commitment=com,
            proof_key=proof_key,
            proof=(c, s_sk, s_alpha))


def verify_claim_proof(owner_vrf_pk, nonce, claim_proof, claim_label, claim_body):
    """Verify the claim proof.
    """
    pp = PublicParams.get_default()
    local_params = LocalParams.get_default()
    claim_label = ensure_binary(claim_label)
    claim_body = ensure_binary(claim_body)

    G = pp.ec_group
    g = G.generator()
    a = G.hash_to_point('a')
    b = G.hash_to_point('b')

    c, s_sk, s_alpha = claim_proof.proof
    v = G.hash_to_point(nonce + claim_label)
    R_pk = s_sk * g + c * owner_vrf_pk
    R_h = s_sk * v + c * claim_proof.vrf_value

    bind = Bn.from_binary(sha256(claim_body).digest()) * a
    R_com = s_alpha * b + c * (claim_proof.commitment - bind)

    packed_challenge = [
        g, v, a,
        owner_vrf_pk, claim_proof.vrf_value, claim_proof.commitment, bind,
        R_pk, R_h, R_com,
        claim_proof.proof_key
    ]
    c_1 = Bn.from_binary(sha512(encode(packed_challenge)).digest())
    return c_1 == c

