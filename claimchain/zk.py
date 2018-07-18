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
from .crypto.utils import hash_to_bn
from .utils import ensure_binary


@attr.s
class ClaimProofContainer(object):
    vrf_value = attr.ib()
    commitment = attr.ib()
    proof = attr.ib()


def compute_claim_proof(salted_label, claim_content, proof_key):
    """Compute a claim proof.

    Produces a VRF proof of the lookup key and the signature ZK proof
    of the claim content commitment correctness.

    :param bytes salted_label: Claim label concatenated with a nonce
    :param bytes claim_content: Claim body
    :param bytes proof_key: Proof key
    """

    pp = PublicParams.get_default()
    local_params = LocalParams.get_default()
    salted_label = ensure_binary(salted_label)
    claim_content = ensure_binary(claim_content)
    proof_key = ensure_binary(proof_key)

    G = pp.ec_group
    g = G.generator()
    a = G.hash_to_point(b'a')
    b = G.hash_to_point(b'b')
    z = G.hash_to_point(salted_label)

    sk = local_params.vrf.sk
    pk = local_params.vrf.pk

    h = sk * z

    alpha = hash_to_bn(
            local_params.prf.sk + salted_label)
    bind = hash_to_bn(claim_content) * a
    com = alpha * b + bind

    r_sk = G.order().random()
    r_alpha = G.order().random()

    R_pk = r_sk * g
    R_h = r_sk * z
    R_com = r_alpha * b

    packed_challenge = [
        g, z, a, b,
        pk, h, com, bind,
        R_pk, R_h, R_com,
        proof_key
    ]

    c = hash_to_bn(encode(packed_challenge))
    s_sk = r_sk.mod_sub(c * sk, G.order())
    s_alpha = r_alpha.mod_sub(c * alpha, G.order())
    return ClaimProofContainer(
            vrf_value=h.export(),
            commitment=com.export(),
            proof=encode([c, s_sk, s_alpha]))


def verify_claim_proof(owner_vrf_pk, claim_proof, salted_label,
                       claim_content, proof_key):
    """Verify the claim proof.

    :param owner_vrf_pk: Owner's VRF pk
    :param ClaimProofContainer claim_proof: Claim proof
    :param bytes salted_label: Claim label concatenated with a nonce
    :param bytes claim_content: Claim body
    :param bytes proof_key: Proof key
    """

    pp = PublicParams.get_default()
    local_params = LocalParams.get_default()
    salted_label = ensure_binary(salted_label)
    claim_content = ensure_binary(claim_content)
    proof_key = ensure_binary(proof_key)

    G = pp.ec_group
    g = G.generator()
    a = G.hash_to_point(b'a')
    b = G.hash_to_point(b'b')
    z = G.hash_to_point(salted_label)

    vrf_value = EcPt.from_binary(claim_proof.vrf_value, G)
    com = EcPt.from_binary(claim_proof.commitment, G)
    proof = decode(claim_proof.proof)

    c, s_sk, s_alpha = proof
    R_pk = s_sk * g + c * owner_vrf_pk
    R_h = s_sk * z + c * vrf_value

    bind = hash_to_bn(claim_content) * a
    R_com = s_alpha * b + c * (com - bind)

    packed_challenge = [
        g, z, a, b,
        owner_vrf_pk, vrf_value, com, bind,
        R_pk, R_h, R_com,
        proof_key
    ]
    c_prime = hash_to_bn(encode(packed_challenge))
    return c_prime == c

