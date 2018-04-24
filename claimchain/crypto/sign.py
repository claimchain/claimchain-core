from petlib.ecdsa import do_ecdsa_setup, do_ecdsa_sign, do_ecdsa_verify

from . import PublicParams, LocalParams


def sign(message):
    """Sign a message.

    :param bytes message: Message
    :return: Tuple of bignums (``petlib.bn.Bn``)
    """
    pp = PublicParams.get_default()
    params = LocalParams.get_default()
    G = pp.ec_group
    digest = pp.hash_func(message).digest()
    kinv_rp = do_ecdsa_setup(G, params.sig.sk)
    sig = do_ecdsa_sign(G, params.sig.sk, digest, kinv_rp=kinv_rp)
    return sig


def verify_signature(sig_pk, sig, message):
    """Verify a signature.

    :param petlib.EcPt sig_pk: Signature verification key
    :param sig: Signature
    :type sig: tuple of bignums (``petlib.bn.Bn``)
    :param bytes message: Message
    """
    pp = PublicParams.get_default()
    G = pp.ec_group
    digest = pp.hash_func(message).digest()
    return do_ecdsa_verify(G, sig_pk, sig, digest)
