import ursa_bbs as bbs


def log(msg: str, *vals):
    print(msg, *vals)
    print()


def test_random_keypair():
    dpk, sk = bbs.generate_bls_keypair()
    pk = dpk.to_public_key(5)
    log("Public key:", pk, bytes(pk).hex())
    log("Secret key:", sk, bytes(sk).hex())


def test_seed_keypair():
    dpk, sk = bbs.generate_bls_keypair(seed=b"seed00001")
    pk = dpk.to_public_key(5)
    log("Public key:", pk, bytes(pk).hex())


def test_pre_hashed():
    dpk, sk = bbs.generate_bls_keypair()
    pk = dpk.to_public_key(5)
    log("Public key:", bytes(pk).hex())

    messages = [b"message 1", b"message 2", b"message 3", b"message 4", b"message 5"]

    hashed_messages = [bbs.hash_message(m) for m in messages]
    signature = bbs.sign_messages(hashed_messages, sk, pk, pre_hashed=True)
    log("Signature:", bytes(signature).hex())

    log(
        "Verify:", bbs.verify_signature(hashed_messages, signature, pk, pre_hashed=True)
    )


def test_signature():
    dpk, sk = bbs.generate_bls_keypair()
    pk = dpk.to_public_key(5)
    log("Public key:", bytes(pk).hex())

    messages = [b"message 1", b"message 2", b"message 3", b"message 4", b"message 5"]

    signature = bbs.sign_messages(messages, sk, pk)
    log("Signature:", bytes(signature).hex())

    log("Verify:", bbs.verify_signature(messages, signature, pk))


def test_blind_context():
    dpk, sk = bbs.generate_bls_keypair()
    pk = dpk.to_public_key(5)
    log("Public key:", bytes(pk).hex())

    signing_nonce = bbs.generate_signing_nonce()
    # log("Signing nonce:", signing_nonce.hex())

    link_secret = b"secret"
    context_messages = {0: link_secret}
    signature_blinding, context = bbs.create_blinding_context(
        context_messages, pk, signing_nonce
    )
    log("Blinding:", signature_blinding.hex())
    log("Context:", context.hex())

    messages = {1: b"message_1", 2: b"message_2", 3: b"message_3", 4: b"message_4"}

    blind_signature = bbs.sign_messages_blinded_context(
        messages, sk, pk, context, signing_nonce
    )
    log("Blind signature:", bytes(blind_signature).hex())

    signature = bbs.unblind_signature(blind_signature, signature_blinding)
    log("Unblinded signature:", bytes(signature).hex())

    all_messages = [link_secret] + [messages[i] for i in range(1, 5)]
    log("Verify:", bbs.verify_signature(all_messages, signature, pk))


def test_zkp():
    dpk, sk = bbs.generate_bls_keypair()
    pk = dpk.to_public_key(5)
    log("Public key:", bytes(pk).hex())

    messages = [b"message_1", b"message_2", b"message_3", b"message_4", b"message_5"]

    signature = bbs.sign_messages(messages, sk, pk)
    log("Signature:", bytes(signature).hex())

    verifier_nonce = bbs.generate_proof_nonce()
    # log("Verifier nonce:", verifier_nonce.hex())

    proof = bbs.create_proof(messages, [1, 3], pk, signature, verifier_nonce)
    log("Proof:", bytes(proof).hex())

    verify_messages = [messages[1], messages[3]]
    log("Verify:", bbs.verify_proof(verify_messages, [1, 3], pk, proof, verifier_nonce))


if __name__ == "__main__":
    test_random_keypair()
    print("---\n")
    test_seed_keypair()
    print("---\n")
    test_signature()
    print("---\n")
    test_pre_hashed()
    print("----\n")
    test_blind_context()
    print("----\n")
    test_zkp()
