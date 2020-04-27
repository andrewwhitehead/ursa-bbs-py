import ursa_bbs as bbs


def log(msg: str, *vals):
    print(msg, *vals)
    print()


def test_random_short_keys():
    dpk, sk = bbs.new_short_keys()
    dst = bbs.DomainSeparationTag(b"testgen", None, None, None)
    pk = dpk.to_public_key(5, dst)
    log("Public key:", pk.to_json())
    log("Secret key:", sk, bytes(sk))


def test_seed_short_keys():
    dpk, sk = bbs.new_short_keys(seed=b"seed00001")
    dst = bbs.DomainSeparationTag(b"testgen", None, None, None)
    pk = dpk.to_public_key(5, dst)
    log("Public key:", pk.to_json())


def test_pre_hashed():
    pk, sk = bbs.new_keys(5)
    log("Public key:", pk.to_json())

    messages = [b"message 1", b"message 2", b"message 3", b"message 4", b"message 5"]

    hashed_messages = [bbs.hash_message(m) for m in messages]
    signature = bbs.sign_messages(hashed_messages, sk, pk, pre_hashed=True)
    log("Signature:", signature)

    log(
        "Verify:", bbs.verify_signature(hashed_messages, signature, pk, pre_hashed=True)
    )


def test_signature():
    pk, sk = bbs.new_keys(5)
    log("Public key:", pk.to_json())

    messages = [b"message 1", b"message 2", b"message 3", b"message 4", b"message 5"]

    signature = bbs.sign_messages(messages, sk, pk)
    log("Signature:", signature)

    log("Verify:", bbs.verify_signature(messages, signature, pk))


def test_blind_commitment():
    pk, sk = bbs.new_keys(5)
    log("Public key:", pk.to_json())

    commit_message = b"message_0"

    signature_blinding, commitment = bbs.create_blinding_commitment(commit_message, pk)
    log("Blinding:", signature_blinding)
    log("Commitment:", commitment)

    messages = {1: b"message_1", 2: b"message_2", 3: b"message_3", 4: b"message_4"}

    blind_signature = bbs.sign_messages_blinded_commitment(messages, sk, pk, commitment)
    log("Blind signature:", blind_signature)

    signature = bbs.unblind_signature(blind_signature, signature_blinding)
    log("Signature:", signature)

    all_messages = [commit_message] + [messages[i] for i in range(1, 5)]
    log("Verify:", bbs.verify_signature(all_messages, signature, pk))


def test_blind_context():
    pk, sk = bbs.new_keys(5)
    log("Public key:", pk.to_json())

    signing_nonce = bbs.generate_signing_nonce()
    log("Signing nonce:", signing_nonce)

    link_secret = b"secret"
    context_messages = {0: link_secret}
    signature_blinding, context = bbs.create_blinding_context(
        context_messages, pk, signing_nonce
    )
    log("Blinding:", signature_blinding)
    log("Context:", context)

    messages = {1: b"message_1", 2: b"message_2", 3: b"message_3", 4: b"message_4"}

    blind_signature = bbs.sign_messages_blinded_context(
        messages, sk, pk, context, signing_nonce
    )
    log("Blind signature:", blind_signature)

    signature = bbs.unblind_signature(blind_signature, signature_blinding)
    log("Signature:", signature)

    all_messages = [link_secret] + [messages[i] for i in range(1, 5)]
    log("Verify:", bbs.verify_signature(all_messages, signature, pk))


def test_zkp():
    pk, sk = bbs.new_keys(5)
    log("Public key:", pk.to_json())

    messages = [b"message_1", b"message_2", b"message_3", b"message_4", b"message_5"]

    signature = bbs.sign_messages(messages, sk, pk)
    log("Signature:", signature)

    verifier_nonce = bbs.generate_proof_nonce()
    log("Nonce:", verifier_nonce)

    proof = bbs.create_proof(messages, [1, 3], pk, signature, verifier_nonce)
    log("Proof:", proof)

    verify_messages = [messages[1], messages[3]]
    log("Verify:", bbs.verify_proof(verify_messages, [1, 3], pk, proof, verifier_nonce))


if __name__ == "__main__":
    test_random_short_keys()
    print("---\n")
    test_seed_short_keys()
    print("---\n")
    test_signature()
    print("---\n")
    test_pre_hashed()
    print("---\n")
    test_blind_commitment()
    print("----\n")
    test_blind_context()
    print("----\n")
    test_zkp()
