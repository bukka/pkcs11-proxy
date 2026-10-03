import os

import pkcs11
import pkcs11.util.ec
from pkcs11 import Attribute, KeyType, Mechanism, KDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization

def test_rsa_generate_keypair(pkcs11_session):
    public_key, private_key = pkcs11_session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="TestRSAKey"
    )
    assert public_key is not None
    assert private_key is not None

def test_rsa_encrypt_decrypt(pkcs11_session):
    public_key, private_key = pkcs11_session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="TestRSAKey"
    )
    message = b"Secret Message"
    encrypted = public_key.encrypt(message, mechanism=Mechanism.RSA_PKCS)
    decrypted = private_key.decrypt(encrypted, mechanism=Mechanism.RSA_PKCS)

    assert message == decrypted

def test_ecdsa_key_load_and_sign_verify(pkcs11_session):
    # Load the private key created during setup by label
    private_key = pkcs11_session.get_key(
        label="ProxyTestExistingECKey",
        key_type=KeyType.EC,
        object_class=pkcs11.ObjectClass.PRIVATE_KEY
    )
    assert private_key is not None, "Failed to load private key"

    # Load the corresponding public key by label
    public_key = pkcs11_session.get_key(
        label="ProxyTestExistingECKey",
        key_type=KeyType.EC,
        object_class=pkcs11.ObjectClass.PUBLIC_KEY
    )
    assert public_key is not None, "Failed to load public key"

    # Message to sign
    message = b"Message to be signed using ECDSA"

    # Sign the message using the private key
    signature = private_key.sign(
        message,
        mechanism=Mechanism.ECDSA
    )
    assert signature is not None, "Signature generation failed"

    # Verify the signature using the public key
    is_valid = public_key.verify(
        message,
        signature,
        mechanism=Mechanism.ECDSA
    )
    assert is_valid, "Signature verification failed"

def test_ecdh_derive_key(pkcs11_session):
    # Generate Alice's EC key pair in PKCS#11
    ecparams = pkcs11_session.create_domain_parameters(
        pkcs11.KeyType.EC, {
            pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp256r1'),
        }, local=True)
    alice_public_key, alice_private_key = ecparams.generate_keypair(store=True, label="TestECKey")
    alices_value_raw = alice_public_key[Attribute.EC_POINT]
    # Strip first two extra bytes
    alices_value = alices_value_raw[2:]

    # Generate Bob's EC key pair in `cryptography`
    bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_public_key = bob_private_key.public_key()

    # Export Bob's public key to DER format and decode the EC point to match PKCS#11 format
    bobs_value = bob_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Get Alice's secret
    session_key_alice = alice_private_key.derive_key(
        KeyType.AES, 256,
        mechanism_param=(KDF.NULL, None, bobs_value)
    )

    # Bob derives the shared secret using Alice's public value in `cryptography`
    shared_secret_bob = bob_private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), alices_value))

    # Use AES-CBC for encryption with Alice's session key
    iv = os.urandom(16)
    plaintext = b"Test message for ECDH key agreement verification"

    # Alist encrypts the key - AES_CBC_PAD is default
    ciphertext = session_key_alice.encrypt(plaintext, mechanism_param=iv)

    # Bob tries to decrypt the message using his derived key
    cipher = Cipher(algorithms.AES(shared_secret_bob), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_text_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted text
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_text_padded) + unpadder.finalize()

    # Verify that the decrypted text matches the original plaintext
    assert decrypted_text == plaintext

def test_mechanism_list_contains_ecdh(pkcs11_session):
    mechanisms = pkcs11_session.token.slot.get_mechanisms()
    assert Mechanism.ECDH1_DERIVE in mechanisms, "ECDH1_DERIVE mechanism is not supported by the token"
