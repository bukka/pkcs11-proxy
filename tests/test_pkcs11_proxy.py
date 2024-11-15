import pytest
import pkcs11
import pkcs11.util.ec
from pkcs11 import Attribute, KeyType, Mechanism, KDF
import subprocess
import os
import platform
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def get_pkcs11_library_path():
    pkcs11_lib = os.getenv("PKCS11_TEST_LIB")
    if pkcs11_lib and os.path.exists(pkcs11_lib):
        return pkcs11_lib
    default_paths = [
        "/usr/local/lib/softhsm/libsofthsm2.so", 
        "/usr/lib/softhsm/libsofthsm2.so",
    ]
    for path in default_paths:
        if os.path.exists(path):
            return path
    pytest.fail("PKCS11 library not found. Set PKCS11_TEST_LIB or install SoftHSM.")

@pytest.fixture(scope="session", autouse=True)
def setup_pkcs11_proxy_lib():
    # Check if PKCS11_TEST_NO_PROXY is set
    if os.getenv("PKCS11_TEST_NO_PROXY"):
        # Use SoftHSM directly without starting pkcs11-daemon
        pkcs11_lib = get_pkcs11_library_path()
        yield pkcs11_lib
        return

    build_dir = os.path.join(os.path.dirname(__file__), "../build")
    pkcs11_daemon_path = os.path.join(build_dir, "pkcs11-daemon")
    
    # OSX uses dylib by default
    lib_extension = "dylib" if platform.system() == "Darwin" else "so"
    proxy_lib_path = os.path.join(build_dir, f"libpkcs11-proxy.{lib_extension}")
    
    if not os.path.exists(pkcs11_daemon_path):
        pytest.fail(f"pkcs11-daemon not found in {build_dir}. Ensure it is built correctly.")
    if not os.path.exists(proxy_lib_path):
        pytest.fail(f"Proxy library {proxy_lib_path} not found in {build_dir}.")

    pkcs11_lib = get_pkcs11_library_path()

    daemon_process = subprocess.Popen([
        pkcs11_daemon_path, pkcs11_lib
    ], env={**os.environ, "PKCS11_DAEMON_SOCKET": "tcp://127.0.0.1:2345"})
    
    time.sleep(0.5)
    yield proxy_lib_path
    daemon_process.terminate()

@pytest.fixture
def pkcs11_session(setup_pkcs11_proxy_lib):
    # Set PKCS11_PROXY_SOCKET for the proxy library to connect to the daemon
    os.environ["PKCS11_PROXY_SOCKET"] = "tcp://127.0.0.1:2345"
    lib = pkcs11.lib(setup_pkcs11_proxy_lib)
    token = lib.get_token(token_label="ProxyTestToken")
    
    with token.open(user_pin="1234", rw=True) as session:
        yield session

def test_generate_rsa_keypair(pkcs11_session):
    public_key, private_key = pkcs11_session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="TestRSAKey"
    )
    assert public_key is not None
    assert private_key is not None

def test_encrypt_decrypt(pkcs11_session):
    public_key, private_key = pkcs11_session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="TestRSAKey"
    )
    message = b"Secret Message"
    encrypted = public_key.encrypt(message, mechanism=Mechanism.RSA_PKCS)
    decrypted = private_key.decrypt(encrypted, mechanism=Mechanism.RSA_PKCS)

def test_derive_key_ecdh(pkcs11_session):
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
        KeyType.AES, 128,
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
    decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

    # Verify that the decrypted text matches the original plaintext
    assert decrypted_text == plaintext
