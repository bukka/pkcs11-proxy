import pytest
import pkcs11
from pkcs11 import KeyType, Mechanism
import subprocess
import os
import platform
import time

def get_pkcs11_library_path():
    pkcs11_lib = os.getenv("PKCS11_LIB")
    if pkcs11_lib and os.path.exists(pkcs11_lib):
        return pkcs11_lib
    default_paths = [
        "/usr/local/lib/softhsm/libsofthsm2.so", 
        "/usr/lib/softhsm/libsofthsm2.so",
    ]
    for path in default_paths:
        if os.path.exists(path):
            return path
    pytest.fail("PKCS11 library not found. Set PKCS11_LIB or install SoftHSM.")

@pytest.fixture(scope="session", autouse=True)
def setup_pkcs11_proxy_lib():
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
