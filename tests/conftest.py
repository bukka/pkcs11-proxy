import gc
import os

import pytest
import pkcs11

import pkcs11_raw
import proxytest
from proxytest import DaemonRegistry

_registry = None
_current_socket = None


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "daemon_config(**options): run against a pkcs11-daemon using these configuration options",
    )


def pytest_sessionstart(session):
    os.environ["SOFTHSM2_CONF"] = os.path.join(proxytest.TESTS_DIR, "softhsm2.conf")
    if proxytest.softhsm_library_path() is None:
        pytest.exit("PKCS11 library not found. Set PKCS11_TEST_LIB or install SoftHSM.", returncode=1)
    if not proxytest.use_proxy():
        return
    for path in (proxytest.daemon_path(), proxytest.proxy_library_path()):
        if not os.path.exists(path):
            pytest.exit(f"{path} not found. Ensure the project is built in {proxytest.BUILD_DIR}.", returncode=1)
    if proxytest.use_tls():
        with open(proxytest.PSK_FILE, "w") as f:
            f.write(proxytest.PSK_CONTENT)
        os.environ["PKCS11_PROXY_TLS_PSK_FILE"] = proxytest.PSK_FILE


def pytest_sessionfinish(session, exitstatus):
    # The client library must be finalized before its daemon stops
    close_library()
    if _registry is not None:
        _registry.stop_all()


def close_library():
    global _current_socket
    pkcs11._lib = None
    pkcs11._so = None
    gc.collect()
    _current_socket = None


def open_library(socket):
    # python-pkcs11 keeps a single library instance. Switching to another
    # daemon finalizes it and initializes it again, which makes the proxy
    # library read PKCS11_PROXY_SOCKET again. A test therefore must not use
    # libraries of two daemons at once.
    global _current_socket
    if socket is None:
        return pkcs11.lib(proxytest.softhsm_library_path())
    os.environ["PKCS11_PROXY_SOCKET"] = socket
    lib = pkcs11.lib(proxytest.proxy_library_path())
    if _current_socket is not None and _current_socket != socket:
        lib.reinitialize()
    _current_socket = socket
    return lib


@pytest.fixture(scope="session")
def daemon_registry(tmp_path_factory):
    global _registry
    _registry = DaemonRegistry(str(tmp_path_factory.mktemp("pkcs11-daemon")))
    return _registry


@pytest.fixture
def daemon_options(request):
    marker = request.node.get_closest_marker("daemon_config")
    return dict(marker.kwargs) if marker else {}


@pytest.fixture
def daemon(daemon_registry, daemon_options):
    if not proxytest.use_proxy():
        if daemon_options:
            pytest.skip("requires pkcs11-daemon")
        return None
    return daemon_registry.get(daemon_options)


@pytest.fixture
def pkcs11_lib(daemon):
    return open_library(daemon.socket if daemon else None)


@pytest.fixture
def pkcs11_token(pkcs11_lib):
    return pkcs11_lib.get_token(token_label=proxytest.TOKEN_LABEL)


@pytest.fixture
def pkcs11_session(pkcs11_token):
    with pkcs11_token.open(user_pin=proxytest.USER_PIN, rw=True) as session:
        yield session


@pytest.fixture
def raw_module(pkcs11_lib, daemon):
    if daemon is None:
        pytest.skip("requires the proxy library")
    return pkcs11_raw.RawModule(proxytest.proxy_library_path())
