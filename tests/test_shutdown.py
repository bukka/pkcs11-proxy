import os
import signal
import socket
import subprocess
import sys

import pytest

import proxytest
from proxytest import ProxyDaemon

SHUTDOWN_PORT = 2398


@pytest.fixture
def own_daemon():
    if not proxytest.use_proxy():
        pytest.skip("requires pkcs11-daemon")
    daemon = ProxyDaemon(SHUTDOWN_PORT)
    daemon.start()
    yield daemon
    daemon.stop()


def assert_clean_exit_on_sigterm(daemon):
    daemon.process.send_signal(signal.SIGTERM)
    assert daemon.process.wait(timeout=5) == 0


def test_sigterm_with_connected_client(own_daemon):
    env = {
        **os.environ,
        "PKCS11_PROXY_SOCKET": own_daemon.socket,
        "PKCS11_TEST_PROXY_LIB": proxytest.proxy_library_path(),
        "PKCS11_TEST_TOKEN_LABEL": proxytest.TOKEN_LABEL,
        "PKCS11_TEST_USER_PIN": proxytest.USER_PIN,
    }
    script = os.path.join(proxytest.TESTS_DIR, "hold_session.py")
    client = subprocess.Popen([sys.executable, script], env=env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert client.stdout.readline().strip() == b"ready"
        assert_clean_exit_on_sigterm(own_daemon)
    finally:
        client.stdin.close()
        client.wait(timeout=10)


def test_sigterm_with_idle_connection(own_daemon):
    if proxytest.use_tls():
        pytest.skip("a plain TCP connection is enough to cover this")
    host, port = own_daemon.socket.split("://")[1].rsplit(":", 1)
    with socket.create_connection((host, int(port))):
        assert_clean_exit_on_sigterm(own_daemon)
