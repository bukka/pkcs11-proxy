import signal
import socket

import pytest

import proxytest
from proxytest import start_hold_session_client, stop_hold_session_client


def assert_clean_exit_on_sigterm(daemon):
    daemon.process.send_signal(signal.SIGTERM)
    assert daemon.process.wait(timeout=5) == 0


def test_sigterm_with_connected_client(own_daemon):
    client = start_hold_session_client(own_daemon)
    try:
        assert_clean_exit_on_sigterm(own_daemon)
    finally:
        stop_hold_session_client(client)


def test_sigterm_with_idle_connection(own_daemon):
    if proxytest.use_tls():
        pytest.skip("a plain TCP connection is enough to cover this")
    host, port = own_daemon.socket.split("://")[1].rsplit(":", 1)
    with socket.create_connection((host, int(port))):
        assert_clean_exit_on_sigterm(own_daemon)
