import re
import subprocess

import pytest

import proxytest
from proxytest import start_hold_session_client, stop_hold_session_client, wait_for_log

VERSION_PATTERN = r"[0-9]+\.[0-9]+"


def test_daemon_version_option():
    if not proxytest.use_proxy():
        pytest.skip("requires pkcs11-daemon")
    result = subprocess.run([proxytest.daemon_path(), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert re.match(r"pkcs11-daemon " + VERSION_PATTERN, result.stdout)


def test_daemon_logs_version_on_startup(own_daemon):
    log_file = own_daemon.env["PKCS11_PROXY_LOG_FILE"]
    wait_for_log(log_file, "Starting pkcs11-daemon ", process=own_daemon.process)
    assert re.search(r"Starting pkcs11-daemon " + VERSION_PATTERN, open(log_file).read())


def test_proxy_logs_version_on_initialize(own_daemon, tmp_path):
    log_file = str(tmp_path / "proxy.log")
    client = start_hold_session_client(own_daemon, {"PKCS11_PROXY_LOG_FILE": log_file})
    stop_hold_session_client(client)
    assert re.search(r"Initializing pkcs11-proxy " + VERSION_PATTERN, open(log_file).read())
