import time

import pytest

from proxytest import count_in_log, start_client_script, stop_hold_session_client


def open_connections(daemon):
    log_file = daemon.env["PKCS11_PROXY_LOG_FILE"]
    return count_in_log(log_file, "New session") - count_in_log(log_file, "disconnected (client")


def wait_for_open_connections(daemon, expected, timeout=5):
    deadline = time.monotonic() + timeout
    while open_connections(daemon) != expected and time.monotonic() < deadline:
        time.sleep(0.05)
    return open_connections(daemon)


@pytest.mark.parametrize("pool_size", [1, 3])
def test_pool_size_limits_idle_connections(own_daemon, tmp_path, pool_size):
    conf_path = tmp_path / "pkcs11-proxy.conf"
    conf_path.write_text(f"pool_size = {pool_size}\n")
    client = start_client_script(own_daemon, "pool_calls.py", {"PKCS11_PROXY_CONF_PATH": str(conf_path)})
    try:
        assert wait_for_open_connections(own_daemon, pool_size) == pool_size
    finally:
        stop_hold_session_client(client)
    assert client.returncode == 0
