import pytest

import proxytest


def test_thread_exit_after_finalize(daemon):
    # Crashed with TLS when the thread still referred to a freed OpenSSL context
    if daemon is None:
        pytest.skip("requires pkcs11-daemon")
    assert proxytest.run_client_script(daemon, "thread_exit.py") == 0
