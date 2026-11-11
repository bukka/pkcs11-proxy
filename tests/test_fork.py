import pytest

import proxytest


def test_initialize_in_forked_child(daemon):
    # The child must not reuse connections inherited from the parent
    if daemon is None:
        pytest.skip("requires pkcs11-daemon")
    assert proxytest.run_client_script(daemon, "fork_reinit.py") == 0
