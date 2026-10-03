import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, exceptions

import proxytest
from proxytest import EC_KEY_LABEL, ProxyDaemon

pytestmark = pytest.mark.daemon_config(disabled_functions="C_WrapKey, C_DestroyObject")


def test_wrap_key_is_rejected(pkcs11_session):
    public_key, _ = pkcs11_session.generate_keypair(KeyType.RSA, 2048)
    key = pkcs11_session.generate_key(KeyType.AES, 128, template={Attribute.EXTRACTABLE: True})
    with pytest.raises(exceptions.FunctionNotSupported):
        public_key.wrap_key(key, mechanism=Mechanism.RSA_PKCS)


def test_destroy_object_is_rejected(pkcs11_session):
    key = pkcs11_session.generate_key(KeyType.AES, 128, label="UndeletableSessionKey")
    with pytest.raises(exceptions.FunctionNotSupported):
        key.destroy()
    assert pkcs11_session.get_key(label="UndeletableSessionKey") is not None


def test_other_functions_work(pkcs11_session):
    private_key = pkcs11_session.get_key(label=EC_KEY_LABEL, object_class=ObjectClass.PRIVATE_KEY)
    public_key = pkcs11_session.get_key(label=EC_KEY_LABEL, object_class=ObjectClass.PUBLIC_KEY)
    message = b"Message to be signed with wrapping disabled"
    signature = private_key.sign(message, mechanism=Mechanism.ECDSA)
    assert public_key.verify(message, signature, mechanism=Mechanism.ECDSA)


@pytest.mark.parametrize("names", ["C_WrapKey, C_Nonexistent", "C_Initialize", "C_Finalize"])
def test_invalid_configuration_stops_the_daemon(tmp_path, names):
    if not proxytest.use_proxy():
        pytest.skip("requires pkcs11-daemon")
    conf_path = tmp_path / "pkcs11-daemon.conf"
    conf_path.write_text(f"disabled_functions = {names}\n")
    daemon = ProxyDaemon(2399, {"PKCS11_PROXY_CONF_PATH": str(conf_path)})
    daemon.start()
    try:
        assert daemon.process.wait(timeout=5) != 0
    finally:
        daemon.stop()
