import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass, TokenFlag, exceptions

import pkcs11_raw
from proxytest import EC_KEY_LABEL, USER_PIN

pytestmark = pytest.mark.daemon_config(read_only_sessions=True)


def get_ec_key(session, object_class):
    return session.get_key(label=EC_KEY_LABEL, key_type=KeyType.EC, object_class=object_class)


def test_token_is_write_protected(pkcs11_token, raw_module):
    assert TokenFlag.WRITE_PROTECTED in pkcs11_token.flags
    info = raw_module.get_token_info(pkcs11_token.slot.slot_id)
    assert info.flags & pkcs11_raw.CKF_WRITE_PROTECTED
    assert info.ulMaxRwSessionCount == 0
    assert info.ulRwSessionCount == 0


def test_rw_session_is_downgraded(pkcs11_session, raw_module):
    # The session fixture requests a read/write session
    info = raw_module.get_session_info(pkcs11_session._handle)
    assert info.flags & pkcs11_raw.CKF_SERIAL_SESSION
    assert not info.flags & pkcs11_raw.CKF_RW_SESSION
    assert info.state == pkcs11_raw.CKS_RO_USER_FUNCTIONS


def test_token_objects_cannot_be_modified(pkcs11_session):
    with pytest.raises(exceptions.SessionReadOnly):
        pkcs11_session.generate_key(KeyType.AES, 128, store=True, label="ReadOnlyShouldFail")

    private_key = get_ec_key(pkcs11_session, ObjectClass.PRIVATE_KEY)
    with pytest.raises(exceptions.SessionReadOnly):
        private_key[Attribute.LABEL] = "Renamed"
    with pytest.raises(exceptions.SessionReadOnly):
        private_key.destroy()

    assert list(pkcs11_session.get_objects({Attribute.LABEL: "ReadOnlyShouldFail"})) == []
    assert get_ec_key(pkcs11_session, ObjectClass.PRIVATE_KEY) is not None


def test_session_objects_work(pkcs11_session):
    key = pkcs11_session.generate_key(KeyType.AES, 128, store=False, label="SessionAES")
    iv = pkcs11_session.generate_random(128)
    plaintext = b"0123456789abcdef" * 2
    ciphertext = key.encrypt(plaintext, mechanism_param=iv)
    assert key.decrypt(ciphertext, mechanism_param=iv) == plaintext
    key[Attribute.LABEL] = "SessionAESRenamed"
    key.destroy()


def test_token_keys_can_be_used(pkcs11_session):
    private_key = get_ec_key(pkcs11_session, ObjectClass.PRIVATE_KEY)
    public_key = get_ec_key(pkcs11_session, ObjectClass.PUBLIC_KEY)
    message = b"Message to be signed in a read-only session"
    signature = private_key.sign(message, mechanism=Mechanism.ECDSA)
    assert public_key.verify(message, signature, mechanism=Mechanism.ECDSA)


def test_pin_management_is_rejected(pkcs11_session, raw_module):
    handle = pkcs11_session._handle
    assert raw_module.set_pin(handle, USER_PIN, USER_PIN) == pkcs11_raw.CKR_TOKEN_WRITE_PROTECTED
    assert raw_module.init_pin(handle, USER_PIN) == pkcs11_raw.CKR_TOKEN_WRITE_PROTECTED


def test_init_token_is_rejected(pkcs11_token, raw_module):
    # A wrong SO PIN keeps the token intact if the daemon lets the call through
    rv = raw_module.init_token(pkcs11_token.slot.slot_id, "0000", "ReadOnlyInit")
    assert rv == pkcs11_raw.CKR_TOKEN_WRITE_PROTECTED
