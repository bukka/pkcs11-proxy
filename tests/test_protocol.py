import pkcs11
from pkcs11 import Attribute, KeyType, TokenFlag

def test_token_is_writable(pkcs11_token):
    assert TokenFlag.WRITE_PROTECTED not in pkcs11_token.flags

def test_repeated_calls_stay_consistent(pkcs11_lib):
    # Repeat the buffer-growing calls past the daemon's shrink interval (1000).
    lib = pkcs11_lib
    token = lib.get_token(token_label="ProxyTestToken")

    slot = token.slot
    expected_mechs = sorted(slot.get_mechanisms())
    expected_slots = [s.slot_id for s in lib.get_slots()]

    rounds = 400
    with token.open(user_pin="1234", rw=True) as session:
        public_key = session.get_key(
            label="ProxyTestExistingECKey",
            key_type=KeyType.EC,
            object_class=pkcs11.ObjectClass.PUBLIC_KEY,
        )
        expected_point = public_key[Attribute.EC_POINT]
        expected_params = public_key[Attribute.EC_PARAMS]

        for i in range(rounds):
            assert sorted(slot.get_mechanisms()) == expected_mechs, f"mechanism list changed at round {i}"
            assert [s.slot_id for s in lib.get_slots()] == expected_slots, f"slot list changed at round {i}"
            assert public_key[Attribute.EC_POINT] == expected_point, f"EC_POINT changed at round {i}"
            assert public_key[Attribute.EC_PARAMS] == expected_params, f"EC_PARAMS changed at round {i}"
