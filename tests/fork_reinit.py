"""Initialize the proxy again in a forked child while the parent keeps using it.

Used by the fork tests in a separate process to keep pytest free of forks.
"""

import ctypes
import os

import pkcs11_raw

module = pkcs11_raw.RawModule(os.environ["PKCS11_TEST_PROXY_LIB"])


def check(name, *args):
    rv = module.call(name, *args)
    assert rv == pkcs11_raw.CKR_OK, f"{name} failed with {rv:#x} in {os.getpid()}"


def get_slot_id():
    count = pkcs11_raw.CK_ULONG()
    check("C_GetSlotList", 1, None, ctypes.byref(count))
    slot_ids = (pkcs11_raw.CK_ULONG * count.value)()
    check("C_GetSlotList", 1, slot_ids, ctypes.byref(count))
    return slot_ids[0]


check("C_Initialize", None)
session = pkcs11_raw.CK_ULONG()
check("C_OpenSession", get_slot_id(), pkcs11_raw.CKF_SERIAL_SESSION, None, None, ctypes.byref(session))
pid = os.fork()
if pid == 0:
    try:
        check("C_Initialize", None)
        get_slot_id()
        check("C_Finalize", None)
    except BaseException:
        os._exit(1)
    os._exit(0)
assert os.waitpid(pid, 0)[1] == 0
# The session of the parent must survive the child
module.get_session_info(session.value)
check("C_Finalize", None)
