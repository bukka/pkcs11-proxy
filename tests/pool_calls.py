"""Make calls from several threads at once and then wait until stdin is closed.

Used by the pool tests, which count the connections left open afterwards.
"""

import ctypes
import os
import sys
import threading

import pkcs11_raw

THREADS = 8
CALLS = 50

module = pkcs11_raw.RawModule(os.environ["PKCS11_TEST_PROXY_LIB"])
barrier = threading.Barrier(THREADS)


def check(name, *args):
    rv = module.call(name, *args)
    assert rv == pkcs11_raw.CKR_OK, f"{name} failed with {rv:#x}"


def get_slot_counts():
    count = pkcs11_raw.CK_ULONG()
    barrier.wait()
    for _ in range(CALLS):
        check("C_GetSlotList", 0, None, ctypes.byref(count))


check("C_Initialize", None)
threads = [threading.Thread(target=get_slot_counts) for _ in range(THREADS)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
print("ready", flush=True)
sys.stdin.read()
check("C_Finalize", None)
