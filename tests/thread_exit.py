"""Use the proxy in a thread that ends after C_Finalize.

Used by the thread tests in a separate process as a failure crashes it.
"""

import ctypes
import os
import threading

import pkcs11_raw

module = pkcs11_raw.RawModule(os.environ["PKCS11_TEST_PROXY_LIB"])
used = threading.Event()
finalized = threading.Event()
results = []


def get_slot_count():
    count = pkcs11_raw.CK_ULONG()
    results.append(module.call("C_GetSlotList", 0, None, ctypes.byref(count)))
    used.set()
    finalized.wait()


results.append(module.call("C_Initialize", None))
thread = threading.Thread(target=get_slot_count)
thread.start()
used.wait()
results.append(module.call("C_Finalize", None))
finalized.set()
thread.join()
assert results == [pkcs11_raw.CKR_OK] * 3, results
