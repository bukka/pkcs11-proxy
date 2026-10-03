"""PKCS#11 calls that python-pkcs11 does not expose.

The calls go through the function list of a library that python-pkcs11 has
already loaded and initialized.
"""

import ctypes

CKR_OK = 0x00
CKR_TOKEN_WRITE_PROTECTED = 0xE2
CKF_WRITE_PROTECTED = 0x02
CKF_RW_SESSION = 0x02
CKF_SERIAL_SESSION = 0x04
CKS_RO_PUBLIC_SESSION = 0
CKS_RO_USER_FUNCTIONS = 1

CK_ULONG = ctypes.c_ulong
CK_BYTE = ctypes.c_ubyte


class CK_VERSION(ctypes.Structure):
    _fields_ = [("major", CK_BYTE), ("minor", CK_BYTE)]


class CK_TOKEN_INFO(ctypes.Structure):
    _fields_ = [
        ("label", CK_BYTE * 32),
        ("manufacturerID", CK_BYTE * 32),
        ("model", CK_BYTE * 16),
        ("serialNumber", CK_BYTE * 16),
        ("flags", CK_ULONG),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", CK_BYTE * 16),
    ]


class CK_SESSION_INFO(ctypes.Structure):
    _fields_ = [
        ("slotID", CK_ULONG),
        ("state", CK_ULONG),
        ("flags", CK_ULONG),
        ("ulDeviceError", CK_ULONG),
    ]


# Leading part of CK_FUNCTION_LIST, enough for the functions used here
FUNCTION_NAMES = [
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
    "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
]


class CK_FUNCTION_LIST(ctypes.Structure):
    _fields_ = [("version", CK_VERSION)] + [(name, ctypes.c_void_p) for name in FUNCTION_NAMES]


class RawModule:
    def __init__(self, path):
        self.module = ctypes.CDLL(path)
        get_function_list = self.module.C_GetFunctionList
        get_function_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
        get_function_list.restype = CK_ULONG
        function_list = ctypes.POINTER(CK_FUNCTION_LIST)()
        self._check("C_GetFunctionList", get_function_list(ctypes.byref(function_list)))
        self.functions = function_list.contents

    @staticmethod
    def _check(name, rv):
        if rv != CKR_OK:
            raise RuntimeError(f"{name} failed with {rv:#x}")

    def call(self, name, *args):
        prototype = ctypes.CFUNCTYPE(CK_ULONG, *([ctypes.c_void_p] * len(args)))
        return prototype(getattr(self.functions, name))(*args)

    def get_token_info(self, slot_id):
        info = CK_TOKEN_INFO()
        self._check("C_GetTokenInfo", self.call("C_GetTokenInfo", slot_id, ctypes.byref(info)))
        return info

    def get_session_info(self, session_handle):
        info = CK_SESSION_INFO()
        self._check("C_GetSessionInfo", self.call("C_GetSessionInfo", session_handle, ctypes.byref(info)))
        return info

    def init_token(self, slot_id, so_pin, label):
        so_pin = so_pin.encode()
        label = label.encode().ljust(32)
        return self.call("C_InitToken", slot_id, so_pin, len(so_pin), label)

    def init_pin(self, session_handle, pin):
        pin = pin.encode()
        return self.call("C_InitPIN", session_handle, pin, len(pin))

    def set_pin(self, session_handle, old_pin, new_pin):
        old_pin = old_pin.encode()
        new_pin = new_pin.encode()
        return self.call("C_SetPIN", session_handle, old_pin, len(old_pin), new_pin, len(new_pin))
