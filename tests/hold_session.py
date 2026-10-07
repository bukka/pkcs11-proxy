"""Keep a session open through the proxy until stdin is closed.

Used by the shutdown tests, which need a client connected from another
process while the daemon is stopped.
"""

import os
import sys

import pkcs11

lib = pkcs11.lib(os.environ["PKCS11_TEST_PROXY_LIB"])
token = lib.get_token(token_label=os.environ["PKCS11_TEST_TOKEN_LABEL"])
with token.open(user_pin=os.environ["PKCS11_TEST_USER_PIN"]):
    print("ready", flush=True)
    sys.stdin.read()
