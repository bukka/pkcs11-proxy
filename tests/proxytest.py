import os
import platform
import subprocess
import time

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(TESTS_DIR, "..", "build")

TOKEN_LABEL = "ProxyTestToken"
USER_PIN = "1234"
EC_KEY_LABEL = "ProxyTestExistingECKey"

PSK_FILE = os.path.join(TESTS_DIR, "pkcs11_tls.psk")
PSK_CONTENT = "client:0df6c00be91c6a334589f699365b3125acb9e2232203d2e05ee61af848c103a4"

SOFTHSM_PATHS = [
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
]


def use_proxy():
    return not os.getenv("PKCS11_TEST_NO_PROXY")


def use_tls():
    return bool(os.getenv("PKCS11_TEST_TLS"))


def start_daemon():
    return not os.getenv("PKCS11_TEST_NO_DAEMON")


def softhsm_library_path():
    path = os.getenv("PKCS11_TEST_LIB")
    if path and os.path.exists(path):
        return path
    for path in SOFTHSM_PATHS:
        if os.path.exists(path):
            return path
    return None


def proxy_library_path():
    extension = "dylib" if platform.system() == "Darwin" else "so"
    return os.path.join(BUILD_DIR, f"libpkcs11-proxy.{extension}")


def daemon_path():
    return os.path.join(BUILD_DIR, "pkcs11-daemon")


class ProxyDaemon:
    """pkcs11-daemon listening on a local port"""

    def __init__(self, port, env=None):
        scheme = "tls" if use_tls() else "tcp"
        self.socket = f"{scheme}://127.0.0.1:{port}"
        self.env = env or {}
        self.process = None

    def start(self):
        env = {**os.environ, "PKCS11_DAEMON_SOCKET": self.socket, **self.env}
        self.process = subprocess.Popen([daemon_path(), softhsm_library_path()], env=env)

    def stop(self):
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None


class DaemonRegistry:
    """One pkcs11-daemon per distinct set of configuration options"""

    def __init__(self, conf_dir):
        self.conf_dir = conf_dir
        self.daemons = {}
        self.next_port = 2346

    def get(self, options):
        key = tuple(sorted(options.items()))
        if key not in self.daemons:
            self.daemons[key] = self._start(options)
        return self.daemons[key]

    def _start(self, options):
        if not options:
            # The main daemon may be run externally, see PKCS11_TEST_NO_DAEMON
            daemon = ProxyDaemon(2345)
            if start_daemon():
                daemon.start()
                time.sleep(0.5)
            return daemon

        port = self.next_port
        self.next_port += 1
        conf_path = os.path.join(self.conf_dir, f"pkcs11-daemon-{port}.conf")
        with open(conf_path, "w") as f:
            for name, value in options.items():
                if isinstance(value, bool):
                    value = "true" if value else "false"
                f.write(f"{name} = {value}\n")
        daemon = ProxyDaemon(port, {"PKCS11_PROXY_CONF_PATH": conf_path})
        daemon.start()
        time.sleep(0.5)
        return daemon

    def stop_all(self):
        for daemon in reversed(list(self.daemons.values())):
            daemon.stop()
        self.daemons = {}
