import os
import platform
import socket
import subprocess
import sys
import time

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(TESTS_DIR, "..", "build")

TOKEN_LABEL = "ProxyTestToken"
USER_PIN = "1234"
EC_KEY_LABEL = "ProxyTestExistingECKey"
OWN_DAEMON_PORT = 2398

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

    def start(self, timeout=5):
        env = {**os.environ, "PKCS11_DAEMON_SOCKET": self.socket, **self.env}
        self.process = subprocess.Popen([daemon_path(), softhsm_library_path()], env=env)
        self.wait_until_listening(timeout)

    def wait_until_listening(self, timeout):
        host, port = self.socket.split("://")[1].rsplit(":", 1)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"pkcs11-daemon exited with {self.process.returncode}")
            try:
                socket.create_connection((host, int(port)), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"pkcs11-daemon is not listening on {self.socket}")

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
        return daemon

    def stop_all(self):
        for daemon in reversed(list(self.daemons.values())):
            daemon.stop()
        self.daemons = {}


def start_hold_session_client(daemon, env=None):
    """Run hold_session.py against the daemon and return it once connected"""
    client_env = {
        **os.environ,
        "PKCS11_PROXY_SOCKET": daemon.socket,
        "PKCS11_TEST_PROXY_LIB": proxy_library_path(),
        "PKCS11_TEST_TOKEN_LABEL": TOKEN_LABEL,
        "PKCS11_TEST_USER_PIN": USER_PIN,
        **(env or {}),
    }
    script = os.path.join(TESTS_DIR, "hold_session.py")
    client = subprocess.Popen([sys.executable, script], env=client_env, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if client.stdout.readline().strip() != b"ready":
        client.kill()
        raise RuntimeError("hold_session.py did not connect")
    return client


def stop_hold_session_client(client):
    client.stdin.close()
    client.wait(timeout=10)


def wait_for_log(log_file, text, timeout=15, process=None):
    """Wait until the log file contains the text"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(log_file) and text in open(log_file).read():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"process exited with {process.returncode}")
        time.sleep(0.1)
    raise TimeoutError(f"{text!r} not found in {log_file}")
