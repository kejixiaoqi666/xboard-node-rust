"""Owned local TLS 1.3 fixture. No public listener or outbound network calls.

CPython SSLContext doesn't expose final hybrid groups; this fixture-only adapter
uses the documented OpenSSL SSL_CTX_ctrl SSL_CTRL_SET_GROUPS_LIST (92) and
CPython's pinned PySSLContext layout. Never used in the shipped Rust executable.
"""
import argparse
import ctypes
import json
from pathlib import Path
import socketserver
import ssl
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--cert', type=Path, required=True)
parser.add_argument('--key', type=Path, required=True)
parser.add_argument('--group', choices=['X25519', 'prime256v1', 'X25519MLKEM768'], required=True)
args = parser.parse_args()
assert sys.implementation.name == 'cpython' and sys.version_info[:2] == (3, 12)
assert ctypes.sizeof(ctypes.c_void_p) == 8 and ssl.OPENSSL_VERSION_INFO[:2] == (3, 5)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(str(args.cert), str(args.key))
if sys.platform == 'win32':
    library = ctypes.CDLL(str(Path(sys.executable).parent / 'DLLs/libssl-3-x64.dll'))
else:
    import ctypes.util
    library = ctypes.CDLL(ctypes.util.find_library('ssl'))
ssl_ctx = ctypes.c_void_p.from_address(id(context) + 2 * ctypes.sizeof(ctypes.c_void_p)).value
ctrl = library.SSL_CTX_ctrl
ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
ctrl.restype = ctypes.c_long
groups = ctypes.create_string_buffer(args.group.encode('ascii'))
assert ctrl(ssl_ctx, 92, 0, groups) == 1

class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            with context.wrap_socket(self.request, server_side=True) as stream:
                stream.recv(1)
        except OSError:
            pass  # The REALITY engine intentionally discards the mirror after its flight.

with Server(('127.0.0.1', 0), Handler) as server:
    print(json.dumps({'mirror': server.server_address, 'openssl': ssl.OPENSSL_VERSION,
                      'group': args.group, 'real_tls': True}), flush=True)
    server.serve_forever(poll_interval=0.1)
