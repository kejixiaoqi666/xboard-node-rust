"""Installed Rust ELF vs pinned official Xray client, loopback-only."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import time

XRAY_VERSION = 'v26.3.27'

def receive(stream, count):
    body = bytearray()
    while len(body) < count:
        part = stream.recv(count - len(body))
        if not part: raise EOFError('Vision tunnel closed early')
        body.extend(part)
    return bytes(body)

def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]

def exercise(config, run, wait, cases, measurements, node_port, cert, key, user, temp, reality=None):
    binary = Path(os.environ['XRAY_TEST_BINARY'])
    assert binary.is_file()
    version = subprocess.check_output([str(binary), 'version'], text=True).splitlines()[0]
    assert '26.3.27' in version
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    logs, accepted, lock = {}, [0], threading.Lock()
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            stream = self.request
            stream.settimeout(20)
            try:
                with lock: accepted[0] += 1
                if self.server.tls:
                    stream = self.server.tls.wrap_socket(stream, server_side=True)
                while True:
                    body = stream.recv(65536)
                    if not body: return
                    stream.sendall(body)
            except (OSError, EOFError): pass
            finally: stream.close()
    servers = []
    for version_limit in [None, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2]:
        server = Server(('127.0.0.1', 0), Echo)
        server.tls = None
        if version_limit:
            server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.tls.minimum_version = server.tls.maximum_version = version_limit
            server.tls.load_cert_chain(str(cert), str(key))
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    # Force a TLS1.3 retry: the Python client offers X25519 first and the
    # origin only accepts P-384. A loopback relay records the actual HRR random.
    hrr_origin = Server(('127.0.0.1', 0), Echo)
    hrr_origin.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    hrr_origin.tls.minimum_version = hrr_origin.tls.maximum_version = ssl.TLSVersion.TLSv1_3
    hrr_origin.tls.load_cert_chain(str(cert), str(key))
    hrr_origin.tls.set_ecdh_curve('secp384r1')
    hrr_observed = [False]
    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(20)
            upstream = socket.create_connection(hrr_origin.server_address, timeout=20)
            def copy(source, target, record=False):
                observed = bytearray()
                try:
                    while True:
                        body = source.recv(65536)
                        if not body: break
                        if record and len(observed) < 65536:
                            observed.extend(body[:65536-len(observed)])
                            random = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')
                            if random in observed: hrr_observed[0] = True
                        target.sendall(body)
                except OSError: pass
                finally:
                    try: target.shutdown(socket.SHUT_WR)
                    except OSError: pass
            thread = threading.Thread(target=copy, args=(self.request, upstream), daemon=True)
            thread.start(); copy(upstream, self.request, True); thread.join(timeout=22); upstream.close()
    retry = Server(('127.0.0.1', 0), Relay)
    retry.tls = hrr_origin.tls
    servers.append(retry)
    for server in [hrr_origin, retry]: threading.Thread(target=server.serve_forever, daemon=True).start()
    @contextlib.contextmanager
    def client(label, flow='xtls-rprx-vision', identity=user, short_id=None):
        port = free_port()
        path = temp / ('xray-' + label + '.json')
        profile = {'log': {'loglevel': 'debug'}, 'inbounds': [{
            'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': node_port,
                'users': [{'id': identity, 'encryption': 'none', 'flow': flow}]}]},
                'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'serverName': 'localhost',
                    'allowInsecure': False, 'minVersion': '1.3', 'maxVersion': '1.3',
                    'certificates': [{'usage': 'verify', 'certificateFile': str(cert)}]}}}]}
        if reality:
            profile['outbounds'][0]['streamSettings'] = {'network': 'tcp', 'security': 'reality',
                'realitySettings': dict(reality, **({'shortId': short_id} if short_id else {}))}
        path.write_text(json.dumps(profile))
        log_path = temp / ('xray-' + label + '.log')
        with log_path.open('wb') as output:
            process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=output, stderr=subprocess.STDOUT)
            try:
                def ready():
                    assert process.poll() is None, log_path.read_text(errors='replace')
                    with socket.create_connection(('127.0.0.1', port), timeout=2): return True
                wait(ready)
                yield port
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                logs[label] = log_path.read_text(errors='replace')
    def connect(port, target):
        stream = socket.create_connection(('127.0.0.1', port), timeout=12)
        stream.settimeout(12)
        stream.sendall(b'\5\1\0')
        assert receive(stream, 2) == b'\5\0'
        stream.sendall(b'\5\1\0\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', target))
        header = receive(stream, 4)
        assert header[:2] == b'\5\0'
        assert header[3] in [1,4]
        receive(stream, (4 if header[3]==1 else 16)+2)
        return stream
    config['flow'] = 'xtls-rprx-vision'
    try:
        run('restart')
        for label, server in zip(['plain', 'tls13', 'tls12', 'tls13-hrr'], servers):
            with client(label) as port:
                def roundtrip():
                    with connect(port, server.server_address[1]) as stream:
                        if server.tls:
                            context = ssl.create_default_context(cafile=str(cert))
                            context.minimum_version = context.maximum_version = server.tls.minimum_version
                            stream = context.wrap_socket(stream, server_hostname='localhost')
                        # Xray only emits DIRECT when its input contains complete TLS records.
                        # Start with a small complete application record, then exercise large fragmented records.
                        warmup = b"complete-record-before-large-transfer"
                        stream.sendall(warmup)
                        assert receive(stream, len(warmup)) == warmup
                        # Tail resembling a partial TLS header must also be delivered.
                        for index in range(32):
                            body = bytes([index])*8192 + b'\x16\x03\x03'
                            stream.sendall(body)
                            assert receive(stream, len(body)) == body
                        return True
                wait(roundtrip)
            if label in ['tls13', 'tls13-hrr']:
                assert re.search(r'XtlsPadding \d+ \d+ 2', logs[label]), logs[label]
                assert re.search(r'Xtls Unpadding new block, content \d+ padding \d+ command 2', logs[label]), logs[label]
            if label == 'tls12':
                assert 'command 2' not in logs[label]
                assert not re.search(r'XtlsPadding \d+ \d+ 2', logs[label])
            cases.append('installed-native-' + ('REALITY-' if reality else '') + 'Vision-official-Xray-' + label + '-exact-bytes' + ('-bidirectional-DIRECT' if label in ['tls13','tls13-hrr'] else ''))
        assert hrr_observed[0], 'Fixture did not exercise a real HelloRetryRequest'
        denied_cases = [('missing-flow', '', user, None), ('wrong-uuid', 'xtls-rprx-vision', '00000000-0000-4000-8000-000000000999', None)]
        if reality: denied_cases.append(('wrong-short-id', 'xtls-rprx-vision', user, 'ffffffffffffffff'))
        for label, flow, identity, short_id in denied_cases:
            with lock: baseline = accepted[0]
            with client(label, flow, identity, short_id) as port:
                denied = False
                try:
                    with connect(port, servers[0].server_address[1]) as stream:
                        stream.sendall(b'not-authorized')
                        denied = not stream.recv(1)
                except (OSError, EOFError): denied = True
                assert denied
            with lock: assert accepted[0] == baseline, 'Denied credentials reached origin'
            cases.append('installed-native-' + ('REALITY-' if reality else '') + 'Vision-' + label + '-denied-before-origin-connect')
        if reality:
            config.pop('flow', None); run('restart')
            with client('no-vision', flow='') as port:
                def plain():
                    with connect(port, servers[0].server_address[1]) as stream:
                        body = b'REALITY VLESS without Vision' * 1024
                        stream.sendall(body); assert receive(stream, len(body)) == body
                    return True
                wait(plain)
            cases.append('installed-native-REALITY-VLESS-without-Vision-exact-bytes')
        measurements['reality' if reality else 'vision'] = {'client_version': version, 'client_binary_sha256': binary_sha,
            'client_only': True, 'loopback_only': True, 'payload_bytes_per_case': 32*8195 + len(b"complete-record-before-large-transfer"),
            'client_logs_sha256': {label: hashlib.sha256(body.encode()).hexdigest() for label,body in logs.items()},
            'tls13_client_sent_and_received_direct_command': True,
            'tls13_retry_observed_in_actual_origin_wire': hrr_observed[0],
            'server_runtime_external_kernel_required': False}
    except BaseException:
        for label, body in logs.items(): print('Xray fixture ' + label + ':\n' + body[-16000:])
        raise
    finally:
        config.pop('flow', None)
        for server in [*servers,hrr_origin]: server.shutdown(); server.server_close()
