"""Loopback Xray KeyUpdate injection and unchanged-ciphertext auto-rotation observer.

Xray performs the real REALITY handshake. Peer-update cases use an ephemeral
test key log to insert rotations and translate the generations. The automatic
case only observes and forwards original ciphertext to the unmodified client.
No key log is printed or included in release artifacts.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from test_vision import receive, free_port


class Direction:
    def __init__(self, secret, suite):
        self.secret, self.suite, self.seq = secret, suite, 0
        self._keys()

    def expand(self, label, length):
        label = b'tls13 ' + label
        info = struct.pack('!H', length) + bytes([len(label)]) + label + b'\0'
        return hmac.new(self.secret, info + b'\1', self.hash).digest()[:length]

    def _keys(self):
        assert self.suite in [0x1301, 0x1302, 0x1303]
        self.hash = hashlib.sha384 if self.suite == 0x1302 else hashlib.sha256
        self.iv = self.expand(b'iv', 12)
        key = self.expand(b'key', 16 if self.suite == 0x1301 else 32)
        self.aead = ChaCha20Poly1305(key) if self.suite == 0x1303 else AESGCM(key)

    def rotate(self):
        self.secret = self.expand(b'traffic upd', self.hash().digest_size)
        self.seq = 0
        self._keys()

    def nonce(self):
        nonce = bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, 'big')))
        self.seq += 1
        return nonce

    def decrypt(self, record):
        return self.aead.decrypt(self.nonce(), record[5:], record[:5])

    def encrypt(self, inner):
        header = b'\x17\x03\x03' + struct.pack('!H', len(inner) + 16)
        return header + self.aead.encrypt(self.nonce(), inner, header)


def tls_record(stream):
    header = receive(stream, 5)
    count = int.from_bytes(header[3:5], 'big')
    assert 0 < count <= 16640
    return header + receive(stream, count)


def inner_type(inner):
    inner = inner.rstrip(b'\0')
    assert inner
    return inner[-1], inner[:-1]


def exercise(config, run, wait, cases, measurements, node_port, user, temp, settings):
    config.pop('flow', None)
    binary = Path(os.environ['XRAY_TEST_BINARY'])
    assert '26.3.27' in subprocess.check_output([str(binary), 'version'], text=True).splitlines()[0]
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        block_on_close = False
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with origin_lock: origin_connections[0] += 1
            self.request.settimeout(15)
            try:
                while True:
                    body = self.request.recv(65536)
                    if not body: break
                    self.request.sendall(body)
            except OSError: pass
    origin_lock = threading.Lock()
    origin_connections = [0]
    origin = Server(('127.0.0.1', 0), Echo)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        for mode in ['rotate', 'invalid-request', 'auto-rotate']:
            automatic = mode == 'auto-rotate'
            config['tls_settings']['key_update_after_records'] = 16 if automatic else 1 << 20
            run('restart')
            metrics = {'sent_key_updates': 0, 'received_responses': 0, 'fragment_records': 0,
                       'client_data_records': 0, 'server_data_records': 0,
                       'observed_server_updates': 0, 'observed_client_updates': 0,
                       'max_records_per_generation': 0,
                       'forwarded_client_ciphertext_bytes': 0, 'forwarded_server_ciphertext_bytes': 0}
            forwarded = {name: {'in': hashlib.sha256(), 'out': hashlib.sha256()} for name in ['client', 'server']}
            failures = []
            handler_done = threading.Event()
            with origin_lock: origin_baseline = origin_connections[0]
            # Restrict test-only secrets to an owned private temporary directory.
            with tempfile.TemporaryDirectory(prefix='xbr-ku-') as private:
                keylog = Path(private) / 'keys'
                keylog.touch(mode=0o600)
                class Bridge(socketserver.BaseRequestHandler):
                    def handle(self):
                        self.request.settimeout(15)
                        upstream = socket.create_connection(('127.0.0.1', node_port), timeout=15)
                        upstream.settimeout(15)
                        client_hello = tls_record(self.request)
                        assert client_hello[0] == 22 and client_hello[5] == 1
                        random = client_hello[11:43].hex()
                        upstream.sendall(client_hello)
                        server_hello = tls_record(upstream)
                        assert server_hello[0] == 22 and server_hello[5] == 2
                        session_length = server_hello[43]
                        suite = int.from_bytes(server_hello[44+session_length:46+session_length], 'big')
                        self.request.sendall(server_hello)
                        def secret(label):
                            deadline = time.monotonic() + 10
                            while time.monotonic() < deadline:
                                for line in keylog.read_text().splitlines():
                                    fields = line.split()
                                    if len(fields) == 3 and fields[0] == label and fields[1].lower() == random:
                                        return bytes.fromhex(fields[2])
                                time.sleep(0.01)
                            raise AssertionError('test TLS key log entry unavailable: ' + label)
                        response = threading.Event()
                        def client_to_server():
                            handshake = None; app_in = app_out = None; complete = False
                            try:
                                while True:
                                    record = tls_record(self.request)
                                    if record[0] != 23:
                                        upstream.sendall(record); continue
                                    if not complete:
                                        if handshake is None: handshake = Direction(secret('CLIENT_HANDSHAKE_TRAFFIC_SECRET'), suite)
                                        kind, body = inner_type(handshake.decrypt(record))
                                        assert kind == 22 and body[0] == 20
                                        complete = True
                                        upstream.sendall(record)
                                        app_in = Direction(secret('CLIENT_TRAFFIC_SECRET_0'), suite)
                                        app_out = Direction(app_in.secret, suite)
                                        continue
                                    inner = app_in.decrypt(record)
                                    kind, _ = inner_type(inner)
                                    if automatic:
                                        # Observation only: every byte forwarded unchanged to the node.
                                        upstream.sendall(record)
                                        forwarded['client']['in'].update(record)
                                        forwarded['client']['out'].update(record)
                                        metrics['forwarded_client_ciphertext_bytes'] += len(record)
                                        if kind == 23: metrics['client_data_records'] += 1
                                        elif kind == 22:
                                            assert inner_type(inner)[1] in [b'\x18\0\0\1\0', b'\x18\0\0\1\1']
                                            metrics['observed_client_updates'] += 1
                                            app_in.rotate()
                                        continue
                                    if kind == 23:
                                        index = metrics['client_data_records']
                                        if index < 3:
                                            requested = 2 if mode == 'invalid-request' else int(index > 0)
                                            ku = bytes([24, 0, 0, 1, requested])
                                            pieces = [bytes([b]) for b in ku] if index == 1 else [ku]
                                            response.clear()
                                            for piece in pieces: upstream.sendall(app_out.encrypt(piece + b'\x16'))
                                            metrics['sent_key_updates'] += 1
                                            if index == 1: metrics['fragment_records'] = len(pieces)
                                            if mode == 'invalid-request':
                                                # Invalid request must close before this VLESS request can reach origin.
                                                return
                                            app_out.rotate()
                                        upstream.sendall(app_out.encrypt(inner))
                                        metrics['client_data_records'] += 1
                                        if index in [1, 2]: assert response.wait(10), 'requested KeyUpdate response missing'
                                    else: upstream.sendall(app_out.encrypt(inner))
                            except (OSError, EOFError): pass
                            except BaseException as error: failures.append(type(error).__name__ + ': ' + str(error))
                            finally:
                                try: upstream.shutdown(socket.SHUT_WR)
                                except OSError: pass
                        thread = threading.Thread(target=client_to_server, daemon=True)
                        thread.start()
                        try:
                            handshake = Direction(secret('SERVER_HANDSHAKE_TRAFFIC_SECRET'), suite)
                            complete = False; app_in = app_out = None
                            while True:
                                record = tls_record(upstream)
                                if record[0] != 23:
                                    self.request.sendall(record); continue
                                if not complete:
                                    kind, body = inner_type(handshake.decrypt(record))
                                    assert kind == 22
                                    offset = 0
                                    while offset < len(body):
                                        assert offset + 4 <= len(body)
                                        count = int.from_bytes(body[offset+1:offset+4], 'big')
                                        if body[offset] == 20: complete = True
                                        offset += 4 + count
                                    assert offset == len(body)
                                    self.request.sendall(record)
                                    if complete:
                                        app_in = Direction(secret('SERVER_TRAFFIC_SECRET_0'), suite)
                                        app_out = Direction(app_in.secret, suite)
                                    continue
                                inner = app_in.decrypt(record)
                                kind, body = inner_type(inner)
                                if automatic:
                                    # Keep the observer independent of the client's key update handling.
                                    before_update = app_in.seq - 1
                                    if kind == 22:
                                        assert body == b'\x18\0\0\1\0'
                                        assert before_update == 16, 'server rotated at wrong record boundary'
                                        metrics['observed_server_updates'] += 1
                                        metrics['max_records_per_generation'] = max(metrics['max_records_per_generation'], before_update)
                                        app_in.rotate()
                                    else:
                                        assert app_in.seq <= 16, 'server exceeded configured record budget'
                                        metrics['max_records_per_generation'] = max(metrics['max_records_per_generation'], app_in.seq)
                                        if kind == 23: metrics['server_data_records'] += 1
                                    self.request.sendall(record)
                                    forwarded['server']['in'].update(record)
                                    forwarded['server']['out'].update(record)
                                    metrics['forwarded_server_ciphertext_bytes'] += len(record)
                                    continue
                                if kind == 22:
                                    assert body == b'\x18\0\0\1\0'
                                    app_in.rotate()
                                    metrics['received_responses'] += 1
                                    response.set()
                                else:
                                    self.request.sendall(app_out.encrypt(inner))
                                    if kind == 23: metrics['server_data_records'] += 1
                        except (OSError, EOFError): pass
                        except BaseException as error: failures.append(type(error).__name__ + ': ' + str(error))
                        finally:
                            self.request.close(); upstream.close(); thread.join(timeout=16)
                            assert not thread.is_alive(), 'record adapter thread did not stop'
                            handler_done.set()
                bridge = Server(('127.0.0.1', 0), Bridge)
                threading.Thread(target=bridge.serve_forever, daemon=True).start()
                profile = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': free_port(),
                    'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
                    'outbounds': [{'protocol': 'vless', 'mux': {'enabled': False},
                    'settings': {'vnext': [{'address': '127.0.0.1', 'port': bridge.server_address[1],
                    'users': [{'id': user, 'encryption': 'none', 'flow': ''}]}]},
                    'streamSettings': {'network': 'tcp', 'security': 'reality',
                    'realitySettings': dict(settings, masterKeyLog=str(keylog))}}]}
                profile_path = temp / ('key-update-' + mode + '.json')
                # The profile has a temporary path, no secret contents.
                profile_path.write_text(json.dumps(profile))
                log = temp / ('key-update-' + mode + '.log')
                with log.open('wb') as output:
                    process = subprocess.Popen([str(binary), 'run', '-c', str(profile_path)], stdout=output, stderr=subprocess.STDOUT)
                    try:
                        port = profile['inbounds'][0]['port']
                        def ready():
                            assert process.poll() is None
                            with socket.create_connection(('127.0.0.1', port), timeout=1): return True
                        wait(ready)
                        with socket.create_connection(('127.0.0.1', port), timeout=15) as stream:
                            stream.settimeout(15); stream.sendall(b'\5\1\0'); assert receive(stream, 2) == b'\5\0'
                            stream.sendall(b'\5\1\0\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.server_address[1]))
                            header = receive(stream, 4); assert header[:2] == b'\5\0'
                            receive(stream, (4 if header[3] == 1 else 16) + 2)
                            if mode in ['rotate', 'auto-rotate']:
                                for index in range(32 if automatic else 12):
                                    body = bytes([index]) * 8192 + b'\x16\x03\x03'
                                    stream.sendall(body); assert receive(stream, len(body)) == body
                            else:
                                stream.sendall(b'must-not-echo')
                                try: assert not stream.recv(32)
                                except (ConnectionError, EOFError): pass
                    finally:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                        bridge.shutdown(); bridge.server_close()
                        assert handler_done.wait(18), 'record adapter did not stop'
                assert not failures, failures
                if automatic:
                    assert metrics['observed_server_updates'] >= 3, metrics
                    assert metrics['sent_key_updates'] == 0 and metrics['received_responses'] == 0
                    assert metrics['observed_client_updates'] == 0
                    assert metrics['max_records_per_generation'] == 16
                    assert metrics['server_data_records'] >= 49
                    for name, digest in forwarded.items():
                        assert digest['in'].hexdigest() == digest['out'].hexdigest()
                        metrics[name + '_ciphertext_sha256'] = digest['in'].hexdigest()
                    metrics.update(payload_bytes_per_direction=32*8195, ciphertext_forwarded_unchanged=True,
                        test_record_observer=True, key_update_after_records=16, loopback_only=True,
                        official_client_version='v26.3.27', secrets_retained=False,
                        client_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    measurements['reality_auto_key_update'] = metrics
                elif mode == 'rotate':
                    assert metrics['sent_key_updates'] == 3 and metrics['received_responses'] == 2, metrics
                    assert metrics['fragment_records'] == 5 and metrics['client_data_records'] >= 3, metrics
                    metrics.update(payload_bytes_per_direction=12*8195, test_adapter=True, loopback_only=True,
                        official_client_version='v26.3.27', secrets_retained=False,
                        client_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
                    measurements['reality_key_update'] = metrics
                else:
                    assert metrics['sent_key_updates'] == 1 and metrics['received_responses'] == 0
                    with origin_lock: assert origin_connections[0] == origin_baseline, 'invalid update reached origin'
            cases.append('installed-native-REALITY-KeyUpdate-' + mode + (
                '-unmodified-official-client-unchanged-ciphertext-observer' if automatic else '-official-handshake-test-record-adapter'))
    finally:
        origin.shutdown(); origin.server_close()
