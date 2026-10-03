"""Installed native Rust Shadowsocks vs official Xray and independent AEAD frames."""
import base64
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import struct
import subprocess
import threading
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from test_vision import free_port, receive

METHODS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
           '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm']

def converted(method, text):
    size = 16 if 'aes-128' in method else 32
    return base64.b64encode(text.encode()[:size].ljust(size, b'\0')).decode()

def classic_key(method, password, salt):
    size = 16 if method == 'aes-128-gcm' else 32
    output, block = b'', b''
    while len(output) < size:
        block = hashlib.md5(block + password.encode()).digest(); output += block
    return HKDF(algorithm=hashes.SHA1(), length=size, salt=salt, info=b'ss-subkey').derive(output[:size])

def classic_udp(method, password, address, body):
    salt = os.urandom(16 if method == 'aes-128-gcm' else 32)
    cipher = ChaCha20Poly1305 if method.startswith('chacha') else AESGCM
    return salt + cipher(classic_key(method, password, salt)).encrypt(bytes(12), address + body, None)

def classic_tcp(method, password, address, body):
    salt = os.urandom(16 if method == 'aes-128-gcm' else 32)
    cipher = ChaCha20Poly1305 if method.startswith('chacha') else AESGCM
    cipher = cipher(classic_key(method, password, salt))
    plain = address + body
    return salt + cipher.encrypt(bytes(12), struct.pack('!H', len(plain)), None) + cipher.encrypt((1).to_bytes(12, 'little'), plain, None)

def exercise(config, users, run, wait, cases, measurements, node_port, user, temp, traffic_snapshot, parent, child_ids):
    binary = Path(os.environ['XRAY_TEST_BINARY'])
    version = subprocess.check_output([str(binary), 'version'], text=True).splitlines()[0]
    assert '26.3.27' in version
    original, original_users = copy.deepcopy(config), copy.deepcopy(users)
    logs, observed, accepted, lock = {}, [], [0], threading.Lock()
    class TCP(socketserver.ThreadingTCPServer): daemon_threads = True
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            with lock: accepted[0] += 1
            self.request.settimeout(10)
            try:
                while True:
                    body = self.request.recv(65536)
                    if not body: break
                    self.request.sendall(body)
            except OSError: pass
    origin = TCP(('127.0.0.1', 0), Echo)
    class UDP(socketserver.ThreadingUDPServer):
        daemon_threads = True
        max_packet_size = 65536
    class UDP6(UDP): address_family = socket.AF_INET6
    class Datagram(socketserver.BaseRequestHandler):
        def handle(self):
            body, sock = self.request
            with lock: observed.append(body)
            sock.sendto(body, self.client_address)
    datagrams = [UDP(('127.0.0.1', 0), Datagram), UDP(('127.0.0.1', 0), Datagram), UDP6(('::1', 0), Datagram)]
    # Independent TCP relay splits the whole client direction into tiny writes.
    class Fragment(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            try:
                with socket.create_connection(('127.0.0.1', node_port), timeout=10) as upstream:
                    peers = {self.request: upstream, upstream: self.request}
                    first = True
                    while peers:
                        ready, _, _ = select.select(list(peers), [], [], 10)
                        if not ready: break
                        for source in ready:
                            body = source.recv(65536); target = peers[source]
                            if body:
                                if source is self.request and first:
                                    for part in range(0, min(128, len(body)), 3):
                                        target.sendall(body[part:min(part+3, 128, len(body))]); time.sleep(0.001)
                                    target.sendall(body[128:]); first = False
                                else: target.sendall(body)
                            else: target.shutdown(socket.SHUT_WR); del peers[source]
            except OSError: pass
    fragment = TCP(('127.0.0.1', 0), Fragment)
    for server in [origin, fragment, *datagrams]: threading.Thread(target=server.serve_forever, daemon=True).start()

    @contextlib.contextmanager
    def client(method, label, identity=user, port=node_port):
        local = free_port()
        password = converted(method, 'server-unique-key') + ':' + converted(method, identity) if method.startswith('2022-') else identity
        profile = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': local,
            'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}], 'outbounds': [{
                'protocol': 'shadowsocks', 'settings': {'servers': [{'address': '127.0.0.1', 'port': port,
                    'method': method, 'password': password}]}, 'mux': {'enabled': False}}]}
        path = temp / ('xray-ss-' + label + '.json'); path.write_text(json.dumps(profile))
        log = temp / ('xray-ss-' + label + '.log')
        with log.open('wb') as output:
            process = subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=output, stderr=subprocess.STDOUT)
            try:
                def ready():
                    assert process.poll() is None, log.read_text(errors='replace')
                    with socket.create_connection(('127.0.0.1', local), timeout=2): return True
                wait(ready); yield local
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                logs[label] = log.read_text(errors='replace')

    def socks(port, command, target):
        stream = socket.create_connection(('127.0.0.1', port), timeout=5); stream.settimeout(5)
        stream.sendall(b'\5\1\0'); assert receive(stream, 2) == b'\5\0'
        stream.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(target[0]) + struct.pack('!H', target[1]))
        head = receive(stream, 4); assert head[:2] == b'\5\0' and head[3] == 1
        bound = socket.inet_ntoa(receive(stream, 4)), struct.unpack('!H', receive(stream, 2))[0]
        return stream, bound

    def tcp(local, size):
        stream, _ = socks(local, 1, origin.server_address)
        with stream:
            payload = bytes([29]) * size
            stream.sendall(payload); assert receive(stream, size) == payload
        return True

    def packet(index, size):
        ip, port = datagrams[index].server_address[:2]
        addr = b'\3\11localhost' if index == 1 else bytes([4 if ':' in ip else 1]) + socket.inet_pton(socket.AF_INET6 if ':' in ip else socket.AF_INET, ip)
        body = bytes([41+index]) * size
        return bytes(3) + addr + struct.pack('!H', port) + body, body

    def udp(local, index, size):
        control, relay = socks(local, 3, ('0.0.0.0', 0))
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            datagram.bind(('127.0.0.1', 0)); datagram.settimeout(5)
            wire, body = packet(index, size); datagram.sendto(wire, relay); response, sender = datagram.recvfrom(65536)
            assert sender == relay and response[:3] == bytes(3)
            end = 8 if response[3] == 1 else 20 if response[3] == 4 else 5 + response[4]
            assert struct.unpack('!H', response[end:end+2])[0] == datagrams[index].server_address[1]
            assert response[end+2:] == body
        return True

    def no_origin(wire, udp_packet=False, source='127.0.0.1'):
        wait(node_ready)
        with lock: before = (accepted[0], len(observed))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp_packet else socket.SOCK_STREAM) as sock:
            sock.bind((source, 0)); sock.settimeout(0.5)
            if udp_packet: sock.sendto(wire, ('127.0.0.1', node_port))
            else: sock.connect(('127.0.0.1', node_port)); sock.sendall(wire)
            try: returned = sock.recv(65536)
            except (OSError, EOFError): returned = b''
            assert not returned, 'Denied SS packet received data'
        time.sleep(0.1)
        with lock: assert (accepted[0], len(observed)) == before, 'Denied SS packet opened origin'

    def node_ready():
        # Readiness does not authenticate or count a proxy request.
        with socket.create_connection(('127.0.0.1', node_port), timeout=1): return True

    try:
        per_method = []
        for method in METHODS:
            for name in ['tls_settings', 'server_name', 'cert_config', 'flow', 'plugin', 'plugin_opts']: config.pop(name, None)
            config.update(protocol='shadowsocks', tls=0, cipher=method, routes=None)
            if method.startswith('2022-'): config['server_key'] = converted(method, 'server-unique-key')
            else: config.pop('server_key', None)
            before = traffic_snapshot(); run('start'); wait(node_ready)
            with client(method, method) as local:
                assert tcp(local, 131072)
                cases.append('installed-SS-' + method + '-official-Xray-multiframe-TCP-exact-payload')
                for index in range(3):
                    for size in [1, 37, 8000]: assert udp(local, index, size)
                cases.append('installed-SS-' + method + '-official-Xray-UDP-IPv4-domain-IPv6-exact-payload')
            with client(method, method+'-fragment', port=fragment.server_address[1]) as local: assert tcp(local, 37)
            cases.append('installed-SS-' + method + '-fragmented-client-fixed-header-TCP')
            with lock: origin_before = (accepted[0], len(observed))
            with client(method, method+'-wrong', identity='wrong-user-key') as local:
                try: tcp(local, 37)
                except (OSError, EOFError): pass
                else: raise AssertionError('Wrong SS password accepted')
                try: udp(local, 0, 37)
                except (OSError, EOFError): pass
                else: raise AssertionError('Wrong SS UDP password accepted')
            with lock: assert (accepted[0], len(observed)) == origin_before
            cases.append('installed-SS-' + method + '-wrong-user-denied-before-origin')
            after = traffic_snapshot(); expected = 131072 + 37 + 3*(1+37+8000)
            assert [after[i]-before[i] for i in range(2)] == [expected, expected], (method, before, after)
            cases.append('installed-SS-' + method + '-exact-TCP-UDP-payload-only-graceful-accounting')
            per_method.append({'method': method, 'payload_bytes_per_direction': expected, 'udp_address_types': ['IPv4','domain','IPv6'], 'TCP_initial_fragment_bytes': 3})
        config['cipher'] = 'aes-128-gcm'; config.pop('server_key', None); run('start')
        wait(node_ready)
        tcp_address = b'\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', origin.server_address[1])
        udp_address = b'\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', datagrams[0].server_address[1])
        tcp_wire = classic_tcp('aes-128-gcm', user, tcp_address, b'replay-probe')
        with socket.create_connection(('127.0.0.1', node_port), timeout=5) as sock:
            sock.settimeout(5); sock.sendall(tcp_wire); assert sock.recv(1024)
        no_origin(tcp_wire)
        udp_wire = classic_udp('aes-128-gcm', user, udp_address, b'replay-probe')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5); sock.sendto(udp_wire, ('127.0.0.1', node_port)); assert sock.recv(65536)
        no_origin(udp_wire, True)
        tampered = bytearray(classic_udp('aes-128-gcm', user, udp_address, b'corrupt')); tampered[-1] ^= 1
        no_origin(tampered, True)
        cases.append('installed-SS-independent-AEAD-TCP-and-UDP-replays-and-bad-tag-denied-before-origin')
        config['routes'] = [{'match': ['127.0.0.1'], 'action': 'block'}]; run('restart')
        before = traffic_snapshot(); run('start')
        no_origin(classic_tcp('aes-128-gcm', user, tcp_address, b'blocked'))
        no_origin(classic_udp('aes-128-gcm', user, udp_address, b'blocked'), True)
        assert traffic_snapshot() == before
        cases.append('installed-SS-TCP-UDP-blocked-route-no-origin-or-counted-payload')
        config['routes'] = None; run('start')
        with client('aes-128-gcm', 'before-hot-update') as local: wait(lambda: tcp(local, 37))
        pids = parent(), child_ids()
        replacement = 'replacement-user-key'
        users[:] = [{'id':1, 'uuid':replacement, 'speed_limit':0, 'device_limit':0}]
        with client('aes-128-gcm', 'replacement', identity=replacement) as local: wait(lambda: tcp(local, 37))
        no_origin(classic_tcp('aes-128-gcm', user, tcp_address, b'removed'))
        no_origin(classic_udp('aes-128-gcm', user, udp_address, b'removed'), True)
        assert (parent(), child_ids()) == pids
        cases.append('installed-SS-user-hot-replacement-preserves-controller-and-child-PIDs-and-removes-old-password')
        users[:] = copy.deepcopy(original_users)
        with client('aes-128-gcm', 'restored') as local: wait(lambda: tcp(local, 37))
        measurements['shadowsocks'] = {'client_version': version, 'client_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            'methods': per_method, 'real_independent_AEAD_replay_negatives': True, 'route_negatives': True,
            'hot_update_without_restart': True, 'server_runtime': 'installed Rust ELF', 'loopback_only': True,
            'client_logs_sha256': {name: hashlib.sha256(body.encode()).hexdigest() for name, body in logs.items()}}
    finally:
        users[:] = original_users; config.clear(); config.update(original)
        for server in [fragment, origin, *datagrams]: server.shutdown(); server.server_close()
