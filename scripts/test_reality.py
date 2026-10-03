"""REALITY acceptance on the actual installed Rust ELF, with a local TLS mirror."""
import json
import hashlib
import select
import socket
import socketserver
import ssl
import subprocess
import threading
from test_vision import exercise as vision_exercise, receive
from test_reality_udp import exercise as udp_exercise
from test_reality_key_update import exercise as key_update_exercise

def exercise(config, run, wait, cases, measurements, node_port, cert, key, user, temp, binary, traffic_snapshot):
    keys = json.loads(subprocess.check_output([str(binary), 'generate-reality-keypair'], text=True))
    class Mirror(socketserver.ThreadingTCPServer):
        daemon_threads = True
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(15)
            try:
                with self.server.tls.wrap_socket(self.request, server_side=True) as stream:
                    body = bytearray()
                    while b'\r\n\r\n' not in body and len(body) < 8192:
                        part = stream.recv(1024)
                        if not part: return
                        body.extend(part)
                    stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nfixed-reality-mirror!')
            except OSError: pass
    mirror = Mirror(('127.0.0.1', 0), Handler)
    mirror.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    mirror.tls.minimum_version = mirror.tls.maximum_version = ssl.TLSVersion.TLSv1_3
    mirror.tls.set_ecdh_curve('X25519')
    mirror.tls.load_cert_chain(str(cert), str(key))
    threading.Thread(target=mirror.serve_forever, daemon=True).start()
    fragmented = []
    class Fragment(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(20)
            try:
                with socket.create_connection(('127.0.0.1', node_port), timeout=20) as upstream:
                    header = receive(self.request, 5)
                    body = receive(self.request, int.from_bytes(header[3:5], 'big'))
                    assert header[0] == 22 and body[0] == 1
                    pieces = [body[:1], body[1:2], body[2:3], body[3:39], body[39:71], body[71:]]
                    assert all(pieces) and b''.join(pieces) == body
                    for piece in pieces:
                        upstream.sendall(header[:3] + len(piece).to_bytes(2, 'big') + piece)
                    fragmented.append(hashlib.sha256(body).hexdigest())
                    upstream.settimeout(20)
                    peers = {self.request: upstream, upstream: self.request}
                    while peers:
                        ready, _, _ = select.select(list(peers), [], [], 20)
                        if not ready: break
                        for source in ready:
                            target = peers[source]; data = source.recv(65536)
                            if data: target.sendall(data)
                            else:
                                target.shutdown(socket.SHUT_WR); del peers[source]
            except (OSError, EOFError): pass
    fragment = Mirror(('127.0.0.1', 0), Fragment)
    threading.Thread(target=fragment.serve_forever, daemon=True).start()
    previous = {k: config.get(k) for k in ['tls', 'tls_settings', 'server_name', 'cert_config', 'flow']}
    try:
        config.pop('cert_config', None)
        config.update(tls=2, server_name='localhost', tls_settings={'private_key': keys['private_key'],
            'public_key': keys['public_key'], 'server_name': 'localhost',
            'short_id': '1234567890abcdef', 'dest': '127.0.0.1:' + str(mirror.server_address[1])})
        run('restart')
        def ordinary_tls():
            context = ssl.create_default_context(cafile=str(cert))
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            with context.wrap_socket(socket.create_connection(('127.0.0.1', node_port), timeout=12), server_hostname='localhost') as stream:
                stream.settimeout(12); stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                body = bytearray()
                while True:
                    part = stream.recv(4096)
                    if not part: break
                    body.extend(part)
                assert body.endswith(b'fixed-reality-mirror!')
            return True
        wait(ordinary_tls)
        cases.append('installed-native-REALITY-ordinary-TLS-probe-fixed-mirror-with-trusted-certificate')
        client_settings = {'serverName': 'localhost', 'password': keys['public_key'], 'shortId': '1234567890abcdef', 'fingerprint': 'chrome'}
        vision_exercise(config, run, wait, cases, measurements, node_port, cert, key, user, temp, reality=client_settings)
        vision_exercise(config, run, wait, cases, measurements, fragment.server_address[1], cert, key, user, temp,
            reality=client_settings, variant='fragmented-')
        assert len(fragmented) >= 8
        measurements['reality_fragmented'].update(client_hello_record_count=6,
            actual_fragmented_client_hellos=len(fragmented), handshake_sha256=fragmented)
        udp_exercise(config, run, wait, cases, measurements, node_port, user, temp, client_settings, traffic_snapshot)
        key_update_exercise(config, run, wait, cases, measurements, node_port, user, temp, client_settings)
        measurements['reality'].update(fixed_mirror_tls13=True, ordinary_tls_probe_verified=True,
            no_vision_vless_verified=True, wrong_short_id_origin_connects=0)
    finally:
        for name, value in previous.items():
            if value is None: config.pop(name, None)
            else: config[name] = value
        fragment.shutdown(); fragment.server_close()
        mirror.shutdown(); mirror.server_close()
