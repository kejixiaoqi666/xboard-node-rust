#!/usr/bin/env python3
"""Production Rust fleet entry against pinned official clients, loopback only.

The panel model is HTTP, not a mock Host or codec. This gate traverses actual
NodeRuntime -> production builder -> embedded native listeners -> payload/outbox.
Real Flash billing is a separate gate. No system service is installed here.
"""
import argparse
import contextlib
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import shutil
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
USER = '00000000-0000-4000-8000-000000000007'
TOKEN = 'loopback-fleet-fixture-token'
TCP_PAYLOAD = bytes(n % 251 for n in range(66000))
UDP_PAYLOAD = bytes(n % 239 for n in range(3000))
SHA = lambda body: hashlib.sha256(body).hexdigest()
USED_PORTS = set()


def receive(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise EOFError('client closed before complete payload')
        result.extend(part)
    return bytes(result)


def port():
    while True:
        with socket.socket() as listener, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            listener.bind(('127.0.0.1', 0))
            candidate = listener.getsockname()[1]
            if candidate in USED_PORTS:
                continue
            try:
                udp.bind(('127.0.0.1', candidate))
            except OSError:
                continue
            USED_PORTS.add(candidate)
            return candidate


def wait(condition, timeout=20):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if condition():
                return
        except (OSError, EOFError, ValueError) as error:
            last = type(error).__name__
        time.sleep(0.05)
    raise AssertionError('bounded loopback condition timed out: ' + str(last))


def pinned(binary, client):
    machine = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
    lock = json.loads((ROOT / 'crates/node-extended/tests/clients-lock.json').read_text())
    entry = next(item for item in lock['assets'] if item['client'] == client
                 and item['platform'] == 'linux-' + machine)
    actual = SHA(binary.read_bytes())
    assert actual == entry['binary_sha256'], 'official test executable SHA mismatch'
    version = subprocess.check_output([str(binary), 'version'], text=True, timeout=10)
    assert ('1.14.2' if client == 'sing-box' else '26.3.27') in version
    return actual


def preserve_failure(directory, output, error):
    """Keep a bounded, secret-free failure bundle before the temp directory is removed."""
    failure = Path(str(output) + '.failure')
    shutil.rmtree(failure, ignore_errors=True)
    failure.mkdir(mode=0o700, parents=True)
    candidates = [directory / 'runtime.log', directory / 'fleet.json']
    candidates.extend(directory.glob('*.client.log'))
    candidates.extend(directory.glob('*.client.json'))
    candidates.extend(directory.glob('node-*/*.json'))
    for source in candidates:
        if source.is_file() and source.stat().st_size <= 2 * 1024 * 1024:
            target = failure / source.relative_to(directory)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    (failure / 'error.txt').write_text(
        f'{type(error).__name__}: {error}\n', encoding='utf-8')
    return failure


class TcpEcho(socketserver.ThreadingTCPServer):
    daemon_threads = True


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            while body := self.request.recv(65536):
                self.request.sendall(body)
        except OSError:
            pass


class UdpEcho(socketserver.ThreadingUDPServer):
    daemon_threads = True
    max_packet_size = 65536


class DatagramEcho(socketserver.BaseRequestHandler):
    def handle(self):
        body, stream = self.request
        stream.sendto(body, self.client_address)


def socks(command, socks_port, target):
    stream = socket.create_connection(('127.0.0.1', socks_port), timeout=12)
    stream.settimeout(12)
    try:
        stream.sendall(b'\5\1\0')
        assert receive(stream, 2) == b'\5\0'
        stream.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(target[0])
                       + struct.pack('!H', target[1]))
        head = receive(stream, 4)
        assert head[:2] == b'\5\0', 'SOCKS command rejected'
        assert head[3] in [1, 4], 'unexpected SOCKS address type'
        host = socket.inet_ntop(socket.AF_INET if head[3] == 1 else socket.AF_INET6,
                               receive(stream, 4 if head[3] == 1 else 16))
        remote_port = struct.unpack('!H', receive(stream, 2))[0]
        if host in ['0.0.0.0', '::']:
            host = '127.0.0.1'
        return stream, (host, remote_port)
    except BaseException:
        stream.close()
        raise


@contextlib.contextmanager
def official(binary, outbound, directory, label):
    socks_port = port()
    profile = {'log': {'level': 'error'}, 'inbounds': [{'type': 'socks',
               'listen': '127.0.0.1', 'listen_port': socks_port}],
               'outbounds': [dict(outbound, tag='proxy')], 'route': {'final': 'proxy'}}
    config = directory / (label + '.client.json')
    config.write_text(json.dumps(profile))
    log = directory / (label + '.client.log')
    with log.open('wb') as output:
        child = subprocess.Popen([str(binary), 'run', '-c', str(config)],
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            def ready():
                assert child.poll() is None, 'client startup: ' + log.read_text(errors='replace')[-3000:]
                with socket.create_connection(('127.0.0.1', socks_port), timeout=1):
                    return True
            wait(ready)
            yield socks_port
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


def matrix(cert, key, reality):
    cases = []

    def add(label, protocol, tls=False, extra=None, client=None):
        number = len(cases) + 1
        node = {'protocol': protocol, 'server_port': port(), 'listen_ip': '127.0.0.1',
                'node_id': number, 'network': 'tcp', 'base_config': {'pull_interval': 30, 'push_interval': 1}}
        outbound = {'type': protocol, 'server': '127.0.0.1', 'server_port': node['server_port']}
        if protocol in ['vless', 'vmess']:
            outbound['uuid'] = USER
        elif protocol == 'tuic':
            outbound.update(uuid=USER, password=USER, congestion_control='cubic', udp_relay_mode='native')
        else:
            outbound['password'] = USER
        if protocol == 'vmess':
            node['cipher'] = 'aes-128-gcm'
            # The fleet gate sends one SOCKS UDP association to a loopback
            # target selected at runtime. XUDP carries that target per packet;
            # legacy VMess command=2 binds a connection to its header target
            # and is covered separately by the official codec matrix.
            outbound.update(security='aes-128-gcm', alter_id=0, packet_encoding='xudp')
        if protocol == 'shadowsocks':
            node['cipher'] = 'aes-128-gcm'
            outbound['method'] = 'aes-128-gcm'
        if tls:
            node.update(tls=1, server_name='localhost', cert_config={
                'cert_mode': 'file', 'cert_file': str(cert), 'key_file': str(key)})
            outbound['tls'] = {'enabled': True, 'server_name': 'localhost', 'certificate_path': str(cert)}
        if extra:
            node.update(extra)
        if client:
            outbound.update(client)
        cases.append({'label': label, 'node': node, 'outbound': outbound})

    for protocol in ['vless', 'vmess', 'trojan', 'shadowsocks', 'anytls', 'hysteria2', 'tuic']:
        add(protocol, protocol, protocol in ['trojan', 'anytls', 'hysteria2', 'tuic'])
    add('hysteria2-salamander', 'hysteria2', True,
        {'obfs': 'salamander', 'obfs-password': 'loopback-obfs-password'},
        {'obfs': {'type': 'salamander', 'password': 'loopback-obfs-password'}})
    add('tuic-quic-stream-udp', 'tuic', True, client={'udp_relay_mode': 'quic', 'zero_rtt_handshake': True})
    add('vision-file-tls-xudp', 'vless', True, {'flow': 'xtls-rprx-vision'},
        {'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp'})
    add('vision-reality-xudp', 'vless', False,
        {'tls': 2, 'flow': 'xtls-rprx-vision', 'server_name': 'localhost', 'tls_settings': reality['server']},
        {'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp', 'tls': reality['client']})
    for protocol in ['vless', 'vmess', 'trojan']:
        for kind in ['ws', 'httpupgrade', 'http', 'grpc']:
            settings = ({'serviceName': 'fixture.bridge', 'multiMode': False} if kind == 'grpc'
                        else {'path': '/bridge', 'host': 'localhost'})
            if kind == 'ws':
                settings = {'path': '/bridge', 'headers': {'Host': 'localhost'}}
            elif kind == 'http':
                settings['host'] = ['localhost']
            transport = ({'type': 'grpc', 'service_name': 'fixture.bridge'} if kind == 'grpc'
                         else {'type': kind, 'path': '/bridge'})
            if kind == 'ws':
                transport['headers'] = {'Host': 'localhost'}
            elif kind == 'httpupgrade':
                transport['host'] = 'localhost'
            elif kind == 'http':
                transport['host'] = ['localhost']
            add(protocol + '-' + kind, protocol, True, {'network': kind, 'networkSettings': settings},
                {'transport': transport})
    for protocol in ['vless', 'vmess', 'trojan', 'shadowsocks']:
        for mux in ['smux', 'yamux', 'h2mux']:
            add(protocol + '-' + mux, protocol, protocol == 'trojan',
                {'multiplex': {'enabled': True, 'max_streams': 8}},
                {'multiplex': {'enabled': True, 'protocol': mux, 'max_connections': 1, 'padding': True}})
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sing-box', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == 'Linux', 'Unix production entry must be executed on Linux'
    binary, client = args.binary.resolve(), args.sing_box.resolve()
    client_sha = pinned(client, 'sing-box')
    reports, lock, results = {}, threading.Lock(), []
    with tempfile.TemporaryDirectory(prefix='xbr-fleet-wire-') as temp:
        directory = Path(temp)
        directory.chmod(0o700)
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        key.chmod(0o600)
        mirror = TcpEcho(('127.0.0.1', 0), Echo)
        mirror_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        mirror_context.minimum_version = mirror_context.maximum_version = ssl.TLSVersion.TLSv1_3
        mirror_context.set_ecdh_curve('X25519')
        mirror_context.load_cert_chain(str(cert), str(key))
        accept = mirror.get_request
        mirror.get_request = lambda: (lambda pair: (mirror_context.wrap_socket(pair[0], server_side=True), pair[1]))(accept())
        keys = json.loads(subprocess.check_output([str(binary), 'generate-reality-keypair'], text=True, timeout=10))
        reality = {'server': dict(keys, server_name='localhost', short_id='1234567890abcdef',
                                 dest='127.0.0.1:' + str(mirror.server_address[1])),
                   'client': {'enabled': True, 'server_name': 'localhost', 'utls': {'enabled': True, 'fingerprint': 'chrome'},
                              'reality': {'enabled': True, 'public_key': keys['public_key'], 'short_id': '1234567890abcdef'}}}
        cases = matrix(cert, key, reality)
        nodes = {case['node']['node_id']: case['node'] for case in cases}

        class Panel(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, value):
                payload = json.dumps(value).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                request = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(request.query)
                node_id = int(query.get('node_id', ['0'])[0])
                if query.get('token') != [TOKEN] or node_id not in nodes:
                    self.send_error(403)
                elif request.path == '/api/v2/server/config':
                    self.reply(nodes[node_id])
                elif request.path == '/api/v2/server/user':
                    self.reply({'users': [{'id': 7, 'uuid': USER, 'speed_limit': 0, 'device_limit': 0}]})
                else:
                    self.send_error(404)

            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                assert 0 < length <= 1024 * 1024
                body = json.loads(self.rfile.read(length))
                node_id = body.get('node_id')
                if body.get('token') != TOKEN or node_id not in nodes:
                    self.send_error(403)
                elif self.path == '/api/v2/server/handshake':
                    self.reply({'websocket': {'enabled': False, 'ws_url': ''}})
                elif self.path == '/api/v2/server/report':
                    with lock:
                        reports.setdefault(node_id, []).append(body.get('traffic', {}))
                    self.reply({'data': True})
                else:
                    self.send_error(404)

        panel = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Panel)
        panel.daemon_threads = True
        tcp = TcpEcho(('127.0.0.1', 0), Echo)
        udp = UdpEcho(('127.0.0.1', 0), DatagramEcho)
        servers = [panel, tcp, udp, mirror]
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        runtimes = [{'panel_url': 'http://127.0.0.1:' + str(panel.server_address[1]),
                     'allow_loopback_http': True, 'token_env': 'XBR_LOOPBACK_TOKEN', 'node_id': node_id,
                     'machine_id': 1, 'state_dir': str(directory / ('node-' + str(node_id))),
                     'embedded': True, 'websocket': False, 'poll_seconds': 30, 'report_seconds': 1,
                     'traffic_reporting': True, 'traffic_checkpoint_ms': 100} for node_id in nodes]
        config = directory / 'fleet.json'
        config.write_text(json.dumps({'version': 1, 'nodes': runtimes}))
        environment = dict(os.environ, XBR_LOOPBACK_TOKEN=TOKEN)
        subprocess.run([str(binary), '--config', str(config), '--check'], env=environment,
                       check=True, capture_output=True, timeout=20)
        log = directory / 'runtime.log'
        with log.open('wb') as output:
            runtime = subprocess.Popen([str(binary), '--config', str(config)], env=environment,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            try:
                for case in cases:
                    label, number = case['label'], case['node']['node_id']
                    def ready():
                        assert runtime.poll() is None, 'fleet exited: ' + log.read_text(errors='replace')[-4000:]
                        return bool(list((directory / ('node-' + str(number))).glob('*.sock')))
                    wait(ready, 30)
                    with official(client, case['outbound'], directory, label) as socks_port:
                        try:
                            stream, _ = socks(1, socks_port, tcp.server_address)
                            with stream:
                                stream.sendall(TCP_PAYLOAD)
                                assert receive(stream, len(TCP_PAYLOAD)) == TCP_PAYLOAD
                            association, endpoint = socks(3, socks_port, ('0.0.0.0', 0))
                            with association, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                                datagram.settimeout(12)
                                frame = b'\0\0\0\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp.server_address[1]) + UDP_PAYLOAD
                                datagram.sendto(frame, endpoint)
                                returned = datagram.recv(65536)
                                assert returned[:10] == frame[:10] and returned[10:] == UDP_PAYLOAD
                        except BaseException as error:
                            raise AssertionError(label + ': ' + type(error).__name__ + '; runtime=' +
                                                 log.read_text(errors='replace')[-3000:] + '; client=' +
                                                 (directory / (label + '.client.log')).read_text(errors='replace')[-2000:]) from error
                    results.append({'node_id': number, 'case': label, 'tcp_each_direction': len(TCP_PAYLOAD),
                                    'udp_each_direction': len(UDP_PAYLOAD), 'result': 'PASS'})
                    print(label + ': actual fleet TCP66000/UDP3000 PASS', flush=True)
                children = set()
                for path in (Path('/proc') / str(runtime.pid) / 'task').glob('*/children'):
                    children.update(path.read_text().split())
                assert not children, 'embedded fleet retained an external data-plane process'
                runtime.send_signal(signal.SIGTERM)
                runtime.wait(timeout=15)
                assert runtime.returncode == 0, 'graceful fleet shutdown failed: ' + log.read_text(errors='replace')[-4000:]
                for result in results:
                    number = result['node_id']
                    state = directory / ('node-' + str(number))
                    native = json.loads((state / 'native-traffic.json').read_text())
                    outbox = json.loads((state / 'traffic.json').read_text())
                    flight = outbox.get('flight')
                    assert not flight or flight['stage'] != 'uncertain', 'loopback report lost acknowledgement'
                    with lock:
                        sent = list(reports.get(number, []))
                    totals = [sum(record.get('7', [0, 0])[direction] for record in sent)
                              + native['counters'].get('7', [0, 0])[direction]
                              + outbox['pending'].get('7', [0, 0])[direction]
                              + (flight['traffic'].get('7', [0, 0])[direction] if flight else 0)
                              for direction in range(2)]
                    assert totals == [69000, 69000], (result['case'], 'payload billing', totals)
                    assert not list(state.glob('*.sock')), 'control listener survived graceful stop'
                    result['accounted_each_direction'] = totals
            except BaseException as error:
                preserve_failure(directory, args.output, error)
                raise
            finally:
                if runtime.poll() is None:
                    runtime.terminate()
                    try:
                        runtime.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        runtime.kill()
                        runtime.wait(timeout=5)
                for server in servers:
                    server.shutdown()
                    server.server_close()
        receipt = {'result': 'PASS', 'scope': 'isolated production Rust embedded fleet, local HTTP panel model',
                   'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'binary_sha256': SHA(binary.read_bytes()), 'client_sha256': client_sha,
                   'case_count': len(results), 'single_rust_process': True,
                   'cases': results, 'limits': ['not a real panel billing test', 'not a WAN capacity benchmark']}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'result': 'PASS', 'case_count': len(results), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
