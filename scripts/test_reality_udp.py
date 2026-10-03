"""Official Xray ordinary VLESS UDP over REALITY; no Vision, mux or XUDP."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
from test_vision import free_port, receive


def exercise(config, run, wait, cases, measurements, node_port, user, temp, reality, traffic_snapshot):
    logs, observed = {}, []
    lock = threading.Lock()

    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            body, sock = self.request
            with lock: observed.append(body)
            sock.sendto(body, self.client_address)
    class Server(socketserver.ThreadingUDPServer):
        daemon_threads = True
        max_packet_size = 65536
    class Server6(Server):
        address_family = socket.AF_INET6
    servers = [Server(('127.0.0.1', 0), Echo), Server(('127.0.0.1', 0), Echo), Server6(('::1', 0), Echo)]
    previous_routes = config.get('routes')
    for server in servers: threading.Thread(target=server.serve_forever, daemon=True).start()

    @contextlib.contextmanager
    def client(label, identity=user):
        port = free_port()
        profile = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
            'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}], 'outbounds': [{
            'protocol': 'vless', 'mux': {'enabled': False, 'concurrency': -1}, 'settings': {'vnext': [{
                'address': '127.0.0.1', 'port': node_port, 'users': [{'id': identity, 'encryption': 'none', 'flow': ''}]}]},
            'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': reality}}]}
        path = temp / ('xray-udp-' + label + '.json'); path.write_text(json.dumps(profile))
        log = temp / ('xray-udp-' + label + '.log')
        # In this pinned Xray version cone defaults to XUDP for non-DNS ports.
        # Official core/xray.go interprets this flag as cone disabled.
        environment = dict(os.environ, XRAY_CONE_DISABLED='true')
        with log.open('wb') as output:
            process = subprocess.Popen([os.environ['XRAY_TEST_BINARY'], 'run', '-c', str(path)],
                stdout=output, stderr=subprocess.STDOUT, env=environment)
            try:
                def ready():
                    assert process.poll() is None, log.read_text(errors='replace')
                    with socket.create_connection(('127.0.0.1', port), timeout=2): return True
                wait(ready)
                with socket.create_connection(('127.0.0.1', port), timeout=5) as control:
                    control.settimeout(5); control.sendall(b'\5\1\0'); assert receive(control, 2) == b'\5\0'
                    control.sendall(b'\5\3\0\1' + bytes(6))
                    head = receive(control, 4); assert head[:2] == b'\5\0' and head[3] == 1
                    address = socket.inet_ntoa(receive(control, 4)); target = struct.unpack('!H', receive(control, 2))[0]
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                        datagram.bind(('127.0.0.1', 0)); datagram.settimeout(4)
                        yield datagram, (address, target)
            finally:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                logs[label] = log.read_text(errors='replace')

    def packet(index, size):
        server = servers[index]; ip, port = server.server_address[:2]
        address = b'\3\11localhost' if index == 1 else bytes([4 if ':' in ip else 1]) + socket.inet_pton(socket.AF_INET6 if ':' in ip else socket.AF_INET, ip)
        body = bytes([31 + index]) * size
        return b'\0\0\0' + address + struct.pack('!H', port) + body, body, ip, port

    def roundtrip(datagram, relay, index, size):
        wire, body, ip, port = packet(index, size)
        datagram.sendto(wire, relay); reply, source = datagram.recvfrom(65536)
        assert source == relay and reply[:3] == bytes(3) and reply[3] in [1, 3, 4]
        if reply[3] == 3:
            end = 5 + reply[4]
            assert index == 1 and reply[5:end] == b'localhost'
        else:
            end = 8 if reply[3] == 1 else 20
            assert socket.inet_ntop(socket.AF_INET if reply[3] == 1 else socket.AF_INET6, reply[4:end]) == ip
        assert struct.unpack('!H', reply[end:end+2])[0] == port and reply[end+2:] == body

    try:
        config.pop('flow', None)
        before = traffic_snapshot(); run('start')
        for index, name in enumerate(['IPv4', 'domain', 'IPv6']):
            with client(name) as (datagram, relay):
                for size in [1, 37, 8000]: roundtrip(datagram, relay, index, size)
            cases.append('installed-REALITY-ordinary-VLESS-UDP-official-Xray-' + name + '-exact-payload')
        with lock: baseline = len(observed)
        with client('wrong-uuid', '00000000-0000-4000-8000-000000000999') as (datagram, relay):
            datagram.sendto(packet(0, 37)[0], relay)
            try: datagram.recvfrom(65536)
            except socket.timeout: pass
            else: raise AssertionError('Unauthorized UDP received a response')
        with lock: assert len(observed) == baseline, 'Unauthorized UDP reached origin'
        cases.append('installed-REALITY-UDP-wrong-UUID-denied-before-origin')
        config['routes'] = [{'match': ['127.0.0.1'], 'action': 'block'}]; run('restart')
        with client('blocked-route') as (datagram, relay):
            datagram.sendto(packet(0, 37)[0], relay)
            try: datagram.recvfrom(65536)
            except socket.timeout: pass
            else: raise AssertionError('Blocked REALITY UDP received a response')
        with lock: assert len(observed) == baseline, 'Blocked REALITY UDP reached origin'
        cases.append('installed-REALITY-UDP-blocked-route-denied-before-origin-and-not-counted')
        config['routes'] = previous_routes
        config['flow'] = 'xtls-rprx-vision'; run('restart')
        with client('missing-flow') as (datagram, relay):
            datagram.sendto(packet(0, 37)[0], relay)
            try: datagram.recvfrom(65536)
            except socket.timeout: pass
            else: raise AssertionError('Vision-only user accepted ordinary UDP')
        with lock: assert len(observed) == baseline
        cases.append('installed-REALITY-Vision-required-user-denies-ordinary-UDP')
        config.pop('flow', None); run('restart')
        with client('active-stop') as (datagram, relay):
            roundtrip(datagram, relay, 0, 37)
            run('stop')
        cases.append('installed-REALITY-UDP-active-association-cancelled-by-service-stop')
        run('start')
        with client('restart') as (datagram, relay): roundtrip(datagram, relay, 0, 37)
        cases.append('installed-REALITY-UDP-new-association-after-service-restart')
        after = traffic_snapshot()
        expected = 3 * (1 + 37 + 8000) + 2 * 37
        assert [after[i] - before[i] for i in range(2)] == [expected, expected], (before, after, expected)
        with lock: assert len(observed) == 11 and sum(map(len, observed)) == expected
        cases.append('installed-REALITY-UDP-exact-payload-counters-and-graceful-drain-exclude-framing-and-denied-packets')
        measurements['reality_udp'] = {'client_only': True, 'loopback_only': True,
            'client_binary_sha256': hashlib.sha256(Path(os.environ['XRAY_TEST_BINARY']).read_bytes()).hexdigest(),
            'flow': '', 'mux': False, 'cone_disabled': True, 'payload_sizes': [1, 37, 8000],
            'zero_datagram_unverified': 'Pinned Xray SOCKS drops empty datagrams',
            'maximum_datagram_unverified': 'Pinned Xray uses 8192-byte buffers',
            'wrong_uuid_origin_packets': 0, 'vision_required_origin_packets': 0,
            'blocked_route_origin_packets': 0,
            'expected_payload_bytes_per_direction': expected,
            'accounted_payload_bytes_per_direction': [after[i] - before[i] for i in range(2)],
            'accounting_scope': 'ACKed synthetic panel reports plus durable unsent pending/prepared queue; native counters drained',
            'client_logs_sha256': {label: hashlib.sha256(body.encode()).hexdigest() for label, body in logs.items()}}
    except BaseException:
        for label, body in logs.items(): print('Xray UDP ' + label + ':\n' + body[-16000:])
        raise
    finally:
        config.pop('flow', None)
        config['routes'] = previous_routes
        for server in servers: server.shutdown(); server.server_close()
