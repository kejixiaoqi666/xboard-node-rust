"""Real installed-ELF DNS, routing and SOCKS5 checks, imported by test_systemd."""
import collections
import json
import socket
import socketserver
import struct
import threading
import time
import uuid


def receive(stream, size):
    body = bytearray()
    while len(body) < size:
        part = stream.recv(size - len(body))
        if not part:
            raise ConnectionError('unexpected EOF')
        body.extend(part)
    return bytes(body)


def exercise(config, runtime_path, run, wait, fetch, connect, parent, child_ids,
             cases, measurements, echo_port, udp_origin, user):
    counts, lock = collections.Counter(), threading.Lock()
    targets = []

    def dns_answer(query, transport):
        cursor, labels = 12, []
        while query[cursor]:
            size = query[cursor]
            labels.append(query[cursor + 1:cursor + 1 + size].decode().lower())
            cursor += size + 1
        name = '.'.join(labels)
        qtype, qclass = struct.unpack('!HH', query[cursor + 1:cursor + 5])
        question = query[12:cursor + 5]
        with lock:
            counts[transport + ':' + name] += 1
        if name == 'truncated.test' and transport == 'udp':
            return query[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 0) + question
        if name in ['missing.test', 'localhost']:
            return query[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 0, 0) + question
        if qtype != 1 or qclass != 1:
            return query[:2] + struct.pack('!HHHHH', 0x8180, 1, 0, 0, 0) + question
        ip = '127.0.0.2' if name == 'private.test' else '127.0.0.1'
        ttl = 1 if name == 'ttl.test' else 60
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, ttl, 4) + socket.inet_aton(ip)
        return query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question + answer

    class UDP(socketserver.ThreadingUDPServer):
        daemon_threads = True

    class TCP(socketserver.ThreadingTCPServer):
        daemon_threads = True

    class DNSUDP(socketserver.BaseRequestHandler):
        def handle(self):
            query, stream = self.request
            stream.sendto(dns_answer(query, 'udp'), self.client_address)

    class DNSTCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            try:
                while True:
                    size = struct.unpack('!H', receive(self.request, 2))[0]
                    answer = dns_answer(receive(self.request, size), 'tcp')
                    self.request.sendall(struct.pack('!H', len(answer)) + answer)
            except (OSError, ConnectionError):
                pass

    class Socks(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            try:
                assert receive(self.request, 3) == b'\5\1\2'
                self.request.sendall(b'\5\2')
                assert receive(self.request, 1) == b'\1'
                username = receive(self.request, receive(self.request, 1)[0])
                password = receive(self.request, receive(self.request, 1)[0])
                assert username == b'fixture-user' and password == b'fixture-password'
                self.request.sendall(b'\1\0')
                header = receive(self.request, 4)
                assert header == b'\5\1\0\1', 'Routing must pass the pinned IPv4, not re-resolve at SOCKS'
                ip = socket.inet_ntoa(receive(self.request, 4))
                port = struct.unpack('!H', receive(self.request, 2))[0]
                with lock:
                    targets.append([ip, port])
                assert (ip, port) == ('127.0.0.1', echo_port)
                with socket.create_connection((ip, port), timeout=8) as origin:
                    self.request.sendall(b'\5\0\0\1' + b'\0' * 6)
                    while True:
                        body = self.request.recv(65536)
                        if not body:
                            return
                        origin.sendall(body)
                        self.request.sendall(receive(origin, len(body)))
            except (OSError, ConnectionError):
                pass

    class PrivateOrigin(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(8)
            try:
                while True:
                    body = self.request.recv(65536)
                    if not body:
                        return
                    with lock:
                        counts['private-origin-bytes'] += len(body)
                    self.request.sendall(body)
            except OSError:
                pass

    dns_udp = UDP(('127.0.0.1', 0), DNSUDP)
    dns_tcp = TCP(dns_udp.server_address, DNSTCP)
    socks = TCP(('127.0.0.1', 0), Socks)
    private_origin = TCP(('127.0.0.2', echo_port), PrivateOrigin)
    servers = [dns_udp, dns_tcp, socks, private_origin]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    runtime_before = runtime_path.read_bytes()
    runtime = json.loads(runtime_before)
    runtime['poll_seconds'] = 1
    runtime['dns'] = {'servers': ['127.0.0.1:' + str(dns_udp.server_address[1])],
        'strategy': 'ipv4_only', 'timeout_ms': 1000, 'cache_size': 64,
        'hosts': {'static.test': ['127.0.0.1']}}

    def save_dns():
        runtime_path.write_text(json.dumps(runtime) + '\n')
        runtime_path.chmod(0o600)
        run('restart')
        wait(fetch)

    def request(name, port=echo_port, udp=False, stream=None):
        stream = stream or connect()
        raw = name.encode()
        stream.sendall(b'\0' + uuid.UUID(user).bytes + bytes([0, 2 if udp else 1])
            + struct.pack('!H', port) + bytes([2, len(raw)]) + raw)
        assert receive(stream, 2) == b'\0\0'
        body = b'routed-dns-payload' * 128
        stream.sendall((struct.pack('!H', len(body)) if udp else b'') + body)
        if udp:
            assert struct.unpack('!H', receive(stream, 2))[0] == len(body)
        assert receive(stream, len(body)) == body
        return stream

    def roundtrip(name, **options):
        with connect() as stream:
            request(name, stream=stream, **options)
        return True

    def denied(name, **options):
        try:
            roundtrip(name, **options)
        except (ConnectionError, ConnectionResetError, BrokenPipeError):
            return True
        return False

    try:
        save_dns()
        roundtrip('cached.test'); roundtrip('cached.test')
        assert counts['udp:cached.test'] == 1
        roundtrip('static.test')
        assert not any(key.endswith(':static.test') for key in counts)
        roundtrip('ttl.test'); before = counts['udp:ttl.test']
        time.sleep(1.1); roundtrip('ttl.test')
        assert counts['udp:ttl.test'] > before
        assert denied('missing.test')
        assert denied('localhost'), 'An OS-resolvable name must not bypass custom NXDOMAIN'
        fetch()
        roundtrip('udp.test', port=udp_origin[1], udp=True)
        cases.append('installed-shared-DNS-cache-TTL-expiry-static-hosts-NXDOMAIN-and-TCP-UDP-origin-payload')
        roundtrip('truncated.test')
        assert counts['udp:truncated.test'] >= 1 and counts['tcp:truncated.test'] >= 1
        runtime['dns']['tcp_only'] = True; save_dns()
        roundtrip('tcp-only.test')
        assert counts['tcp:tcp-only.test'] >= 1 and counts['udp:tcp-only.test'] == 0
        cases.append('installed-DNS-UDP-truncation-falls-back-to-TCP-and-explicit-TCP-only-works')

        roundtrip('private.test')
        private_bytes_before_block = counts['private-origin-bytes']
        assert private_bytes_before_block > 0

        original_pid, old_children = parent(), child_ids()
        config['custom_outbounds'] = [{'tag': 'upstream', 'protocol': 'socks', 'settings': {
            'server': '127.0.0.1', 'server_port': socks.server_address[1],
            'username': 'fixture-user', 'password': 'fixture-password'}}]
        config['custom_routes'] = [
            {'domain_suffix': ['blocked.test'], 'outbound': 'block'},
            {'ip_cidr': ['127.0.0.2/32'], 'outbound': 'block'},
            {'domain': ['proxy.test'], 'outbound': 'upstream'},
        ]
        wait(lambda: child_ids() != old_children and roundtrip('proxy.test'))
        assert parent() == original_pid and targets[-1] == ['127.0.0.1', echo_port]
        assert denied('sub.blocked.test') and denied('private.test')
        assert counts['private-origin-bytes'] == private_bytes_before_block
        assert denied('proxy.test', port=udp_origin[1], udp=True)
        roundtrip('good.test'); roundtrip('good.test', port=udp_origin[1], udp=True)
        cases.append('installed-panel-route-update-replaces-child-keeps-controller-and-routes-TCP-via-authenticated-SOCKS5')
        cases.append('installed-domain-suffix-and-resolved-CIDR-blocks-and-proxied-UDP-refuses-direct-fallback')

        # Invalid new panel routes must preserve the current service and rule behavior.
        old_children = child_ids()
        config['custom_routes'].append({'domain_regex': ['.*'], 'outbound': 'block'})
        time.sleep(2.2)
        assert child_ids() == old_children and parent() == original_pid
        roundtrip('proxy.test'); assert denied('sub.blocked.test')
        config['custom_routes'].pop()
        cases.append('invalid-panel-route-keeps-prior-child-working-proxy-and-block-policy')

        # Actual TCP peer port is available to routing (not an invented fixed port).
        with connect() as endpoint:
            node_address = endpoint.getpeername()
        with socket.socket() as held:
            held.bind(('127.0.0.1', 0))
            held.settimeout(8)
            peer_port = held.getsockname()[1]
            config['custom_routes'].insert(0, {'source_port': [peer_port], 'outbound': 'block'})
            old_children = child_ids(); wait(lambda: child_ids() != old_children and fetch())
            held.connect(node_address)
            rejected = False
            try:
                request('good.test', stream=held)
            except (ConnectionError, ConnectionResetError, BrokenPipeError):
                rejected = True
            assert rejected, 'The actual matching source port must be blocked'
        roundtrip('good.test')
        cases.append('actual-client-source-port-is-blocked-while-other-client-ports-still-work')
        measurements['routing_dns'] = {'dns_requests': dict(counts), 'socks_pinned_destinations': targets,
            'controller_retained_during_panel_route_updates': True, 'invalid_route_retained_native_child': True}
    finally:
        for key in ['custom_outbounds', 'custom_routes']:
            config.pop(key, None)
        runtime_path.write_bytes(runtime_before)
        runtime_path.chmod(0o600)
        run('restart'); wait(fetch)
        for server in servers:
            server.shutdown(); server.server_close()
