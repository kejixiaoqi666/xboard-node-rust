#!/usr/bin/env python3
"""Fresh systemd install with real TCP/TLS/UDP and live shared user limits."""
import argparse
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid

from test_installer import fixture_package, read_package

ROOT = Path(__file__).resolve().parents[1]
UNIT = 'xboard-node-rust.service'
CONFIG_DIR = Path('/etc/xboard-node-rust')
STATE_DIR = Path('/var/lib/xboard-node-rust')
LIB_DIR = Path('/usr/local/lib/xboard-node-rust')
CURRENT = LIB_DIR / 'current'
MARKER = CONFIG_DIR / '.managed-by'
TOKEN = 'systemd fixture "$\\quoted\' Unicode-Ω'
USER = '00000000-0000-4000-8000-000000000001'
PAYLOAD = b'real-installed-rust-proxy-' * 511
sha = lambda body: hashlib.sha256(body).hexdigest()


def systemctl(*args, check=True):
    return subprocess.run(['systemctl', *args], check=check, capture_output=True, text=True)


def wait(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate(): return
        except (OSError, EOFError, ValueError, AssertionError, subprocess.CalledProcessError):
            pass
        time.sleep(0.1)
    raise AssertionError('Bounded systemd/business condition timed out')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part: raise EOFError('Proxy closed early')
        result.extend(part)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'package', 'checksums', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--previous-package', type=Path)
    parser.add_argument('--previous-checksums', type=Path)
    args = parser.parse_args()
    assert bool(args.previous_package) == bool(args.previous_checksums)
    assert os.geteuid() == 0 and Path('/run/systemd/system').is_dir()
    managed_paths = [CONFIG_DIR, STATE_DIR, LIB_DIR, Path('/usr/local/bin/xboard-rust'),
        Path('/usr/local/bin/xboard-node-rust'), Path('/etc/systemd/system') / UNIT]
    assert all(not p.exists() and not p.is_symlink() for p in managed_paths), 'Refuse to change an existing installation'
    existing_units = ['nginx.service', 'ssh.service', 'sshd.service']
    before = {unit: systemctl('show', unit, '-p', 'MainPID', '-p', 'ActiveState', check=False).stdout for unit in existing_units}
    cases, reports, measurements = [], [], {}
    files = read_package(args.package)
    assert sha(args.binary.read_bytes()) == json.loads(files['BUILDINFO.json'])['binary_sha256']
    with tempfile.TemporaryDirectory(prefix='xbr-systemd-test-') as temp:
        temp = Path(temp)
        node_port = free_port()
        config = {'protocol': 'vless', 'server_port': node_port, 'listen_ip': '127.0.0.1',
            'node_id': 7, 'base_config': {'pull_interval': 30, 'push_interval': 60}, 'network': '', 'routes': None}
        users = [{'id': 1, 'uuid': USER, 'speed_limit': 0, 'device_limit': 0}]

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(20)
                while True:
                    body = self.request.recv(65536)
                    if not body: return
                    self.request.sendall(body)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        echo = Server(('127.0.0.1', 0), Echo)
        echo_port = echo.server_address[1]

        class DatagramEcho(socketserver.BaseRequestHandler):
            def handle(self):
                body, sock = self.request
                sock.sendto(body, self.client_address)

        class DatagramServer(socketserver.ThreadingUDPServer):
            daemon_threads = True
            max_packet_size = 65536

        class DatagramServer6(DatagramServer):
            address_family = socket.AF_INET6

        udp_origins = [DatagramServer(('127.0.0.1', 0), DatagramEcho),
            DatagramServer(('127.0.0.1', 0), DatagramEcho), DatagramServer6(('::1', 0), DatagramEcho)]

        class Panel(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def reply(self, body):
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
            def do_GET(self):
                request = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(request.query)
                if query.get('token') != [TOKEN] or query.get('node_id') != ['7'] or query.get('machine_id') != ['1']:
                    self.send_error(403); return
                if request.path == '/api/v2/server/config': self.reply(config)
                elif request.path == '/api/v2/server/user': self.reply({'users': users})
                else: self.send_error(404)
            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536: self.send_error(400); return
                body = json.loads(self.rfile.read(length))
                if body.get('token') != TOKEN or body.get('node_id') != 7 or body.get('machine_id') != 1:
                    self.send_error(403); return
                if self.path == '/api/v2/server/handshake': self.reply({'websocket': {'enabled': False, 'ws_url': ''}})
                elif self.path == '/api/v2/server/report':
                    reports.append(body.get('traffic', {})); self.reply({'data': True})
                else: self.send_error(404)

        panel = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Panel)
        panel.daemon_threads = True
        for server in [echo, panel, *udp_origins]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        token = temp / 'token'; token.write_text(TOKEN); token.chmod(0o600)

        def run(action, *options, success=True, environment=None):
            proc = subprocess.run(['bash', str(ROOT / 'install.sh'), action, '--yes', *map(str, options)],
                capture_output=True, text=True, timeout=90, env=environment)
            if (proc.returncode == 0) != success:
                details = systemctl('show', UNIT, '-p', 'Result', '-p', 'ActiveState', '-p', 'ExecMainStatus', check=False).stdout
                raise AssertionError((action + ': ' + proc.stdout + proc.stderr + details).replace(TOKEN, '[FIXTURE_TOKEN]'))
            return proc

        def parent():
            return int(systemctl('show', UNIT, '-p', 'MainPID', '--value').stdout.strip())

        def child_ids():
            result = set()
            for path in (Path('/proc') / str(parent()) / 'task').glob('*/children'):
                result.update(path.read_text().split())
            assert result
            return result

        def running_binary(expected_hash, phase):
            executable = CURRENT / 'bin/xboard-node-rust'
            assert sha(executable.read_bytes()) == expected_hash
            pid = parent()
            native_children = child_ids()
            actual = {}
            for process in [str(pid), *sorted(native_children)]:
                image = Path('/proc') / process / 'exe'
                assert image.samefile(executable), (phase, process, 'running inode differs')
                digest = sha(image.read_bytes())
                assert digest == expected_hash, (phase, process, 'running ELF hash differs')
                actual[process] = digest
            measurements.setdefault('running_version_stages', []).append({
                'phase': phase, 'controller_pid': pid, 'native_child_pids': sorted(native_children),
                'running_ELF_sha256_by_pid': actual, 'expected_binary_sha256': expected_hash})

        def connect(tls=False, source='127.0.0.1'):
            stream = socket.create_connection(('127.0.0.1', node_port), timeout=8, source_address=(source, 0))
            stream.settimeout(8)
            if tls:
                context = ssl.create_default_context(cafile=str(temp / 'cert.pem'))
                stream = context.wrap_socket(stream, server_hostname='localhost')
            return stream

        def tcp_session(protocol='vless', tls=False, source='127.0.0.1'):
            stream = connect(tls, source)
            try:
                if protocol == 'vless':
                    head = b'\0' + uuid.UUID(USER).bytes + b'\0\1' + struct.pack('!H', echo_port) + b'\1' + socket.inet_aton('127.0.0.1')
                    stream.sendall(head)
                    assert receive(stream, 2) == b'\0\0'
                else:
                    head = hashlib.sha224(USER.encode()).hexdigest().encode() + b'\r\n\1\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo_port) + b'\r\n'
                    stream.sendall(head)
                return stream
            except BaseException:
                stream.close()
                raise

        def echo_bytes(stream, body):
            stream.sendall(body)
            assert receive(stream, len(body)) == body

        def fetch(protocol='vless', tls=False):
            with tcp_session(protocol, tls) as stream:
                echo_bytes(stream, PAYLOAD)
                return True

        def live_limits():
            nonlocal users
            runtime_path = CONFIG_DIR / 'runtime.json'
            runtime = json.loads(runtime_path.read_text())
            runtime['poll_seconds'] = 1
            runtime_path.write_text(json.dumps(runtime) + '\n')
            runtime_path.chmod(0o600)
            run('restart'); wait(fetch)
            original_pid, original_children = parent(), child_ids()
            a = tcp_session(source='127.0.0.1')
            b = tcp_session(source='127.0.0.2')
            try:
                echo_bytes(a, b'already-established-A')
                echo_bytes(b, b'already-established-B')
                users = [{'id': 1, 'uuid': USER, 'speed_limit': 1, 'device_limit': 1}]

                def denied():
                    try:
                        with tcp_session(source='127.0.0.3') as extra:
                            echo_bytes(extra, b'new-distinct-IP-probe')
                        return False
                    except (EOFError, ConnectionResetError, BrokenPipeError):
                        return True

                wait(denied)
                # Lowering the allowance retains established connections; a new
                # connection from an already active IP does not consume a slot.
                echo_bytes(a, b'A-still-live')
                echo_bytes(b, b'B-still-live')
                with tcp_session(source='127.0.0.1') as same_ip:
                    echo_bytes(same_ip, b'same-IP-another-connection')
                assert parent() == original_pid and child_ids() == original_children
                cases.append('live-distinct-IP-gate-same-IP-sharing-and-lowered-limit-retains-established-sessions')

                body = b'R' * (96 * 1024)
                started = time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    jobs = [pool.submit(echo_bytes, stream, body) for stream in [a, b]]
                    for job in jobs: job.result(timeout=8)
                elapsed = time.monotonic() - started
                # Both directions of both connections share 125000 bytes/sec
                # and at most one second of burst; per-connection buckets would
                # finish far below this lower bound on the same loopback path.
                assert 1.8 <= elapsed <= 8, f'aggregate limit took {elapsed:.3f}s'
                measurements['shared_1Mbps_two_connection_echo'] = {
                    'payload_bytes_each_way_per_connection': len(body), 'combined_payload_bytes': 4 * len(body),
                    'seconds': elapsed, 'expected_bytes_per_second': 125000, 'initial_burst_bytes': 125000}
                cases.append('real-two-connection-bidirectional-payload-obeys-one-shared-1Mbps-budget')

                users = [{'id': 1, 'uuid': USER, 'speed_limit': 0, 'device_limit': 0}]

                def live_unlimited():
                    started = time.monotonic()
                    echo_bytes(a, b'U' * (128 * 1024))
                    duration = time.monotonic() - started
                    measurements['same_session_after_live_unlimited_seconds'] = duration
                    return duration < 0.6

                wait(live_unlimited)
                assert parent() == original_pid and child_ids() == original_children
                cases.append('hot-unlimited-policy-applies-to-existing-stream-without-restarting-controller-or-native-child')

                # Restore a single-IP limit before disconnecting the existing
                # streams, then prove a new source gets the freed allowance.
                users = [{'id': 1, 'uuid': USER, 'speed_limit': 0, 'device_limit': 1}]
                wait(denied)
            finally:
                a.close(); b.close()

            def released():
                with tcp_session(source='127.0.0.3') as new_source:
                    echo_bytes(new_source, b'last-reference-released')
                return True

            wait(released)
            assert parent() == original_pid and child_ids() == original_children
            cases.append('closing-last-sessions-releases-IP-slot-for-a-new-source')
            users = [{'id': 1, 'uuid': USER, 'speed_limit': 0, 'device_limit': 0}]

        def udp_roundtrip(protocol):
            # TLS authenticates the same installed native process used by TCP.
            # Trojan uses one association for multiple IPv4 ports, a domain and
            # IPv6; VLESS creates one fixed-destination session per endpoint.
            shared = connect(True) if protocol == 'trojan' else None
            try:
                if shared:
                    shared.sendall(hashlib.sha224(USER.encode()).hexdigest().encode() + b'\r\n\3\1' + b'\0' * 6 + b'\r\n')
                for index, origin in enumerate(udp_origins):
                    ip, port = origin.server_address[:2]
                    packed = socket.inet_pton(socket.AF_INET6 if ':' in ip else socket.AF_INET, ip)
                    domain = index == 1
                    address = bytes([3 if protocol == 'trojan' else 2, 9]) + b'localhost' if domain else bytes([4 if ':' in ip else 1]) + packed
                    # VLESS IPv6 uses address type 3, unlike Trojan's type 4.
                    if protocol == 'vless' and ':' in ip: address = b'\3' + packed
                    stream = shared or connect(True)
                    try:
                        if protocol == 'vless':
                            stream.sendall(b'\0' + uuid.UUID(USER).bytes + b'\0\2' + struct.pack('!H', port) + address)
                            assert receive(stream, 2) == b'\0\0'
                        for size in [0, 37, 65507]:
                            body = bytes([index + 31]) * size
                            framing = struct.pack('!H', size) if protocol == 'vless' else address + struct.pack('!HH', port, size) + b'\r\n'
                            stream.sendall(framing + body)
                            if protocol == 'trojan':
                                kind = receive(stream, 1)[0]
                                assert kind in [1, 4]
                                reply_ip = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, receive(stream, 4 if kind == 1 else 16))
                                reply_port = struct.unpack('!H', receive(stream, 2))[0]
                                assert reply_ip == ip and reply_port == port
                            reply_size = struct.unpack('!H', receive(stream, 2))[0]
                            if protocol == 'trojan': assert receive(stream, 2) == b'\r\n'
                            assert reply_size == size, (protocol, ip, size, reply_size)
                            assert receive(stream, size) == body, (protocol, ip, size, 'payload differs')
                    finally:
                        if shared is None: stream.close()
            finally:
                if shared is not None: shared.close()
            cases.append('installed-' + protocol + '-TLS-UDP-real-IPv4-domain-IPv6-zero-and-maximum-datagrams')

        installed = False
        try:
            run('install', '--package', args.package.resolve(), '--checksums', args.checksums.resolve(),
                '--panel', 'http://127.0.0.1:' + str(panel.server_port), '--node-id', '7', '--machine-id', '1', '--token-file', token)
            installed = True
            wait(fetch)
            pid = parent()
            executable = CURRENT / 'bin/xboard-node-rust'
            assert (Path('/proc') / str(pid) / 'exe').samefile(executable)
            environment = (Path('/proc') / str(pid) / 'environ').read_bytes().split(b'\0')
            assert b'XBORD_PANEL_TOKEN=' + TOKEN.encode() in environment
            children = set()
            for path in (Path('/proc') / str(pid) / 'task').glob('*/children'):
                children.update(path.read_text().split())
            assert children
            for child in children:
                assert (Path('/proc') / child / 'exe').samefile(executable)
                assert not any(item.startswith(b'XBORD_PANEL_TOKEN=') for item in (Path('/proc') / child / 'environ').read_bytes().split(b'\0'))
            cases.append('installed-systemd-parent-and-child-run-exact-rust-ELF-with-token-stripped-in-child')
            cases.append('quoted-Unicode-systemd-EnvironmentFile-credential-roundtrip')
            cases.append('installed-loopback-panel-to-native-VLESS-to-real-echo-bytes')
            # Reproduce the real systemd start limit with direct starts, then
            # verify that an explicit manager start recovers only this unit.
            systemctl('stop', UNIT)
            systemctl('reset-failed', UNIT)
            for _ in range(5):
                systemctl('start', UNIT)
                wait(fetch)
                systemctl('stop', UNIT)
            blocked = systemctl('start', UNIT, check=False)
            assert blocked.returncode != 0
            assert systemctl('show', UNIT, '-p', 'Result', '--value').stdout.strip() == 'start-limit-hit'
            run('start'); wait(fetch)
            cases.append('real-systemd-start-limit-reproduced-and-explicit-manager-start-recovers')
            if args.previous_package:
                prior = read_package(args.previous_package)
                prior_info = json.loads(prior['BUILDINFO.json'])
                assert prior_info['version'] == 'v0.1.0-preview.1'
                assert prior_info['commit'] == 'cb3f01fc6a7cefa0afa43fc4a46b3cd9d597304f'
                assert prior_info['binary_sha256'] != sha(args.binary.read_bytes())
                assert prior_info['state_format'] == json.loads(files['BUILDINFO.json'])['state_format']
                run('stop')
                book = json.loads((STATE_DIR / 'native-traffic.json').read_text())
                config_hashes = {name: sha((CONFIG_DIR / name).read_bytes()) for name in ['runtime.json', 'panel.env']}
                run('update', '--package', args.previous_package.resolve(), '--checksums', args.previous_checksums.resolve())
                wait(fetch)
                running_binary(prior_info['binary_sha256'], 'switch-to-published-preview1')
                run('update', '--package', args.package.resolve(), '--checksums', args.checksums.resolve())
                wait(fetch)
                running_binary(sha(args.binary.read_bytes()), 'upgrade-actual-preview1-to-new')
                run('rollback'); wait(fetch)
                running_binary(prior_info['binary_sha256'], 'rollback-to-actual-preview1')
                run('rollback'); wait(fetch)
                running_binary(sha(args.binary.read_bytes()), 'rollback-again-to-new')
                run('stop')
                after_book = json.loads((STATE_DIR / 'native-traffic.json').read_text())
                assert all(book[key] == after_book[key] for key in ['version', 'destination', 'epoch'])
                assert after_book['sequence'] > book['sequence']
                assert config_hashes == {name: sha((CONFIG_DIR / name).read_bytes()) for name in config_hashes}
                run('start'); wait(fetch)
                measurements['actual_previous_release'] = {
                    'version': prior_info['version'], 'commit': prior_info['commit'],
                    'previous_binary_sha256': prior_info['binary_sha256'], 'new_binary_sha256': sha(args.binary.read_bytes()),
                    'native_counter_epoch_retained': True, 'sequence_before': book['sequence'], 'sequence_after': after_book['sequence']}
                cases.append('actual-preview1-to-new-binary-upgrade-and-two-way-rollback-preserve-config-and-native-counter-identity')
            live_limits()
            # PrivateTmp hides /tmp from the service; test TLS material lives in its managed state directory.
            cert = STATE_DIR / 'fixture-cert.pem'; key = STATE_DIR / 'fixture-key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            shutil.copy2(cert, temp / 'cert.pem')
            config.update(tls=1, server_name='localhost', cert_config={'cert_mode': 'file', 'cert_file': str(cert), 'key_file': str(key)})
            run('restart'); wait(lambda: fetch(tls=True))
            cases.append('installed-native-VLESS-file-TLS-with-verified-certificate')
            udp_roundtrip('vless')
            config['protocol'] = 'trojan'
            run('restart'); wait(lambda: fetch('trojan', True))
            cases.append('installed-native-Trojan-file-TLS-with-real-echo-bytes')
            udp_roundtrip('trojan')
            config['protocol'] = 'vless'; config.pop('tls'); config.pop('server_name'); config.pop('cert_config')
            run('restart'); wait(fetch)
            before_hashes = {name: sha((CONFIG_DIR / name).read_bytes()) for name in ['runtime.json', 'panel.env']}
            replacement, replacement_sums = fixture_package(temp / 'replacement', files, 'v0.1.0-systemd-fixture.2')
            run('update', '--package', replacement, '--checksums', replacement_sums)
            wait(fetch)
            assert (CURRENT / 'VERSION').read_text().strip() == 'v0.1.0-systemd-fixture.2'
            assert before_hashes == {name: sha((CONFIG_DIR / name).read_bytes()) for name in before_hashes}
            cases.append('systemd-upgrade-real-forwarding-and-config-retention')
            run('rollback'); wait(fetch)
            assert (CURRENT / 'VERSION').read_bytes() == files['VERSION']
            cases.append('systemd-program-rollback-real-forwarding')
            # Inject failure at the systemctl start boundary without changing other services.
            shim = temp / 'shim'; shim.mkdir()
            real_systemctl = shutil.which('systemctl')
            once = temp / 'start-failed-once'
            (shim / 'systemctl').write_text('#!/bin/bash\nif [[ $1 == start && $2 == xboard-node-rust.service && ! -e ' + str(once) + ' ]]; then touch ' + str(once) + '; exit 17; fi\nexec ' + real_systemctl + ' "$@"\n')
            (shim / 'systemctl').chmod(0o755)
            failure, failure_sums = fixture_package(temp / 'failure', files, 'v0.1.0-systemd-fixture.3')
            injected = dict(os.environ, PATH=str(shim) + ':' + os.environ['PATH'])
            run('update', '--package', failure, '--checksums', failure_sums, success=False, environment=injected)
            assert once.exists() and (CURRENT / 'VERSION').read_bytes() == files['VERSION']
            wait(fetch)
            cases.append('injected-systemd-start-failure-restores-old-program-and-real-forwarding')
            real_mv = shutil.which('mv')
            commit_once = temp / 'metadata-commit-failed-once'
            (shim / 'mv').write_text('#!/bin/bash\nlast=${!#}\nif [[ $last == /usr/local/bin/xboard-rust && ! -e ' + str(commit_once) + ' ]]; then touch ' + str(commit_once) + '; exit 19; fi\nexec ' + real_mv + ' "$@"\n')
            (shim / 'mv').chmod(0o755)
            commit_failure, commit_sums = fixture_package(temp / 'commit-failure', files, 'v0.1.0-systemd-fixture.4')
            run('update', '--package', commit_failure, '--checksums', commit_sums, success=False, environment=injected)
            assert commit_once.exists() and (CURRENT / 'VERSION').read_bytes() == files['VERSION']
            assert Path('/usr/local/bin/xboard-rust').read_bytes() == files['install.sh']
            wait(fetch)
            cases.append('injected-manager-commit-failure-restores-coherent-old-manager-program-and-service')
            final_children = set()
            for path in (Path('/proc') / str(parent()) / 'task').glob('*/children'):
                final_children.update(path.read_text().split())
            assert final_children
            run('stop')
            assert parent() == 0
            for child in children | final_children:
                assert not (Path('/proc') / child).exists()
            assert any(reports)
            cases.append('graceful-systemd-stop-child-cleanup-and-synthetic-report')
            run('traffic-status')
            run('uninstall')
            installed = False
            assert CONFIG_DIR.exists() and STATE_DIR.exists() and not CURRENT.is_symlink()
            assert all(before[unit] == systemctl('show', unit, '-p', 'MainPID', '-p', 'ActiveState', check=False).stdout for unit in existing_units)
            cases.append('uninstall-retains-data-and-preexisting-service-identities')
        finally:
            if installed or (Path('/etc/systemd/system') / UNIT).exists():
                if MARKER.exists() and MARKER.read_text().strip() == 'kejixiaoqi666/xboard-node-rust':
                    run('uninstall', success=True)
            # These directories were absent before this test and contain only synthetic fixture data.
            for path in [CONFIG_DIR, STATE_DIR, LIB_DIR]:
                if path.exists():
                    assert not path.is_symlink() and path in managed_paths
                    shutil.rmtree(path)
            for server in [panel, echo, *udp_origins]:
                server.shutdown(); server.server_close()
    report = {'result': 'PASS', 'scope': 'Fresh exact-asset Linux systemd install, synthetic Xboard v2 panel, real TCP/TLS/UDP IPv4/IPv6, shared-rate timing and live source-IP policy; no production panel or billing validation',
        'measurements': measurements,
        'cases': cases, 'binary_sha256': sha(args.binary.read_bytes()), 'package_sha256': sha(args.package.read_bytes()), 'installer_sha256': sha((ROOT / 'install.sh').read_bytes()),
        'temporary_service_removed': True, 'managed_fixture_data_removed': True, 'existing_service_identities_preserved': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'cases': len(cases), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
