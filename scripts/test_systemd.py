#!/usr/bin/env python3
"""Fresh systemd installation with a synthetic loopback panel and real TCP/TLS."""
import argparse
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
        except (OSError, ValueError, AssertionError, subprocess.CalledProcessError):
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
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path('/run/systemd/system').is_dir()
    managed_paths = [CONFIG_DIR, STATE_DIR, LIB_DIR, Path('/usr/local/bin/xboard-rust'),
        Path('/usr/local/bin/xboard-node-rust'), Path('/etc/systemd/system') / UNIT]
    assert all(not p.exists() and not p.is_symlink() for p in managed_paths), 'Refuse to change an existing installation'
    existing_units = ['nginx.service', 'ssh.service', 'sshd.service']
    before = {unit: systemctl('show', unit, '-p', 'MainPID', '-p', 'ActiveState', check=False).stdout for unit in existing_units}
    cases, reports = [], []
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
                self.request.settimeout(5)
                while True:
                    body = self.request.recv(65536)
                    if not body: return
                    self.request.sendall(body)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True

        echo = Server(('127.0.0.1', 0), Echo)
        echo_port = echo.server_address[1]

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
        for server in [echo, panel]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        token = temp / 'token'; token.write_text(TOKEN); token.chmod(0o600)

        def run(action, *options, success=True, environment=None):
            proc = subprocess.run(['bash', str(ROOT / 'install.sh'), action, '--yes', *map(str, options)],
                capture_output=True, text=True, timeout=90, env=environment)
            if (proc.returncode == 0) != success:
                raise AssertionError((action + ': ' + proc.stdout + proc.stderr).replace(TOKEN, '[FIXTURE_TOKEN]'))
            return proc

        def parent():
            return int(systemctl('show', UNIT, '-p', 'MainPID', '--value').stdout.strip())

        def fetch(protocol='vless', tls=False):
            with socket.create_connection(('127.0.0.1', node_port), timeout=3) as stream:
                stream.settimeout(3)
                if tls:
                    context = ssl.create_default_context(cafile=str(temp / 'cert.pem'))
                    stream = context.wrap_socket(stream, server_hostname='localhost')
                if protocol == 'vless':
                    head = b'\0' + uuid.UUID(USER).bytes + b'\0\1' + struct.pack('!H', echo_port) + b'\1' + socket.inet_aton('127.0.0.1')
                    stream.sendall(head + PAYLOAD)
                    assert receive(stream, 2) == b'\0\0'
                else:
                    head = hashlib.sha224(USER.encode()).hexdigest().encode() + b'\r\n\1\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', echo_port) + b'\r\n'
                    stream.sendall(head + PAYLOAD)
                assert receive(stream, len(PAYLOAD)) == PAYLOAD
                stream.close()
                return True

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
            # PrivateTmp hides /tmp from the service; test TLS material lives in its managed state directory.
            cert = STATE_DIR / 'fixture-cert.pem'; key = STATE_DIR / 'fixture-key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            shutil.copy2(cert, temp / 'cert.pem')
            config.update(tls=1, server_name='localhost', cert_config={'cert_mode': 'file', 'cert_file': str(cert), 'key_file': str(key)})
            run('restart'); wait(lambda: fetch(tls=True))
            cases.append('installed-native-VLESS-file-TLS-with-verified-certificate')
            config['protocol'] = 'trojan'
            run('restart'); wait(lambda: fetch('trojan', True))
            cases.append('installed-native-Trojan-file-TLS-with-real-echo-bytes')
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
            for server in [panel, echo]:
                server.shutdown(); server.server_close()
    report = {'result': 'PASS', 'scope': 'Fresh exact-asset Linux systemd installation, loopback synthetic Xboard v2 panel, real VLESS/Trojan payload and TLS verification; no production panel or billing validation',
        'cases': cases, 'binary_sha256': sha(args.binary.read_bytes()), 'package_sha256': sha(args.package.read_bytes()), 'installer_sha256': sha((ROOT / 'install.sh').read_bytes()),
        'temporary_service_removed': True, 'managed_fixture_data_removed': True, 'existing_service_identities_preserved': True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'cases': len(cases), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
