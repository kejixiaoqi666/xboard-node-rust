"""Bounded Linux executable comparison through real HTTPS and VLESS fixtures.

Requires a valid certificate for --domain. Certificates are read in place and
never copied. All sockets listen on loopback; no system service is replaced.
Use a fresh output directory. Only synthetic panel credentials/users are used.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.server
import json
import os
import pathlib
import queue
import select
import signal
import socket
import socketserver
import ssl
import statistics
import struct
import subprocess
import threading
import time
import urllib.parse

TOKEN = "bounded-lab-fixture-only"
MARKER = b"xbord-bounded-real-vless-origin"
BLOB = MARKER + b"x" * (256 * 1024 - len(MARKER))


def user(index):
    return {"id": index, "uuid": "00000000-0000-4000-8000-%012d" % index,
            "speed_limit": 0, "device_limit": 0}


def wait_for(predicate, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("bounded condition timed out")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def proc_sample(pid):
    base = pathlib.Path("/proc") / str(pid)
    status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines() if ":" in line)
    stat = (base / "stat").read_text().rsplit(")", 1)[1].split()
    return {"rss_kib": int(status["VmRSS"].split()[0]), "threads": int(status["Threads"]),
            "cpu_ticks": int(stat[11]) + int(stat[12]), "fds": len(list((base / "fd").iterdir()))}


def kernel_child(parent, executable):
    children = set()
    for file in (pathlib.Path("/proc") / str(parent) / "task").glob("*/children"):
        try:
            children.update(file.read_text().split())
        except FileNotFoundError:
            pass
    for pid in children:
        try:
            if (pathlib.Path("/proc") / pid / "exe").resolve() == executable:
                return int(pid)
        except OSError:
            pass
    return None


def owned_group_members(group):
    """Popen creates an isolated session whose session/group ID is its PID."""
    members = []
    for file in pathlib.Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = file.read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group and int(fields[3]) == group and fields[0] != "Z":
                members.append(int(file.parent.name))
        except (OSError, ValueError, IndexError):
            continue
    return members


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        data = b""
        while b"\r\n\r\n" not in data:
            part = self.request.recv(1)
            if not part or len(data) > 8192:
                return
            data += part
        if data.split(b"\r\n", 1)[0] != ("CONNECT %s HTTP/1.1" % self.server.authority).encode():
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        with socket.create_connection(("127.0.0.1", self.server.panel_port), timeout=10) as upstream:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(None)
            upstream.settimeout(None)
            while True:
                ready, _, _ = select.select([self.request, upstream], [], [], 40)
                if not ready:
                    return
                for source in ready:
                    destination = upstream if source is self.request else self.request
                    payload = source.recv(65536)
                    if not payload:
                        return
                    destination.sendall(payload)


class ThreadedServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 512


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        request = b""
        while b"\r\n\r\n" not in request:
            part = self.request.recv(4096)
            if not part or len(request) > 8192:
                return
            request += part
        path = urllib.parse.urlsplit(request.split(b" ", 2)[1].decode()).path
        if path.startswith("/hold/"):
            with self.server.lock:
                self.server.arrived += 1
            if not self.server.release.wait(15):
                return
        body = BLOB if path == "/blob" else MARKER
        self.request.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %s\r\nConnection: close\r\n\r\n" % len(body)).encode() + body)


def ws_frame(sock, payload, opcode=1):
    if isinstance(payload, dict):
        payload = json.dumps(payload, separators=(",", ":")).encode()
    length = len(payload)
    header = bytes([0x80 | opcode])
    if length < 126:
        header += bytes([length])
    elif length <= 65535:
        header += bytes([126]) + struct.pack("!H", length)
    else:
        header += bytes([127]) + struct.pack("!Q", length)
    sock.sendall(header + payload)


class Fixture:
    def __init__(self, args, run, users, websocket=False):
        self.args, self.run, self.websocket = args, run, websocket
        self.node_port = free_port()
        self.config = {"protocol": "vless", "server_port": self.node_port, "listen_ip": "127.0.0.1",
                       "node_id": 7, "base_config": {"pull_interval": 1, "push_interval": 60},
                       "network": "", "routes": None}
        self.users = [user(i) for i in range(1, users + 1)]
        self.user_tag = 1
        self.requests = self.not_modified = self.ws_connections = 0
        self.commands = queue.Queue()
        self.stop = threading.Event()
        self.stall = False
        self.entered = threading.Event()
        self.release_http = threading.Event()
        self.processes, self.files = [], []
        fixture = self

        class Panel(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 < length <= 8192
                data = json.loads(self.rfile.read(length))
                if self.path != "/api/v2/server/handshake" or data.get("token") != TOKEN or data.get("node_id") != 7 or data.get("machine_id") != 1:
                    self.send_error(403)
                    return
                fixture.requests += 1
                payload = json.dumps({"websocket": {"enabled": True, "ws_url": "wss://%s:%s/ws" % (args.domain, fixture.panel.server_port)}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                parsed = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(parsed.query)
                if query.get("token") != [TOKEN] or query.get("node_id") != ["7"] or query.get("machine_id") != ["1"]:
                    self.send_error(403)
                    return
                if parsed.path == "/ws":
                    accept = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                    self.send_response(101)
                    self.send_header("Upgrade", "websocket")
                    self.send_header("Connection", "Upgrade")
                    self.send_header("Sec-WebSocket-Accept", accept)
                    self.end_headers()
                    fixture.ws_connections += 1
                    ws_frame(self.connection, {"event": "auth.success"})
                    self.connection.settimeout(10)
                    while not fixture.stop.is_set():
                        try:
                            item = fixture.commands.get(timeout=0.1)
                        except queue.Empty:
                            continue
                        if item is None:
                            ws_frame(self.connection, b"", 8)
                            break
                        ws_frame(self.connection, item)
                    self.close_connection = True
                    return
                fixture.requests += 1
                if parsed.path == "/api/v2/server/handshake":
                    body, tag = {"version": "2", "websocket": {"enabled": True, "ws_url": "wss://%s:%s/ws" % (args.domain, fixture.panel.server_port)}}, None
                elif parsed.path == "/api/v2/server/config":
                    body, tag = fixture.config, '"config-1"'
                elif parsed.path == "/api/v2/server/user":
                    body, tag = {"users": fixture.users}, '"users-%s"' % fixture.user_tag
                else:
                    self.send_error(404)
                    return
                if tag and self.headers.get("If-None-Match") == tag:
                    if fixture.stall and parsed.path.endswith("config"):
                        fixture.entered.set()
                        fixture.release_http.wait(15)
                    fixture.not_modified += 1
                    self.send_response(304)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                if tag:
                    self.send_header("ETag", tag)
                self.end_headers()
                self.wfile.write(payload)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(args.certificate_dir / "fullchain.pem"), str(args.certificate_dir / "privkey.pem"))
        self.panel = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Panel)
        self.panel.daemon_threads = True
        self.panel.socket = context.wrap_socket(self.panel.socket, server_side=True)
        self.proxy = ThreadedServer(("127.0.0.1", 0), Proxy)
        self.proxy.panel_port = self.panel.server_port
        self.proxy.authority = "%s:%s" % (args.domain, self.panel.server_port)
        self.origin = ThreadedServer(("127.0.0.1", 0), Origin)
        self.origin.arrived = 0
        self.origin.release, self.origin.lock = threading.Event(), threading.Lock()
        self.servers = [self.panel, self.proxy, self.origin]
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def spawn(self, command, env, name):
        output = (self.run / (name + ".log")).open("w")
        self.files.append(output)
        process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   start_new_session=True)
        self.processes.append(process)
        return process

    def start(self, executable):
        config = self.run / "runtime.json"
        self.state_dir = self.run / "state"
        config.write_text(json.dumps({"panel_url": "https://" + self.proxy.authority, "token_env": "XBORD_PANEL_TOKEN",
                                      "machine_id": 1, "node_id": 7, "singbox_executable": str(self.args.singbox),
                                      "state_dir": str(self.state_dir), "poll_seconds": 30 if self.websocket else 1,
                                      "websocket": self.websocket}))
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        env.update({"GOMAXPROCS": "2", "XBORD_PANEL_TOKEN": TOKEN, "HTTPS_PROXY": "http://127.0.0.1:%s" % self.proxy.server_address[1], "NO_PROXY": ""})
        command = [str(executable), "--config", str(config)]
        if self.websocket:
            hosts = self.run / "hosts"
            hosts.write_text(pathlib.Path("/etc/hosts").read_text() + "\n127.0.0.1 %s\n" % self.args.domain)
            command = ["unshare", "--mount", "--propagation", "private", "sh", "-c",
                       'mount --bind "$1" /etc/hosts && exec "$2" --config "$3"', "sh", str(hosts), str(executable), str(config)]
        self.runtime = self.spawn(command, env, "runtime")
        wait_for(lambda: port_open(self.node_port) and self.child() is not None)
        self.client_port = self.start_client(user(1)["uuid"], "client")
        assert self.fetch() == MARKER
        wait_for(lambda: self.not_modified >= 2 if not self.websocket else self.ws_connections == 1)
        return self.runtime.pid

    def start_client(self, uuid, name):
        port = free_port()
        config = self.run / (name + ".json")
        config.write_text(json.dumps({"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}],
                                      "outbounds": [{"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": self.node_port, "uuid": uuid}],
                                      "route": {"final": "proxy"}}))
        env = dict(os.environ, GOMAXPROCS="2")
        env.pop("XBORD_PANEL_TOKEN", None)
        process = self.spawn([str(self.args.singbox), "run", "-c", str(config)], env, name)
        wait_for(lambda: port_open(port))
        assert process.poll() is None
        return port

    def child(self):
        return kernel_child(self.runtime.pid, self.args.singbox)

    def connection(self, path="/", port=None):
        sock = socket.create_connection(("127.0.0.1", port or self.client_port), timeout=10)
        sock.settimeout(15)
        sock.sendall(("GET http://127.0.0.1:%s%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n" % (self.origin.server_address[1], path, self.origin.server_address[1])).encode())
        return sock

    @staticmethod
    def response(sock):
        data = bytearray()
        while True:
            part = sock.recv(65536)
            if not part:
                break
            data.extend(part)
            assert len(data) <= len(BLOB) + 8192
        head, body = bytes(data).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200")
        return body

    def fetch(self, path="/", port=None):
        with self.connection(path, port) as sock:
            return self.response(sock)

    def business_ready(self, port=None):
        try:
            return self.fetch(port=port) == MARKER
        except (OSError, ValueError, AssertionError):
            return False

    def close(self):
        self.stop.set()
        self.release_http.set()
        self.origin.release.set()
        for process in reversed(self.processes):
            # The leader may already have exited while a kernel child survives.
            if owned_group_members(process.pid):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            deadline = time.monotonic() + 2
            while owned_group_members(process.pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if owned_group_members(process.pid):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                wait_for(lambda: not owned_group_members(process.pid), timeout=3)
        for server in reversed(self.servers):
            server.shutdown()
            server.server_close()
        for file in self.files:
            file.close()


def sample_steady(fixture, seconds):
    child = fixture.child()
    start, first = time.monotonic(), {"runtime": proc_sample(fixture.runtime.pid), "kernel": proc_sample(child)}
    samples = {"runtime": [], "kernel": []}
    while time.monotonic() - start < seconds:
        samples["runtime"].append(proc_sample(fixture.runtime.pid))
        samples["kernel"].append(proc_sample(child))
        assert fixture.child() == child and fixture.runtime.poll() is None
        time.sleep(0.5)
    elapsed = time.monotonic() - start
    last = {"runtime": proc_sample(fixture.runtime.pid), "kernel": proc_sample(child)}
    result = {"seconds": elapsed, "tick_hz": os.sysconf("SC_CLK_TCK")}
    for name in samples:
        ticks = last[name]["cpu_ticks"] - first[name]["cpu_ticks"]
        result[name] = {"rss_median_kib": statistics.median(s["rss_kib"] for s in samples[name]),
                        "rss_min_kib": min(s["rss_kib"] for s in samples[name]), "rss_max_kib": max(s["rss_kib"] for s in samples[name]),
                        "threads": sorted({s["threads"] for s in samples[name]}), "cpu_ticks": ticks,
                        "cpu_seconds": ticks / result["tick_hz"], "one_core_cpu_percent": ticks / result["tick_hz"] / elapsed * 100}
    return result


def tcp_load(fixture):
    sockets, count = [], 256
    initial = fixture.origin.arrived
    start = time.monotonic()
    try:
        for index in range(count):
            sockets.append(fixture.connection("/hold/%s" % index))
        wait_for(lambda: fixture.origin.arrived == initial + count)
        accepted = time.monotonic() - start
        observations = []
        for _ in range(3):
            observations.append(proc_sample(fixture.child()))
            time.sleep(1)
        assert fixture.runtime.poll() is None
        fixture.origin.release.set()
        for sock in sockets:
            assert fixture.response(sock) == MARKER
    finally:
        fixture.origin.release.set()
        for sock in sockets:
            sock.close()
    results = []
    for _ in range(3):
        begin = time.monotonic()

        def transfer(_):
            started = time.monotonic()
            assert fixture.fetch("/blob") == BLOB
            return (time.monotonic() - started) * 1000

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            latency = sorted(pool.map(transfer, range(32)))
        elapsed = time.monotonic() - begin
        results.append({"mib_per_second": 8 / elapsed, "seconds": elapsed, "requests": 32,
                        "payload_bytes": len(BLOB), "concurrency": 8, "p50_ms": statistics.median(latency),
                        "p95_ms": latency[int(0.95 * (len(latency) - 1))]})
    return {"held_connections": count, "all_responses_verified": count, "hold_seconds": 3,
            "accept_seconds": accepted, "kernel_held_samples": observations, "transfers": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("baseline", "optimized", "singbox", "certificate-dir", "output"):
        parser.add_argument("--" + flag, type=pathlib.Path, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--trials", type=int, default=3, choices=range(1, 4))
    parser.add_argument("--sample-seconds", type=int, default=12, choices=range(5, 31))
    parser.add_argument("--wss", action="store_true", help="use a private mount namespace for process-local hostname mapping")
    args = parser.parse_args()
    assert os.name == "posix" and pathlib.Path("/proc").is_dir()
    for name in ("baseline", "optimized", "singbox", "certificate_dir", "output"):
        setattr(args, name, getattr(args, name).resolve())
    assert all(path.is_file() for path in (args.baseline, args.optimized, args.singbox))
    assert args.domain and all(c.isalnum() or c in ".-" for c in args.domain)
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    host_hash = hashlib.sha256(pathlib.Path("/etc/hosts").read_bytes()).hexdigest()
    report = {"scope": "loopback HTTPS panel and real VLESS; shared host, GOMAXPROCS=2 for both kernels; TCP is sing-box data plane",
              "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cases": [],
              "binary": {name: {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in (("baseline", args.baseline), ("optimized", args.optimized), ("singbox", args.singbox))}}
    try:
        for users in (1, 10000):
            for trial in range(1, args.trials + 1):
                versions = ("baseline", "optimized") if trial % 2 else ("optimized", "baseline")
                for version in versions:
                    run = args.output / ("%s-%s-%s" % (version, users, trial))
                    run.mkdir()
                    fixture = Fixture(args, run, users)
                    try:
                        fixture.start(getattr(args, version))
                        time.sleep(2)
                        result = {"version": version, "users": users, "trial": trial, "steady": sample_steady(fixture, args.sample_seconds)}
                        if trial == 1:
                            result["tcp"] = tcp_load(fixture)
                        if version == "optimized" and users == 1 and trial == 1:
                            fixture.stall = True
                            assert fixture.entered.wait(5)
                            killed = fixture.child()
                            os.kill(killed, signal.SIGKILL)
                            fixture.stall = False
                            fixture.release_http.set()
                            wait_for(lambda: fixture.child() not in (None, killed) and fixture.business_ready())
                            result["mid_rest_304_kernel_crash_recovered"] = True
                            fixture.entered.clear()
                            fixture.release_http.clear()
                            fixture.stall = True
                            assert fixture.entered.wait(5)
                            result["sigterm_during_stalled_https"] = True
                        child = fixture.child()
                        start = time.monotonic()
                        fixture.runtime.send_signal(signal.SIGTERM)
                        fixture.runtime.wait(timeout=12)
                        result["sigterm_seconds"] = time.monotonic() - start
                        assert fixture.runtime.returncode == 0 and not pathlib.Path("/proc", str(child)).exists()
                        assert not port_open(fixture.node_port) and not list(fixture.state_dir.glob("*.json"))
                        result["metrics"] = json.loads((run / "runtime.log").read_text().splitlines()[-1])
                        assert result["metrics"]["failed"] == 0
                        report["cases"].append(result)
                        print(json.dumps(result), flush=True)
                    finally:
                        fixture.close()
        if args.wss:
            run = args.output / "wss"
            run.mkdir()
            fixture = Fixture(args, run, 1, websocket=True)
            try:
                fixture.start(args.optimized)
                time.sleep(0.4)
                before = fixture.requests
                fixture.commands.put({"event": "sync.users", "data": {"node_id": 8, "users": []}})
                time.sleep(0.4)
                assert fixture.requests == before
                old_child = fixture.child()
                fixture.users, fixture.user_tag = [user(2)], 2
                # The push deliberately excludes REST-only id=2 and retains removed id=1.
                payload = {"event": "sync.users", "data": {"node_id": 7, "users": [user(1)] + [user(i) for i in range(3, 10002)]}}
                for _ in range(32):
                    fixture.commands.put(payload)
                wait_for(lambda: fixture.child() not in (None, old_child))
                second = fixture.start_client(user(2)["uuid"], "client2")
                wait_for(lambda: fixture.business_ready(port=second))
                assert not fixture.business_ready(), "WS-retained/REST-removed user is still allowed"
                wait_for(lambda: fixture.commands.empty())
                time.sleep(0.4)
                assert fixture.ws_connections == 1
                fixture.commands.put(None)
                wait_for(lambda: fixture.ws_connections == 2)
                before = fixture.requests
                fixture.commands.put({"event": "sync.devices", "data": {"node_id": 7, "online": {}}})
                wait_for(lambda: fixture.requests >= before + 2)
                assert fixture.fetch(port=second) == MARKER
                child = fixture.child()
                start = time.monotonic()
                fixture.runtime.send_signal(signal.SIGTERM)
                fixture.runtime.wait(timeout=5)
                assert fixture.runtime.returncode == 0
                assert not pathlib.Path("/proc", str(child)).exists() and not port_open(fixture.node_port)
                assert not list(fixture.state_dir.glob("*.json"))
                metrics = json.loads((run / "runtime.log").read_text().splitlines()[-1])
                assert metrics["applied"] == 2 and metrics["push_resyncs"] > 0 and metrics["failed"] == 0
                report["wss"] = {"foreign_node_ignored": True, "burst_messages": 32, "users_per_message": 10000,
                                 "rest_authoritative_rotation_verified": True, "connections_after_forced_close": fixture.ws_connections,
                                 "sigterm_seconds": time.monotonic() - start, "metrics": metrics}
                print(json.dumps(report["wss"]), flush=True)
            finally:
                fixture.close()
        assert hashlib.sha256(pathlib.Path("/etc/hosts").read_bytes()).hexdigest() == host_hash
        report["global_hosts_unchanged"] = True
        report["result"] = "PASS"
    except Exception as error:
        report["result"], report["error"] = "FAIL", str(error)
        raise
    finally:
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (args.output / "result.json").write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
