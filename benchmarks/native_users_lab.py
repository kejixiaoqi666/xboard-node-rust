"""Isolated real-client user-update acceptance for the optional native kernel.

Requires Linux, an official sing-box client, a matching valid certificate, the
Rust controller and xbord-native-users. All listeners/traffic are loopback and
all users/tokens are synthetic. Uses a fresh output; never changes host settings.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import threading
import time
import traceback
import urllib.parse

import runtime_lab as lab

STREAM = lab.BLOB * 8


class StreamingOrigin(lab.Origin):
    def handle(self):
        self.request.settimeout(15)
        data = b""
        while b"\r\n\r\n" not in data:
            part = self.request.recv(4096)
            if not part or len(data) > 8192:
                return
            data += part
        path = urllib.parse.urlsplit(data.split(b" ",2)[1].decode()).path
        try:
            if path.startswith("/hold/"):
                with self.server.lock:
                    self.server.arrived += 1
                if not self.server.release.wait(15):
                    return
            if path != "/stream":
                body = lab.BLOB if path == "/blob" else lab.MARKER
                self.request.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode() + body)
                return
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\nConnection: close\r\n\r\n")
            for offset in range(0, len(STREAM), 16384):
                self.request.sendall(STREAM[offset:offset + 16384])
                time.sleep(0.03)
        except (BrokenPipeError, ConnectionResetError):
            # Expected for the legacy stop/start comparison and explicit stop.
            pass


class Fixture(lab.Fixture):
    def __init__(self, args, run, users, state_dir, native, protocol="vless", tls=False):
        super().__init__(args, run, users)
        self.state_dir, self.native = state_dir, native
        self.kernel = args.native if native else args.singbox
        self.protocol, self.tls = protocol, tls
        self.config_tag = '"config-1"'
        self.allow_overlap = False
        self.origin.RequestHandlerClass = StreamingOrigin
        if tls:
            self.config.update({"protocol": protocol, "tls": 1, "server_name": args.domain,
                "cert_config": {"cert_mode": "file", "cert_file": str(args.certificate_dir / "fullchain.pem"),
                                "key_file": str(args.certificate_dir / "privkey.pem")}})
        fixture = self
        parent = self.panel.RequestHandlerClass

        class Panel(parent):
            def do_GET(self):
                if urllib.parse.urlsplit(self.path).path.endswith("config"):
                    supplied = self.headers.get("If-None-Match")
                    if supplied == fixture.config_tag:
                        self.headers.replace_header("If-None-Match", '"config-1"')
                    elif supplied is not None:
                        del self.headers["If-None-Match"]
                super().do_GET()

            def send_header(self, key, value):
                if key.lower() == "etag" and urllib.parse.urlsplit(self.path).path.endswith("config"):
                    value = fixture.config_tag
                super().send_header(key, value)
        self.panel.RequestHandlerClass = Panel

    def start(self, executable):
        path = self.run / "runtime.json"
        settings = {"panel_url": "https://" + self.proxy.authority, "token_env": "XBORD_PANEL_TOKEN",
            "machine_id": 1, "node_id": 7, "singbox_executable": str(self.kernel), "state_dir": str(self.state_dir),
            "poll_seconds": 1, "native_user_updates": self.native, "traffic_reporting": False}
        if self.native and getattr(self.args, "builtin", False):
            del settings["singbox_executable"]
        path.write_text(json.dumps(settings))
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
        env.update({"GOMAXPROCS": "2", "XBORD_PANEL_TOKEN": lab.TOKEN,
                    "HTTPS_PROXY": "http://127.0.0.1:%s" % self.proxy.server_address[1], "NO_PROXY": ""})
        self.runtime = self.spawn([str(executable), "--config", str(path)], env, "runtime")
        lab.wait_for(lambda: lab.port_open(self.node_port) and self.child() is not None)
        self.client_port = self.start_client(lab.user(1)["uuid"], "client")
        lab.wait_for(self.business_ready)
        lab.wait_for(lambda: self.not_modified >= 2)
        if self.native and getattr(self.args, "builtin", False):
            assert "singbox_executable" not in json.loads(path.read_text())
            assert (Path("/proc") / str(self.child()) / "exe").samefile(executable)
        return self.runtime.pid

    def running_kernels(self):
        children = set()
        for file in (Path("/proc") / str(self.runtime.pid) / "task").glob("*/children"):
            try:
                children.update(file.read_text().split())
            except FileNotFoundError:
                pass
        running = []
        for pid in children:
            try:
                p = Path("/proc") / pid
                argv = (p / "cmdline").read_bytes().split(b"\0")
                if (p / "exe").resolve() == self.kernel and len(argv) > 1 and argv[1] == b"run":
                    running.append(int(pid))
            except OSError:
                pass
        return sorted(running)

    def child(self):
        running = self.running_kernels()
        assert len(running) <= (2 if self.allow_overlap else 1), running
        return running[-1] if running else None

    def start_client(self, credential, name, server_name=None):
        port = lab.free_port()
        outbound = {"type": self.protocol, "tag": "proxy", "server": "127.0.0.1", "server_port": self.node_port,
                    "uuid" if self.protocol == "vless" else "password": credential}
        if self.tls:
            outbound["tls"] = {"enabled": True, "server_name": server_name or self.args.domain}
        path = self.run / (name + ".json")
        path.write_text(json.dumps({"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": port}],
                                  "outbounds": [outbound], "route": {"final": "proxy"}}))
        env = dict(os.environ, GOMAXPROCS="2")
        env.pop("XBORD_PANEL_TOKEN", None)
        proc = self.spawn([str(self.args.singbox), "run", "-c", str(path)], env, name)
        lab.wait_for(lambda: lab.port_open(port))
        assert proc.poll() is None
        return port

    @staticmethod
    def response(sock):
        data = bytearray()
        while True:
            part = sock.recv(65536)
            if not part:
                break
            data.extend(part)
            assert len(data) <= len(STREAM) + 8192
        head, body = bytes(data).split(b"\r\n\r\n", 1)
        assert head.startswith(b"HTTP/1.1 200")
        return body

    def control_path(self):
        paths = list(self.state_dir.glob("u-*.sock"))
        assert len(paths) == 1, paths
        return paths[0]


def status(pid):
    value = lab.proc_sample(pid)
    rows = (Path("/proc") / str(pid) / "status").read_text().splitlines()
    value["hwm_kib"] = int(next(line.split()[1] for line in rows if line.startswith("VmHWM:")))
    return value


class Sampler:
    def __init__(self, parent):
        self.parent, self.samples = parent, []
        self.errors = []
        self.exited_samples = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.collect, daemon=True)

    def collect(self):
        while not self.stop.is_set():
            try:
                rows = []
                for pid in lab.owned_group_members(self.parent):
                    try:
                        rows.append({"pid": pid, **status(pid)})
                    except (OSError, ValueError, StopIteration, KeyError):
                        self.exited_samples += 1  # Includes a reaped/zombie check child.
                control = next((p for p in rows if p["pid"] == self.parent), None)
                if control:
                    self.samples.append({"time": time.monotonic(), "controller": control,
                                         "group_rss_kib": sum(p["rss_kib"] for p in rows), "processes": len(rows)})
            except Exception as error:
                self.errors.append(type(error).__name__)
                return
            self.stop.wait(0.01)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive()

    def summary(self):
        assert self.samples and not self.errors, self.errors
        return {"poll_delay_seconds": 0.01, "sampling_model": "scan /proc, then wait; not a fixed sampling interval",
                "samples": len(self.samples),
                "exited_process_samples_skipped": self.exited_samples,
                "controller_sampled_rss_peak_kib": max(p["controller"]["rss_kib"] for p in self.samples),
                "controller_hwm_kib": max(p["controller"]["hwm_kib"] for p in self.samples),
                "controller_max_fds": max(p["controller"]["fds"] for p in self.samples),
                "group_sampled_rss_peak_kib": max(p["group_rss_kib"] for p in self.samples),
                "group_max_processes": max(p["processes"] for p in self.samples)}


def read_frame(sock, limit):
    def exactly(count):
        data = bytearray()
        while len(data) < count:
            part = sock.recv(count - len(data))
            if not part:
                raise EOFError("control frame closed")
            data.extend(part)
        return bytes(data)
    size = struct.unpack("!I", exactly(4))[0]
    assert 0 < size <= limit
    return exactly(size)


def send_frame(sock, value):
    value = json.dumps(value, separators=(",", ":")).encode()
    sock.sendall(struct.pack("!I", len(value)) + value)


class ControlFault:
    """Temporary, owned Unix-socket proxy; corrupt/drop responses, never credentials."""
    def __init__(self, fixture, mode):
        self.fixture, self.mode = fixture, mode
        self.path = fixture.control_path()
        self.owner = fixture.child()
        self.real = fixture.state_dir / "real.sock"
        assert not self.real.exists()
        self.path.rename(self.real)
        self.replace = threading.Event()
        self.finished = threading.Event()
        self.counts = {"replace": 0, "status": 0, "dropped": 0, "real_applied": 0}
        fault = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                try:
                    req = json.loads(read_frame(self.request, 65536))
                    op = req["operation"]
                    fault.counts[op] += 1
                    if op == "replace":
                        fault.replace.set()
                    mode = fault.mode
                    if mode == "stall":
                        fault.finished.wait(6)
                        return
                    if mode == "reject" and op == "replace":
                        req["digest"] = "0" * 64
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
                        upstream.settimeout(3)
                        upstream.connect(str(fault.real))
                        send_frame(upstream, req)
                        reply = json.loads(read_frame(upstream, 8192))
                    if op == "replace" and mode in ("lost", "unknown"):
                        assert reply["code"] == "ok" and reply["digest"] == req["digest"]
                        fault.counts["real_applied"] += 1
                    if mode == "lost" and op == "replace" and fault.counts["dropped"] == 0:
                        fault.counts["dropped"] += 1
                        return
                    if mode == "unknown":
                        if op == "replace":
                            # After real publication, force the next panel read to
                            # fail, so last-known-good recovery is visible by auth.
                            fault.fixture.config["tls"] = 2
                            fault.fixture.config_tag = '"unknown-recovery-config"'
                        reply["digest"] = "f" * 64
                    send_frame(self.request, reply)
                except (EOFError, OSError, KeyError, AssertionError):
                    pass
        self.server = socketserver.ThreadingUnixStreamServer(str(self.path), Handler)
        self.server.daemon_threads = True
        os.chmod(self.path, 0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.finished.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.path.exists():
            self.path.unlink()
        if self.real.exists():
            if self.fixture.child() == self.owner:
                self.real.rename(self.path)
            else:
                self.real.unlink()


def main():
    parser = argparse.ArgumentParser()
    for arg in ["controller", "native", "singbox", "certificate-dir", "output"]:
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--builtin", action="store_true", help="native cases use the controller's embedded Rust kernel without external executable configuration")
    parser.add_argument("--steady-seconds", type=int, default=30)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--only-lifecycle", action="store_true")
    selection.add_argument("--only-faults", action="store_true")
    args = parser.parse_args()
    assert 10 <= args.steady_seconds <= 120
    os.umask(0o077)
    for key in ["controller", "native", "singbox", "certificate_dir", "output"]:
        setattr(args, key, getattr(args, key).resolve())
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    state_root = args.output / "s"
    state_root.mkdir(mode=0o700)
    report = {"result": "RUNNING", "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Loopback HTTPS panel, official VLESS/Trojan clients, synthetic users, valid TLS hostname verification; no production service/settings changes",
        "binaries": {key: {"bytes": getattr(args, key).stat().st_size, "sha256": hashlib.sha256(getattr(args, key).read_bytes()).hexdigest()} for key in ["controller", "native", "singbox"]},
        "native_backend": "embedded_rust" if args.builtin else "external_companion",
        "cases": [], "faults": []}
    counter = 0

    def save():
        (args.output / "measurements.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))

    def fixture(name, users=10000, native=True, **kwargs):
        nonlocal counter
        directory = args.output / name
        directory.mkdir(mode=0o700)
        f = Fixture(args, directory, users, state_root / str(counter), native, **kwargs)
        counter += 1
        try:
            f.start(args.controller)
        except BaseException:
            f.close()
            raise
        return f

    def update(f, index, size=10000):
        credential = lab.user(900000 + index)["uuid"]
        if f.protocol == "trojan":
            credential = 'hot-update-热更新-Ω-"\\-%d' % index
        fresh = f.start_client(credential, "updated-%d" % index)
        assert not f.business_ready(port=fresh), "new credential accepted before update"
        f.users = [lab.user(i) for i in range(1, size + 1) if i != 2]
        f.users.append({**lab.user(900000 + index), "uuid": credential})
        f.user_tag += 1
        trigger = time.monotonic()
        lab.wait_for(lambda: f.business_ready(port=fresh), timeout=20)
        assert f.fetch(port=fresh) == lab.MARKER
        return fresh, time.monotonic() - trigger

    def transfer(f, port, result):
        result["started"] = time.monotonic()
        try:
            result["body_valid"] = f.fetch("/stream", port=port) == STREAM
        except (OSError, ValueError, AssertionError):
            result["body_valid"] = False
        result["finished"] = time.monotonic()

    def continuity_case(name, native, tls=False, protocol="vless", resource=False):
        f = fixture(name, native=native, tls=tls, protocol=protocol)
        held = []
        result = {"name": name, "native": native, "tls": tls, "protocol": protocol}
        try:
            time.sleep(2)
            if resource:
                result["steady"] = lab.sample_steady(f, args.steady_seconds)
            pid = f.child()
            removed = f.start_client(lab.user(2)["uuid"], "removed-client")
            assert f.fetch(port=removed) == lab.MARKER
            arrived = f.origin.arrived
            f.origin.release.clear()
            for i in range(64):
                held.append(f.connection("/hold/update-%d" % i, port=f.client_port if i < 32 else removed))
            lab.wait_for(lambda: f.origin.arrived == arrived + 64)
            stream = {}
            thread = threading.Thread(target=transfer, args=(f, removed, stream))
            thread.start()
            last_client = None
            cycles = []
            with Sampler(f.runtime.pid) as sampler:
                for index, size in enumerate([20000, 10000] * 3 if resource else [10000], 1):
                    before = f.child()
                    client, elapsed = update(f, index, size)
                    after = f.child()
                    assert (after == before) if native else (after != before)
                    assert not f.business_ready(port=removed), "removed user authenticated anew"
                    if last_client is not None:
                        assert not f.business_ready(port=last_client), "rotated previous credential still accepted"
                    assert f.fetch() == lab.MARKER
                    cycles.append({"users": size, "elapsed_seconds": elapsed, "pid_before": before, "pid_after": after,
                                   "new_works": True, "removed_denied": True, "retained_works": True,
                                   "committed": time.monotonic()})
                    last_client = client
                result["update_resources"] = sampler.summary()
            f.origin.release.set()
            successes = 0
            for conn in held:
                try:
                    successes += f.response(conn) == lab.MARKER
                except (OSError, ValueError, AssertionError):
                    pass
            thread.join(timeout=15)
            assert not thread.is_alive()
            if native:
                assert successes == 64 and stream["body_valid"]
                assert stream["started"] < cycles[0]["committed"] < stream["finished"], "stream did not overlap publication"
            else:
                assert successes == 0 and not stream["body_valid"]
            result.update({"cycles": cycles, "held_connections": 64, "held_survived": successes,
                           "held_retained_user": 32, "held_removed_user": 32, "stream": stream,
                           "stream_bytes": len(STREAM), "stream_sha256": hashlib.sha256(STREAM).hexdigest()})
            if native:
                active = f.child()
                f.users.reverse()
                f.user_tag += 1
                time.sleep(2.2)
                assert f.child() == active and f.fetch() == lab.MARKER
                result["reorder_no_restart"] = True
                # Hostname resolution uses the default direct outbound, not DNS overrides.
                with socket.create_connection(("127.0.0.1", f.client_port), timeout=10) as conn:
                    conn.settimeout(10)
                    conn.sendall(("GET http://localhost:%d/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" % f.origin.server_address[1]).encode())
                    assert f.response(conn) == lab.MARKER
                result["default_hostname_resolution"] = True
                if tls:
                    wrong = f.start_client(lab.user(1)["uuid"], "wrong-hostname", server_name="wrong.invalid")
                    assert not f.business_ready(port=wrong)
                    result["wrong_tls_hostname_denied"] = True
                assert len(list(f.state_dir.glob("candidate-*.json"))) == 1
                assert (f.control_path().stat().st_mode & 0o777) == 0o600
                assert (f.state_dir.stat().st_mode & 0o777) == 0o700
                result["private_state_and_candidate_cleanup"] = True
            return result
        finally:
            f.origin.release.set()
            for conn in held:
                conn.close()
            f.close()

    def fault_case(mode):
        f = fixture("fault-" + mode, users=128)
        proxy = None
        try:
            previous = f.child()
            proxy = ControlFault(f, mode)
            credential = lab.user(990001)["uuid"]
            fresh = f.start_client(credential, "fresh")
            f.users.append(lab.user(990001))
            f.user_tag += 1
            assert proxy.replace.wait(10)
            if mode == "lost":
                lab.wait_for(lambda: f.business_ready(port=fresh))
                assert f.child() == previous and f.fetch() == lab.MARKER
                assert proxy.counts["dropped"] == 1 and proxy.counts["status"] >= 1
                assert proxy.counts["real_applied"] == 1
            elif mode == "reject":
                lab.wait_for(lambda: proxy.counts["replace"] >= 2)
                assert f.child() == previous and f.fetch() == lab.MARKER and not f.business_ready(port=fresh)
                assert len(list(f.state_dir.glob("candidate-*.json"))) == 1
                proxy.mode = "pass"
                lab.wait_for(lambda: f.business_ready(port=fresh))
                assert f.child() == previous
            elif mode == "unknown":
                lab.wait_for(lambda: f.child() not in (None, previous) and f.business_ready(), timeout=20)
                assert not f.business_ready(port=fresh), "unconfirmed users leaked into recovered snapshot"
                assert proxy.counts["real_applied"] == 1
            elif mode == "stall":
                start = time.monotonic()
                f.runtime.send_signal(signal.SIGTERM)
                f.runtime.wait(timeout=7)
                assert f.runtime.returncode == 0 and f.child() is None
                assert time.monotonic() - start < 6
            result = {"mode": mode, "pid_before": previous, "pid_after": f.child(), "proxy_counts": proxy.counts,
                      "result": "PASS"}
            return result
        finally:
            if proxy:
                proxy.close()
            f.close()

    def lifecycle_case():
        f = fixture("lifecycle", users=512)
        held = []
        try:
            pid = f.child()
            assert b"XBORD_PANEL_TOKEN=" not in (Path("/proc")/str(pid)/"environ").read_bytes()
            baseline = {"controller": status(f.runtime.pid), "kernel": status(pid)}
            f.origin.release.clear()
            arrived = f.origin.arrived
            for index in range(256):
                held.append(f.connection("/hold/load-%d" % index))
            lab.wait_for(lambda: f.origin.arrived == arrived + 256)
            held_samples = []
            started = time.monotonic()
            while time.monotonic() - started < 10:
                assert f.child() == pid
                held_samples.append({"controller": status(f.runtime.pid), "kernel": status(pid)})
                time.sleep(0.5)
            f.origin.release.set()
            for conn in held:
                assert f.response(conn) == lab.MARKER
                conn.close()
            held.clear()
            started = time.monotonic()
            def transfer_blob(_):
                assert f.fetch("/blob") == lab.BLOB
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(transfer_blob, range(1024)))
            elapsed = time.monotonic() - started
            lab.wait_for(lambda: status(pid)["fds"] == baseline["kernel"]["fds"],timeout=5)
            tcp = {"held_connections": 256, "hold_seconds": 10, "verified_held_responses": 256,
                   "before": baseline, "held_samples": held_samples, "after": {"controller":status(f.runtime.pid),"kernel":status(pid)},
                   "transfers": {"requests":1024,"payload_bytes":len(lab.BLOB),"concurrency":8,"seconds":elapsed,
                                 "mib_per_second":1024*len(lab.BLOB)/1048576/elapsed,"all_contents_verified":True}}
            os.kill(pid,signal.SIGKILL)
            lab.wait_for(lambda: f.child() not in (None,pid) and f.business_ready(),timeout=20)
            recovered = f.child()
            # Authenticated readiness can precede the parent's 100 ms startup
            # settling/commit boundary. Wait for actual owned-file reclamation.
            file_settle_started = time.monotonic()
            lab.wait_for(lambda:len(list(f.state_dir.glob("candidate-*.json")))==1,timeout=3)
            candidate_settle = time.monotonic()-file_settle_started
            # A listener change must take the full validated restart path.
            f.allow_overlap = True
            old_port = f.node_port
            f.node_port = lab.free_port()
            f.config["server_port"] = f.node_port
            f.config_tag = '"listener-changed"'
            client = f.start_client(lab.user(1)["uuid"],"changed-listener")
            lab.wait_for(lambda: f.business_ready(port=client) and len(f.running_kernels())==1,timeout=20)
            assert f.child()!=recovered and not lab.port_open(old_port)
            f.client_port = client
            restarted = f.child()
            # The existing API cancellation contract also applies in native mode.
            f.stall = True
            assert f.entered.wait(10)
            started = time.monotonic()
            f.runtime.send_signal(signal.SIGTERM)
            f.runtime.wait(timeout=7)
            shutdown = time.monotonic()-started
            assert f.runtime.returncode==0 and not f.running_kernels() and shutdown<3
            assert not list(f.state_dir.glob("candidate-*.json")) and not list(f.state_dir.glob("*.sock"))
            return {"result":"PASS","tcp":tcp,"crash_pid_before":pid,"crash_pid_after":recovered,
                    "listener_restart_pid":restarted,"stalled_http_shutdown_seconds":shutdown,
                    "recovered_candidate_cleanup_seconds":candidate_settle,
                    "candidate_socket_cleanup":True,"token_not_in_kernel_environment":True}
        finally:
            f.origin.release.set()
            for conn in held:
                conn.close()
            f.close()

    try:
        save()
        cases = [("default", False, False, "vless", True),
                ("native", True, False, "vless", True), ("vless-tls", True, True, "vless", False),
                ("trojan-tls", True, True, "trojan", False)]
        for name, native, tls, protocol, resource in ([] if args.only_lifecycle or args.only_faults else cases):
            result = continuity_case(name, native, tls, protocol, resource)
            report["cases"].append(result)
            save()
            print(json.dumps({"case": name, "held_survived": result["held_survived"], "stream_valid": result["stream"]["body_valid"]}), flush=True)
        for mode in ([] if args.only_lifecycle else ["lost", "reject", "unknown", "stall"]):
            report["faults"].append(fault_case(mode))
            save()
            print(json.dumps({"fault": mode, "result": "PASS"}), flush=True)
        if not args.only_faults:
            report["lifecycle"] = lifecycle_case()
            save()
            print(json.dumps({"lifecycle":"PASS","held":256,"transfers":1024}),flush=True)
        report["result"] = "PASS"
    except BaseException:
        report["result"] = "FAIL"
        report["error"] = traceback.format_exc()
        raise
    finally:
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()


if __name__ == "__main__":
    main()
