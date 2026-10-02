"""Linux-only, loopback test of accept failure without host-wide FD changes.

Only the new Rust kernel child receives RLIMIT_NOFILE=64. Synthetic VLESS
credentials and an echo origin verify that existing transfers survive FD
exhaustion, new transfers recover, control stays usable and shutdown is bounded.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import uuid


def wait(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition did not become ready")


def read_exact(connection, count):
    body = bytearray()
    while len(body) < count:
        part = connection.recv(count - len(body))
        if not part:
            raise AssertionError("unexpected EOF")
        body.extend(part)
    return bytes(body)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while body := self.request.recv(16384):
                self.request.sendall(body)
        except OSError:
            pass


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and args.binary.is_absolute()
    assert args.output.is_absolute() and not args.output.exists()
    args.output.mkdir(mode=0o700)
    config_path = args.output / "c.json"
    control_path = args.output / "s.sock"
    report_path = args.output / "measurements.json"
    assert len(os.fsencode(control_path)) < 108
    origin = Origin(("127.0.0.1", 0), Echo)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    credential = "00000000-0000-4000-8000-000000000100"
    config = {"log": {"level": "error", "timestamp": True}, "inbounds": [
        {"type": "vless", "tag": "vless-in", "listen": "127.0.0.1", "listen_port": port,
         "users": [{"name": "100", "uuid": credential}]}],
        "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
    with config_path.open("x", encoding="utf-8") as file:
        json.dump(config, file)
    config_path.chmod(0o600)
    command = [str(args.binary), "run", "-c", str(config_path), "--control-socket", str(control_path)]
    # A separate Python child changes its own limit, then execs the Rust kernel;
    # no preexec_fn in the threaded parent and no limits on existing processes.
    wrapper = "import os,resource,sys; resource.setrlimit(resource.RLIMIT_NOFILE,(64,64)); os.execv(sys.argv[1],sys.argv[1:])"
    log = (args.output / "kernel.log").open("xb")
    process = subprocess.Popen([sys.executable, "-c", wrapper, *command], stdout=log, stderr=log)
    opened = []
    report = {"result": "RUNNING", "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "child_rlimit_nofile": 64, "host_wide_limits_changed": False, "kernel_pid": process.pid}

    def fd_count():
        return len(list((Path("/proc") / str(process.pid) / "fd").iterdir()))

    def connection():
        stream = socket.create_connection(("127.0.0.1", port), timeout=2)
        opened.append(stream)
        header = bytes([0]) + uuid.UUID(credential).bytes + bytes([0, 1])
        header += struct.pack(">H", origin.server_address[1]) + bytes([1, 127, 0, 0, 1])
        stream.sendall(header)
        assert read_exact(stream, 2) == bytes([0, 0])
        return stream

    def exchange(stream, body):
        stream.sendall(body)
        assert read_exact(stream, len(body)) == body

    def exhaust():
        idle = []
        for _ in range(80):
            stream = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            opened.append(stream)
            idle.append(stream)
        wait(lambda: fd_count() == 64, timeout=2)
        assert process.poll() is None
        return idle, fd_count()

    try:
        wait(lambda: control_path.exists() or process.poll() is not None)
        assert process.poll() is None
        baseline = fd_count()
        held = [connection(), connection()]
        idle, peak = exhaust()
        control_result = []
        control_started = threading.Event()

        def control_status():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                    control.settimeout(5)
                    control.connect(str(control_path))
                    payload = json.dumps({"operation": "status"}).encode()
                    control.sendall(struct.pack(">I", len(payload)) + payload)
                    control_started.set()
                    size = struct.unpack(">I", read_exact(control, 4))[0]
                    assert size <= 8192
                    reply = json.loads(read_exact(control, size))
                    assert reply.get("capability") == "xbord-native-users-v1" and reply.get("code") == "ok"
                    control_result.append(True)
            except BaseException as error:
                control_result.append(repr(error))

        control_thread = threading.Thread(target=control_status)
        control_thread.start()
        assert control_started.wait(2)
        time.sleep(0.25)
        assert not control_result, "control request must be queued at the full child FD limit"
        for index, stream in enumerate(held):
            exchange(stream, b"existing stream survives FD exhaustion " + str(index).encode())
        assert process.poll() is None
        for stream in idle:
            stream.close()
            opened.remove(stream)
        control_thread.join(timeout=5)
        assert control_result == [True]
        wait(lambda: fd_count() <= baseline + 4)
        recovered = connection()
        exchange(recovered, b"new authentication after accept recovery")
        recovered.close()
        opened.remove(recovered)
        for stream in held:
            stream.close()
            opened.remove(stream)
        wait(lambda: fd_count() == baseline)
        # Re-enter the resource backoff, then signal it rather than waiting.
        idle, second_peak = exhaust()
        pending_control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        pending_control.settimeout(2)
        opened.append(pending_control)
        pending_control.connect(str(control_path))
        payload = json.dumps({"operation": "status"}).encode()
        pending_control.sendall(struct.pack(">I", len(payload)) + payload)
        time.sleep(0.25)
        assert process.poll() is None and fd_count() == 64
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=3)
        elapsed = time.monotonic() - started
        assert process.returncode == 0 and elapsed < 2 and not control_path.exists()
        report.update(result="PASS", baseline_fds=baseline, exhaustion_fds=peak,
                      existing_transfers_verified=2, new_authenticated_transfer_verified=True,
                      queued_control_during_exhaustion=True, control_after_recovery=True, fd_return_to_baseline=True,
                      second_exhaustion_fds=second_peak, shutdown_seconds=elapsed,
                      control_queued_during_shutdown=True, control_socket_cleanup=True)
    except BaseException as error:
        report.update(result="FAIL", error=repr(error))
        raise
    finally:
        for stream in opened:
            stream.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        log.close()
        origin.shutdown()
        origin.server_close()
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))


if __name__ == "__main__":
    main()
