"""Loopback-only Rust payload accounting and durable report acceptance.

Real official clients; synthetic users/tokens; private HTTPS panel fixture.
No production panel, service, firewall, host mapping or resource-limit writes.
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
import threading
import time
import traceback

import native_users_lab as native
import runtime_lab as lab

def exact(stream, size):
    result = bytearray()
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part: raise EOFError("truncated echo")
        result.extend(part)
    return bytes(result)

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            while True:
                data = self.request.recv(65536)
                if not data: return
                self.request.sendall(data)
        except (OSError, EOFError): pass

class Fixture(native.Fixture):
    def __init__(self, args, directory, protocol="vless", tls=False):
        # Unix-domain sockets have a bounded path length; keep fixture state short.
        super().__init__(args, directory, 2, directory / "s", True, protocol, tls)
        self.origin.RequestHandlerClass = Echo
        self.reports, self.expected = [], {}
        self.report_lock = threading.Lock()
        self.mode = "success"
        self.poll_seconds, self.report_seconds, self.checkpoint_ms = 1, 1, 1000
        self.close_http = False
        self.report_entered, self.report_release = threading.Event(), threading.Event()
        parent, fixture = self.panel.RequestHandlerClass, self
        class Panel(parent):
            def end_headers(self):
                if fixture.close_http:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                super().end_headers()

            def do_POST(self):
                if self.path != "/api/v2/server/report": return super().do_POST()
                size = int(self.headers.get("Content-Length",0))
                assert 0 < size < 256 * 1024
                body = json.loads(self.rfile.read(size))
                assert body.get("token") == lab.TOKEN and body.get("node_id") == 7 and body.get("machine_id") == 1
                assert set(body) == {"token","node_id","machine_id","traffic"}
                assert body["traffic"] and len(body["traffic"]) <= 512
                for identity, values in body["traffic"].items():
                    assert int(identity) > 0 and str(int(identity)) == identity
                    assert len(values) == 2 and all(isinstance(n,int) and 0 <= n <= 2**63-1 for n in values)
                with fixture.report_lock: fixture.reports.append(body["traffic"])
                fixture.report_entered.set()
                if fixture.mode == "lost":
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                if fixture.mode == "stall": fixture.report_release.wait(15)
                self.send_response(200); self.send_header("Content-Length","13"); self.end_headers()
                try: self.wfile.write(b'{"data":true}')
                except OSError: pass
        self.panel.RequestHandlerClass = Panel
        original_proxy = self.proxy.RequestHandlerClass
        self.proxy.reject_connection = False
        class Proxy(original_proxy):
            def handle(self):
                if self.server.reject_connection:
                    self.request.settimeout(2); self.request.recv(4096)
                    self.request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    return
                super().handle()
        self.proxy.RequestHandlerClass = Proxy

    def start(self, executable):
        settings = {"panel_url":"https://"+self.proxy.authority,"token_env":"XBORD_PANEL_TOKEN",
            "machine_id":1,"node_id":7,"state_dir":str(self.state_dir),"poll_seconds":self.poll_seconds,
            "report_seconds":self.report_seconds,"traffic_checkpoint_ms":self.checkpoint_ms,"traffic_reporting":True}
        path = self.run / "runtime.json"; path.write_text(json.dumps(settings))
        env = {k:v for k,v in os.environ.items() if k.lower() not in ("http_proxy","https_proxy","all_proxy","no_proxy")}
        env.update({"XBORD_PANEL_TOKEN":lab.TOKEN,"HTTPS_PROXY":"http://127.0.0.1:%s"%self.proxy.server_address[1],"NO_PROXY":""})
        self.runtime = self.spawn([str(executable),"--config",str(path)],env,"runtime-%s"%len(self.processes))
        lab.wait_for(lambda: lab.port_open(self.node_port) and self.child() is not None)
        assert (Path('/proc')/str(self.child())/'exe').samefile(executable)
        return self.runtime.pid

    def socks(self, port):
        stream = socket.create_connection(("127.0.0.1",port),timeout=5); stream.settimeout(5)
        stream.sendall(b"\x05\x01\x00"); assert exact(stream,2) == b"\x05\x00"
        stream.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+struct.pack(">H",self.origin.server_address[1]))
        header = exact(stream,4); assert header[:2] == b"\x05\x00"
        if header[3] == 1: exact(stream,6)
        elif header[3] == 4: exact(stream,18)
        else: raise AssertionError("unexpected SOCKS address")
        return stream

    def echo(self, stream, index, length):
        body = bytes((i*17+index)%251 for i in range(length))
        stream.sendall(body); assert exact(stream,len(body)) == body
        identity = str(lab.user(index)["id"])
        counts = self.expected.setdefault(identity,[0,0]); counts[0] += length; counts[1] += length

    def totals(self):
        totals = {}
        with self.report_lock:
            for report in self.reports:
                for identity, counts in report.items():
                    total = totals.setdefault(identity,[0,0]); total[0] += counts[0]; total[1] += counts[1]
        return totals

    def journal(self): return json.loads((self.state_dir/'traffic.json').read_text())
    def removed_published(self):
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as control:
                control.settimeout(2); control.connect(str(next(self.state_dir.glob('u-*.sock'))))
                payload = b'{"operation":"status"}'
                control.sendall(struct.pack('>I',len(payload))+payload)
                size = struct.unpack('>I',exact(control,4))[0]; assert size <= 8192
                reply = json.loads(exact(control,size))
            for path in self.state_dir.glob('candidate-*.json'):
                data = path.read_bytes()
                if hashlib.sha256(data).hexdigest() == reply['digest']:
                    users = json.loads(data)['inbounds'][0]['users']
                    return len(users) == 1 and users[0]['name'] == str(lab.user(2)['id'])
        except (OSError,StopIteration,json.JSONDecodeError,EOFError): pass
        return False
    def batch_stage(self, stage):
        try: return (self.journal().get('flight') or {}).get('stage') == stage
        except (FileNotFoundError,json.JSONDecodeError): return False
    def wait_complete(self):
        lab.wait_for(lambda: self.totals() == self.expected and not self.journal()['pending'] and self.journal()['flight'] is None,timeout=15)
    def stop_runtime(self, crash=False):
        process = self.runtime
        if crash:
            os.killpg(process.pid,signal.SIGKILL)
        else: process.send_signal(signal.SIGTERM)
        code = process.wait(timeout=5)
        if not crash: assert code == 0, (code,(self.run/('runtime-%s.log'% (len(self.processes)-1))).exists())
        lab.wait_for(lambda: not lab.port_open(self.node_port),timeout=5)
    def resolve(self, delivered=True):
        batch = self.journal()['flight']; assert batch and batch['stage'] == 'uncertain'
        command = [str(self.args.controller),'--config',str(self.run/'runtime.json'),'--traffic-resolve',str(batch['id']),
            'delivered' if delivered else 'not-delivered']
        result = subprocess.run(command,capture_output=True,text=True,timeout=5,check=True)
        if delivered: assert json.loads(result.stdout)['batch'] is None
        else: assert json.loads(result.stdout)['batch']['stage'] == 'prepared'
    def finish(self):
        self.report_release.set()
        self.close()
        assert all(p.poll() is not None for p in self.processes)

def normal(args, directory, protocol, tls):
    fixture = Fixture(args,directory,protocol,tls)
    try:
        fixture.start(args.controller)
        first = fixture.start_client(lab.user(1)['uuid'],'client-a')
        second = fixture.start_client(lab.user(2)['uuid'],'client-b')
        held = fixture.socks(first); fixture.echo(held,1,200003)
        # Periodic accounting must include an open, long-lived connection.
        lab.wait_for(lambda: fixture.totals().get(str(lab.user(1)['id'])) == [200003,200003])
        old_child = fixture.child()
        fixture.users = [lab.user(2)]; fixture.user_tag += 1
        lab.wait_for(fixture.removed_published)
        assert fixture.child() == old_child
        fixture.echo(held,1,3997); held.shutdown(socket.SHUT_WR); assert held.recv(1) == b''; held.close()
        with fixture.socks(second) as stream: fixture.echo(stream,2,73781)
        rejected = False
        try:
            with fixture.socks(first) as stream:
                stream.sendall(b'removed-user'); rejected = stream.recv(12) != b'removed-user'
        except (OSError,EOFError): rejected = True
        assert rejected
        fixture.wait_complete(); fixture.stop_runtime()
        return {'result':'PASS','expected':fixture.expected,'reported':fixture.totals(),'reports':len(fixture.reports),
            'live_connection_counted':True,'removed_user_old_connection_accounted':True,'child_preserved':True}
    finally: fixture.finish()

def uncertain(args, directory, mode):
    fixture = Fixture(args,directory)
    try:
        fixture.mode = 'lost' if mode == 'lost' else 'stall'
        fixture.start(args.controller); client = fixture.start_client(lab.user(1)['uuid'],'client-a')
        with fixture.socks(client) as stream: fixture.echo(stream,1,98317)
        assert fixture.report_entered.wait(8)
        if mode == 'lost': lab.wait_for(lambda: fixture.batch_stage('uncertain'))
        else: lab.wait_for(lambda: fixture.batch_stage('sending'))
        captured = len(fixture.reports); assert captured == 1
        before = fixture.journal()['flight']['id']
        started = time.monotonic(); fixture.stop_runtime(crash=mode == 'crash')
        shutdown_ms = round((time.monotonic()-started)*1000,3)
        if mode != 'crash': assert shutdown_ms < 2000
        fixture.report_release.set(); fixture.mode = 'success'; fixture.start(args.controller)
        lab.wait_for(lambda: fixture.batch_stage('uncertain')); time.sleep(2.2)
        assert len(fixture.reports) == captured and fixture.journal()['flight']['id'] == before
        with fixture.socks(client) as stream: fixture.echo(stream,1,1379)
        lab.wait_for(lambda: str(lab.user(1)['id']) in fixture.journal()['pending'])
        assert len(fixture.reports) == captured
        fixture.stop_runtime(); fixture.resolve(delivered=True); fixture.start(args.controller)
        fixture.wait_complete(); fixture.stop_runtime()
        return {'result':'PASS','failure':mode,'expected':fixture.expected,'reported':fixture.totals(),
            'reports':len(fixture.reports),'uncertain_batch_id':before,'automatic_retries_while_uncertain':0,
            'shutdown_ms':shutdown_ms,'durably_collected_only':True,'operator_reconciliation_verified':True}
    finally: fixture.finish()

def not_sent(args,directory):
    fixture = Fixture(args,directory)
    try:
        # Disable pooled tunnels before injecting a CONNECT failure; an idle
        # keep-alive tunnel otherwise bypasses the proxy's new-connection gate.
        fixture.close_http = True
        fixture.start(args.controller); client = fixture.start_client(lab.user(1)['uuid'],'client-a')
        fixture.proxy.reject_connection = True
        with fixture.socks(client) as stream: fixture.echo(stream,1,123457)
        lab.wait_for(lambda: fixture.batch_stage('prepared')); time.sleep(1.2)
        assert not fixture.reports
        before = fixture.journal()['flight']['id']
        fixture.proxy.reject_connection = False
        fixture.wait_complete(); fixture.stop_runtime()
        return {'result':'PASS','expected':fixture.expected,'reported':fixture.totals(),'reports':len(fixture.reports),
            'retained_prepared_batch_id':before,'confirmed_not_sent_retry':True}
    finally: fixture.finish()

def main():
    parser = argparse.ArgumentParser()
    for name in ['controller','singbox','certificate-dir','output']: parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--domain',required=True)
    args = parser.parse_args(); args.native,args.builtin = args.controller,True
    assert args.controller.is_absolute() and args.output.is_absolute() and not args.output.exists()
    args.output.mkdir(mode=0o700)
    report = {'result':'RUNNING','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'controller_sha256':hashlib.sha256(args.controller.read_bytes()).hexdigest(),
        'official_client_sha256':hashlib.sha256(args.singbox.read_bytes()).hexdigest(),
        'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'cases':{},
        'server_requires_go':False,'production_panel_used':False,'unsampled_sigkill_tail_lossless':False}
    try:
        for name,protocol,tls in [('vless','vless',False),('vless-tls','vless',True),('trojan-tls','trojan',True)]:
            directory = args.output/name; directory.mkdir(mode=0o700)
            report['cases'][name] = normal(args,directory,protocol,tls)
        for mode in ['lost','cancel','crash']:
            directory = args.output/mode; directory.mkdir(mode=0o700)
            report['cases'][mode] = uncertain(args,directory,mode)
        directory = args.output/'not-sent'; directory.mkdir(mode=0o700)
        report['cases']['not-sent'] = not_sent(args,directory)
        report['result'] = 'PASS'
    except Exception:
        report['result'],report['error'] = 'FAIL',traceback.format_exc()
    (args.output/'measurements.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report)); return 0 if report['result'] == 'PASS' else 1

if __name__ == '__main__': raise SystemExit(main())
