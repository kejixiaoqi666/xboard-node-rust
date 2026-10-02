"""Loopback-only native checkpoint, frozen receipt and quiescence experiments.

Kills only fixture-owned processes. Checkpointed bytes, not unsaved crash tails.
Uses the official sing-box client; never changes production configuration.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import time
import traceback

import traffic_lab as traffic
import runtime_lab as lab


class Fixture(traffic.Fixture):
    def __init__(self, args, directory):
        super().__init__(args, directory)
        self.poll_seconds, self.report_seconds, self.checkpoint_ms = 30, 30, 100

    def native_book(self):
        return json.loads((self.state_dir / 'native-traffic.json').read_text())

    def checkpointed(self):
        try:
            book = self.native_book()
            return book['counters'] == self.expected and book['sequence'] == 0 and book['frozen'] is None
        except (FileNotFoundError, json.JSONDecodeError):
            return False

    def rpc(self, operation, **fields):
        payload = json.dumps(dict(operation=operation, **fields)).encode()
        errors = []
        for path in self.state_dir.glob('u-*.sock'):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                    stream.settimeout(3)
                    stream.connect(str(path))
                    stream.sendall(struct.pack('>I', len(payload)) + payload)
                    size = struct.unpack('>I', traffic.exact(stream, 4))[0]
                    assert 0 < size <= 256 * 1024
                    return json.loads(traffic.exact(stream, size))
            except (ConnectionRefusedError, FileNotFoundError) as error:
                errors.append(type(error).__name__)
        raise AssertionError(('no active native socket', errors))

    def restart_and_complete(self):
        self.poll_seconds, self.report_seconds = 1, 1
        self.start(self.args.controller)
        self.wait_complete()
        stable = len(self.reports)
        time.sleep(2.2)
        assert self.totals() == self.expected and len(self.reports) == stable
        self.stop_runtime()


def recovered(args, directory, kind):
    f = Fixture(args, directory)
    held = None
    try:
        f.start(args.controller)
        client = f.start_client(lab.user(1)['uuid'], 'client-a')
        time.sleep(.15)  # Let the initial empty report tick finish before payload.
        held = f.socks(client)
        f.echo(held, 1, 131089)
        lab.wait_for(f.checkpointed, timeout=5)
        book = f.native_book()
        epoch = book['epoch']
        assert not f.reports and not f.journal()['pending'] and f.journal()['flight'] is None
        frozen = None
        if kind == 'frozen-controller-native-crash':
            reply = f.rpc('traffic_snapshot')
            assert reply['code'] == 'ok'
            frozen = reply['snapshot']
            assert frozen['traffic'] == f.expected and frozen['epoch'] == epoch and frozen['sequence'] == 1
            assert f.native_book()['frozen'] == frozen
        if kind == 'native-crash':
            child = f.child()
            assert child is not None
            os.kill(child, signal.SIGKILL)
            lab.wait_for(lambda: not lab.port_open(f.node_port), timeout=5)
            f.stop_runtime()
        else:
            f.stop_runtime(crash=True)
        held.close()
        held = None
        saved = f.native_book()
        assert saved['counters'] == f.expected and saved['epoch'] == epoch
        f.restart_and_complete()
        final = f.native_book()
        assert final['epoch'] == epoch and final['counters'] == {} and final['frozen'] is None
        return {'result': 'PASS', 'failure': kind, 'expected': f.expected, 'reported': f.totals(),
                'reports': len(f.reports), 'native_epoch_preserved': True,
                'native_checkpoint_preceded_controller_collection': True,
                'frozen_receipt_recovered': frozen is not None,
                'repeated_collection_did_not_duplicate': True, 'unsaved_tail_lossless': False}
    finally:
        if held is not None:
            held.close()
        f.finish()


def quiescence(args, directory):
    f = Fixture(args, directory)
    held = None
    try:
        f.start(args.controller)
        client = f.start_client(lab.user(1)['uuid'], 'client-a')
        time.sleep(.15)
        held = f.socks(client)
        f.echo(held, 1, 65539)
        reply = f.rpc('traffic_quiesce')
        assert reply == {'capability': 'xbord-native-traffic-v1', 'code': 'ok', 'snapshot': None, 'quiesced': True}
        assert not lab.port_open(f.node_port)
        assert held.recv(1) == b''
        held.close()
        held = None
        first = f.native_book()
        assert first['counters'] == f.expected
        time.sleep(.15)
        assert f.native_book() == first  # No remaining writer after the success reply.
        rejected = False
        try:
            with f.socks(client):
                pass
        except (OSError, EOFError, AssertionError):
            rejected = True
        assert rejected
        snapshot = f.rpc('traffic_snapshot')['snapshot']
        assert snapshot['traffic'] == f.expected
        assert f.rpc('traffic_snapshot')['snapshot'] == snapshot
        # Leave the frozen receipt for the controller's durable collect/ACK.
        f.stop_runtime()
        assert f.journal()['pending'] == f.expected and f.native_book()['counters'] == {}
        f.restart_and_complete()
        return {'result': 'PASS', 'expected': f.expected, 'reported': f.totals(),
                'quiesced_confirmed': True, 'listener_closed': True, 'held_writer_ended': True,
                'new_authentication_denied': True, 'frozen_retry_stable': True,
                'final_drain_survived_restart': True}
    finally:
        if held is not None:
            held.close()
        f.finish()


def listener_replacement(args, directory):
    f = Fixture(args, directory)
    held = None
    try:
        f.poll_seconds = 1
        f.start(args.controller)
        client = f.start_client(lab.user(1)['uuid'], 'client-a')
        time.sleep(.15)
        held = f.socks(client)
        f.echo(held, 1, 32771)
        old_child, old_port = f.child(), f.node_port
        epoch = f.native_book()['epoch']
        f.node_port = lab.free_port()
        f.config['server_port'] = f.node_port
        f.config_tag = '"durable-listener-change"'
        lab.wait_for(lambda: f.child() is not None and f.child() != old_child and lab.port_open(f.node_port))
        assert not lab.port_open(old_port)
        assert held.recv(1) == b''
        held.close()
        held = None
        assert f.native_book()['epoch'] == epoch
        new_client = f.start_client(lab.user(2)['uuid'], 'client-b')
        with f.socks(new_client) as stream:
            f.echo(stream, 2, 8197)
        # Stop before the 30-second report; final drain must capture both generations.
        f.stop_runtime()
        assert f.journal()['pending'] == f.expected
        f.restart_and_complete()
        return {'result': 'PASS', 'expected': f.expected, 'reported': f.totals(),
                'native_epoch_preserved': True, 'old_listener_ended': True,
                'new_listener_authenticated': True, 'single_writer_restart_verified': True,
                'both_generations_durably_collected': True}
    finally:
        if held is not None:
            held.close()
        f.finish()


def main():
    parser = argparse.ArgumentParser()
    for name in ['controller', 'singbox', 'certificate-dir', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--domain', required=True)
    args = parser.parse_args()
    args.native, args.builtin = args.controller, True
    assert args.controller.is_absolute() and args.output.is_absolute() and not args.output.exists()
    args.output.mkdir(mode=0o700)
    report = {'result': 'RUNNING', 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'controller_sha256': hashlib.sha256(args.controller.read_bytes()).hexdigest(),
              'official_client_sha256': hashlib.sha256(args.singbox.read_bytes()).hexdigest(),
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'cases': {}, 'server_requires_go': False, 'production_panel_used': False,
              'unsaved_sigkill_tail_lossless': False, 'end_to_end_exactly_once_billing': False}
    try:
        for kind, short in [('native-crash', 'nc'), ('controller-native-crash', 'bc'),
                            ('frozen-controller-native-crash', 'fc')]:
            directory = args.output / short
            directory.mkdir(mode=0o700)
            report['cases'][kind] = recovered(args, directory, kind)
        for name, function, short in [('quiescence', quiescence, 'q'),
                                       ('listener-replacement', listener_replacement, 'lr')]:
            directory = args.output / short
            directory.mkdir(mode=0o700)
            report['cases'][name] = function(args, directory)
        report['result'] = 'PASS'
    except Exception:
        report['result'], report['error'] = 'FAIL', traceback.format_exc()
    (args.output / 'measurements.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
