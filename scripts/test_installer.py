#!/usr/bin/env python3
"""Exercise the exact installer with real ELF archives in an offline target."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sha = lambda body: hashlib.sha256(body).hexdigest()


def read_package(path):
    with tarfile.open(path) as archive:
        return {item.name.removeprefix('xboard-node-rust/'): archive.extractfile(item).read() for item in archive.getmembers()}


def fixture_package(directory, files, version=None, unsafe=False):
    directory.mkdir()
    files = dict(files)
    if version:
        meta = json.loads(files['BUILDINFO.json'])
        meta['version'] = version
        files['BUILDINFO.json'] = (json.dumps(meta) + '\n').encode()
        files['VERSION'] = (version + '\n').encode()
        files['install.sh'] += ('\n# installer fixture ' + version + '\n').encode()
    files['SHA256SUMS'] = ''.join(sha(data) + '  ' + name + '\n' for name, data in sorted(files.items()) if name != 'SHA256SUMS').encode()
    name = 'xboard-node-rust-linux-' + json.loads(files['BUILDINFO.json'])['architecture'] + '.tar.gz'
    path = directory / name
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo('xboard-node-rust/' + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if unsafe:
            info = tarfile.TarInfo('xboard-node-rust/../../outside')
            info.size = 3
            archive.addfile(info, io.BytesIO(b'bad'))
    sums = directory / 'SHA256SUMS'
    sums.write_text(sha(path.read_bytes()) + '  ' + path.name + '\n')
    return path, sums


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'package', 'checksums', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, 'Run on an isolated Linux build host with sudo'
    files = read_package(args.package)
    assert sha(args.binary.read_bytes()) == json.loads(files['BUILDINFO.json'])['binary_sha256']
    cases = []
    with tempfile.TemporaryDirectory(prefix='xbr-install-test-') as temp:
        temp = Path(temp)
        # Execute the installer's actual function against a captured-style API
        # fixture; never assume GitHub's array order represents publication order.
        selector = 'select_version() {\n' + (ROOT / 'install.sh').read_text().split('select_version() {\n', 1)[1].split('\nprepare_package()', 1)[0]
        fixture = temp / 'release-list.json'
        page_two = temp / 'release-list-page-two.json'
        def select(items, arch='amd64', success=True, second_page=None, version='latest'):
            fixture.write_text(json.dumps(items))
            page_two.write_text(json.dumps(second_page or []))
            env = dict(os.environ, VERSION=version, ARCH=arch, WORK=str(temp),
                       FIXTURE=str(fixture), FIXTURE_PAGE_TWO=str(page_two), REPOSITORY='fixture/only')
            source = ('set -euo pipefail\nfetch() { [[ $VERSION == latest ]] || exit 9; case "$1" in *"&page=1") cp -- "$FIXTURE" "$2" ;; *) cp -- "$FIXTURE_PAGE_TWO" "$2" ;; esac; }\n'
                      'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n' + selector +
                      '\nselect_version\nprintf "%s\\n" "$VERSION"\n')
            proc = subprocess.run(['bash', '-c', source], env=env, capture_output=True, text=True, timeout=15)
            assert (proc.returncode == 0) == success, proc.stdout + proc.stderr
            return proc.stdout.strip()
        def published(tag, day, arches=('amd64', 'arm64'), draft=False, identifier=1):
            return dict(tag_name=tag, published_at=f'2026-10-{day:02d}T12:00:00Z', id=identifier, draft=draft,
                        assets=[{'name': name} for name in ['SHA256SUMS', *('xboard-node-rust-linux-' + a + '.tar.gz' for a in arches)]])
        old, new = published('v0.1.0-preview.9', 2), published('v0.1.0-preview.10', 3)
        assert select([old, new]) == select([new, old]) == 'v0.1.0-preview.10'
        cases.append('latest-release-ignores-API-array-order-and-numeric-tag-lexical-order')
        excluded = [published('v0.1.0-preview.12', 5, draft=True), published('v0.1.0-preview.11', 4, arches=('arm64',)), old, new]
        assert select(excluded) == 'v0.1.0-preview.10'
        assert select(excluded, 'arm64') == 'v0.1.0-preview.11'
        cases.append('latest-release-skips-draft-and-missing-architecture')
        malformed = published('v0.1.0-preview.13', 6)
        malformed['published_at'] = 'invalid'
        assert select([malformed, new]) == 'v0.1.0-preview.10'
        select([malformed, excluded[0]], success=False)
        assert select([new, published('v0.1.0-preview.11', 3, identifier=2)]) == 'v0.1.0-preview.11'
        cases.append('latest-release-rejects-unpublished-list-and-breaks-publication-ties-by-ID')
        invalid_tag = published('../untrusted', 7)
        assert select([invalid_tag, new]) == 'v0.1.0-preview.10'
        assert select([old] * 100, second_page=[new]) == 'v0.1.0-preview.10'
        cases.append('latest-release-scans-all-pages-and-skips-invalid-tag')
        assert select([], version='v0.1.0-preview.10') == 'v0.1.0-preview.10'
        select([], version='../invalid', success=False)
        cases.append('explicit-version-skips-release-discovery-and-validates-tag')
        target = temp / 'root'
        token = temp / 'token'
        token.write_text('installer fixture "$\\quoted token\' Unicode-Ω')
        token.chmod(0o600)
        def run(action, *options, success=True, root=target):
            proc = subprocess.run(['bash', str(ROOT / 'install.sh'), action, '--root', str(root), '--yes', *map(str, options)], capture_output=True, text=True, timeout=60)
            if (proc.returncode == 0) != success:
                # Fixture values only; never output env files or a user's token.
                raise AssertionError(action + ': ' + proc.stdout + proc.stderr)
            return proc
        common = ['--package', args.package.resolve(), '--checksums', args.checksums.resolve()]
        config_args = ['--panel', 'https://panel.example.invalid', '--node-id', '7', '--machine-id', '1', '--token-file', token]
        run('install', *common, *config_args)
        config = target / 'etc/xboard-node-rust/runtime.json'
        env = target / 'etc/xboard-node-rust/panel.env'
        state = target / 'var/lib/xboard-node-rust'
        current = target / 'usr/local/lib/xboard-node-rust/current'
        assert json.loads(config.read_text())['node_id'] == 7
        assert json.loads(config.read_text())['token_env'] == 'XBORD_PANEL_TOKEN'
        assert 'singbox_executable' not in json.loads(config.read_text())
        assert 'Unicode-Ω' in env.read_text()
        assert stat.S_IMODE(env.stat().st_mode) == stat.S_IMODE(config.stat().st_mode) == 0o600
        assert stat.S_IMODE(state.stat().st_mode) == 0o700
        assert sha((current / 'bin/xboard-node-rust').read_bytes()) == sha(args.binary.read_bytes())
        cases.append('fresh-install-private-config-and-exact-ELF')
        initial_config, initial_env = config.read_bytes(), env.read_bytes()
        run('install', *common, *config_args, success=False)
        assert config.read_bytes() == initial_config and env.read_bytes() == initial_env
        cases.append('duplicate-install-refused-without-overwrite')
        run('configure', '--panel', 'https://panel.example.invalid/path', success=False)
        assert config.read_bytes() == initial_config and env.read_bytes() == initial_env
        run('configure', '--panel', 'http://panel.example.invalid', success=False)
        cases.append('invalid-and-remote-cleartext-URLs-refused-with-old-config-retained')
        run('configure', '--node-id', '8')
        assert json.loads(config.read_text())['node_id'] == 8 and env.read_bytes() == initial_env
        backups = list((config.parent / 'backups').glob('*/panel.env'))
        assert backups and all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in backups)
        cases.append('configure-preserves-token-and-private-backup')
        run('configure', '--node-type', 'vless')
        assert json.loads(config.read_text())['node_type'] == 'vless' and 'machine_id' not in json.loads(config.read_text())
        run('configure', '--machine-id', '1')
        assert 'node_type' not in json.loads(config.read_text())
        cases.append('machine-and-legacy-auth-modes')
        before_update = config.read_bytes(), env.read_bytes()
        marker = state / 'retained-synthetic-state'
        marker.write_text('retain-me')
        replacement, replacement_sums = fixture_package(temp / 'replacement', files, 'v0.1.0-installer-fixture.2')
        run('update', '--package', replacement, '--checksums', replacement_sums)
        assert (current / 'VERSION').read_text().strip() == 'v0.1.0-installer-fixture.2'
        assert (config.read_bytes(), env.read_bytes()) == before_update and marker.read_text() == 'retain-me'
        cases.append('version-switch-preserves-config-and-state')
        run('rollback')
        assert (current / 'VERSION').read_bytes() == files['VERSION'] and marker.read_text() == 'retain-me'
        cases.append('program-rollback-retains-state')
        bad_files = dict(files)
        bad_meta = json.loads(bad_files['BUILDINFO.json']); bad_meta['state_format'] = 'incompatible-test-only'
        bad_files['BUILDINFO.json'] = json.dumps(bad_meta).encode()
        mismatch, mismatch_sums = fixture_package(temp / 'mismatch', bad_files, 'v0.1.0-installer-fixture.3')
        before_link = current.resolve()
        run('update', '--package', mismatch, '--checksums', mismatch_sums, success=False)
        assert current.resolve() == before_link
        cases.append('incompatible-state-format-refused-before-switch')
        # Ensure rollback validates the entire candidate path before executing it.
        previous = current.parent / 'previous'
        previous_bytes = previous.read_bytes()
        stub = current.parent / 'releases/v0.1.0-path-fixture'
        stub.mkdir()
        external = temp / 'external/v0.1.0-escape'; (external / 'bin').mkdir(parents=True)
        sentinel = temp / 'external-executed'
        executable = external / 'bin/xboard-node-rust'
        executable.write_text('#!/bin/bash\ntouch ' + str(sentinel) + '\n')
        executable.chmod(0o755)
        (external / 'BUILDINFO.json').write_bytes(files['BUILDINFO.json'])
        (external / 'VERSION').write_bytes(files['VERSION'])
        malicious = str(stub) + '/' + os.path.relpath(external, stub)
        previous.write_text(malicious + '\n')
        run('rollback', success=False)
        assert not sentinel.exists() and current.resolve() == before_link
        previous.write_bytes(previous_bytes)
        cases.append('rollback-path-traversal-refused-before-candidate-execution')
        # Stop a leftover ownership marker from authorizing an unrelated replacement.
        manager = target / 'usr/local/bin/xboard-rust'
        manager_bytes = manager.read_bytes()
        manager.write_text('#!/bin/bash\n# unrelated replacement\n')
        run('uninstall', success=False)
        assert current.is_symlink() and (target / 'etc/systemd/system/xboard-node-rust.service').exists()
        manager.write_bytes(manager_bytes)
        cases.append('foreign-manager-refused-despite-owned-marker')
        release_dir = current.parent / 'releases'
        preserved_releases = temp / 'preserved-releases'
        release_dir.rename(preserved_releases)
        escape = temp / 'release-escape'; escape.mkdir()
        release_dir.symlink_to(escape, target_is_directory=True)
        run('update', '--package', replacement, '--checksums', replacement_sums, success=False)
        assert not list(escape.iterdir())
        release_dir.unlink(); preserved_releases.rename(release_dir)
        cases.append('symlink-release-parent-refused')
        # Tampering is rejected before creating the installation directories.
        corrupt = temp / args.package.name
        corrupt.write_bytes(args.package.read_bytes() + b'corruption')
        rejected_root = temp / 'corrupt-root'
        run('install', '--package', corrupt, '--checksums', args.checksums, *config_args, success=False, root=rejected_root)
        assert not (rejected_root / 'etc/xboard-node-rust').exists()
        cases.append('archive-tampering-refused-before-install')
        unsafe, unsafe_sums = fixture_package(temp / 'unsafe', files, unsafe=True)
        rejected_root = temp / 'unsafe-root'
        run('install', '--package', unsafe, '--checksums', unsafe_sums, *config_args, success=False, root=rejected_root)
        assert not (temp / 'outside').exists() and not (rejected_root / 'etc/xboard-node-rust').exists()
        cases.append('tar-traversal-refused-before-extraction')
        unmanaged = temp / 'unmanaged-root/etc/xboard-node-rust'
        unmanaged.mkdir(parents=True); (unmanaged / 'keep').write_text('owned-elsewhere')
        run('install', *common, *config_args, success=False, root=temp / 'unmanaged-root')
        assert (unmanaged / 'keep').read_text() == 'owned-elsewhere'
        cases.append('unmanaged-existing-directory-preserved')
        real = temp / 'real-target'; real.mkdir()
        symlink_root = temp / 'symlink-root'; symlink_root.symlink_to(real, target_is_directory=True)
        run('install', *common, *config_args, success=False, root=symlink_root)
        assert not list(real.iterdir())
        cases.append('symlink-install-root-refused')
        lock_root = temp / 'lock-root'
        (lock_root / 'run').mkdir(parents=True)
        lock_escape = temp / 'lock-escape'; lock_escape.mkdir(mode=0o751)
        initial_mode = stat.S_IMODE(lock_escape.stat().st_mode)
        (lock_root / 'run/lock').symlink_to(lock_escape, target_is_directory=True)
        run('install', *common, *config_args, success=False, root=lock_root)
        assert not list(lock_escape.iterdir()) and stat.S_IMODE(lock_escape.stat().st_mode) == initial_mode
        cases.append('symlink-lock-parent-refused-without-external-write-or-chmod')
        run('check'); run('version')
        run('uninstall')
        assert not current.is_symlink() and not (target / 'usr/local/bin/xboard-rust').exists()
        assert config.exists() and env.exists() and marker.read_text() == 'retain-me'
        cases.append('uninstall-removes-entries-and-retains-config-data')
        run('install', *common, *config_args)
        assert marker.read_text() == 'retain-me'
        cases.append('reinstall-reuses-verified-archive-and-retained-state')
    report = {'result': 'PASS', 'scope': 'Exact installer, real ELF, isolated offline directory; fixture versions reuse the same binary; this does not prove cross-version data migrations or real panel billing',
        'cases': cases, 'binary_sha256': sha(args.binary.read_bytes()), 'package_sha256': sha(args.package.read_bytes()), 'installer_sha256': sha((ROOT / 'install.sh').read_bytes()), 'host_systemd_modified': False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': 'PASS', 'cases': len(cases), 'output': str(args.output)}))


if __name__ == '__main__':
    main()
