#!/usr/bin/env python3
"""Build a hash-complete runtime archive, with exact dependency license notices."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'kejixiaoqi666/xboard-node-rust'
sha = lambda data: hashlib.sha256(data).hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def write_tar(path, prefix, files):
    with tarfile.open(path, 'w:gz') as archive:
        for name, body in sorted(files.items()):
            info = tarfile.TarInfo(prefix + '/' + name)
            info.size = len(body)
            info.mode = 0o755 if name in ['bin/xboard-node-rust', 'install.sh'] else 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(body))


def dependency_notices(target):
    tree = command('cargo', 'tree', '--locked', '--offline', '--target', target,
                   '--edges', 'normal', '-p', 'node-runtime', '--prefix', 'none', '--format', '{p}')
    selected = set(re.findall(r'^([a-zA-Z0-9_-]+) v([^\s]+)', tree, re.M))
    metadata = json.loads(command('cargo', 'metadata', '--locked', '--offline', '--format-version', '1', '--filter-platform', target))
    packages = {(p['name'], p['version']): p for p in metadata['packages']}
    files, entries = {}, []
    for identity in sorted(selected):
        package = packages[identity]
        if package['id'] in metadata['workspace_members']:
            continue
        base = Path(package['manifest_path']).parent
        notices = []
        for path in sorted(base.rglob('*')):
            if path.is_file() and re.match(r'^(LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT|UNLICENSE)([._-]|$)', path.name, re.I):
                name = identity[0] + '-' + identity[1] + '/' + path.relative_to(base).as_posix()
                body = path.read_bytes()
                files[name] = body
                notices.append({'path': name, 'sha256': sha(body)})
        if not notices:
            raise RuntimeError('Missing dependency license: ' + str(identity))
        entries.append({'name': identity[0], 'version': identity[1], 'license': package.get('license'), 'notice_files': notices})
    sysroot = Path(command('rustc', '--print', 'sysroot')) / 'share/doc/rust'
    toolchain_files = [sysroot / 'COPYRIGHT.html', sysroot / 'COPYRIGHT-library.html']
    toolchain_files += sorted(path for path in (sysroot / 'licenses').rglob('*') if path.is_file())
    if len(toolchain_files) < 4 or not all(path.is_file() for path in toolchain_files):
        raise RuntimeError('Rust notices missing; rustup component add rust-docs')
    for path in toolchain_files:
        files['rust-toolchain/' + path.relative_to(sysroot).as_posix()] = path.read_bytes()
    # Static musl/libgcc distributions also retain the build system's notices.
    for pattern in ['musl*/copyright', 'gcc-*-base/copyright', 'libgcc*/copyright']:
        for path in sorted(Path('/usr/share/doc').glob(pattern)):
            files['system/' + path.parent.name + '/COPYRIGHT'] = path.read_bytes()
    if target.endswith('musl') and not any(name.startswith('system/musl') for name in files):
        raise RuntimeError('Static musl license notice missing from /usr/share/doc')
    files['vendored/node-vision/LICENSE'] = (ROOT / 'crates/node-vision/LICENSE').read_bytes()
    files['vendored/node-vision/UPSTREAM.json'] = (ROOT / 'crates/node-vision/UPSTREAM.json').read_bytes()
    files['vendored/node-reality/LICENSE'] = (ROOT / 'crates/node-reality/LICENSE').read_bytes()
    files['vendored/node-reality/UPSTREAM.json'] = (ROOT / 'crates/node-reality/UPSTREAM.json').read_bytes()
    files['vendored/node-extended/LICENSE-shoes-MIT'] = (ROOT / 'crates/node-extended/LICENSE-shoes-MIT').read_bytes()
    files['vendored/node-extended/UPSTREAM.json'] = (ROOT / 'crates/node-extended/UPSTREAM.json').read_bytes()
    files['vendored/node-outbound/LICENSE'] = (ROOT / 'crates/node-outbound/LICENSE').read_bytes()
    files['vendored/node-outbound/NOTICE.md'] = (ROOT / 'crates/node-outbound/NOTICE.md').read_bytes()
    for name in ['LICENSE', 'LICENSE-SHOES', 'UPSTREAM.json', 'NOTICE.md']:
        files['vendored/node-quic/' + name] = (ROOT / 'crates/node-quic' / name).read_bytes()
    files['vendored/shadowsocks/LICENSE'] = (ROOT / 'vendor/shadowsocks/LICENSE').read_bytes()
    files['vendored/shadowsocks/UPSTREAM.json'] = (ROOT / 'vendor/shadowsocks/UPSTREAM.json').read_bytes()
    files['vendored/shadowsocks/crypto/LICENSE'] = (ROOT / 'vendor/shadowsocks/crypto/LICENSE').read_bytes()
    files['vendored/shadowsocks/crypto/UPSTREAM.json'] = (ROOT / 'vendor/shadowsocks/crypto/UPSTREAM.json').read_bytes()
    files['NOTICE_MANIFEST.json'] = (json.dumps({'target': target, 'dependencies': entries,
        'files': [{'path': name, 'sha256': sha(body)} for name, body in sorted(files.items())]}, indent=2) + '\n').encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, body in sorted(files.items()):
            info = tarfile.TarInfo('third-party-notices/' + name)
            info.size, info.mode = len(body), 0o644
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue(), len(entries)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, choices=['x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl', 'aarch64-unknown-linux-gnu'])
    parser.add_argument('--version', required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--notices', type=Path, help='Reuse an already verified notice archive for the same locked GNU build')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    if not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?', args.version):
        parser.error('Invalid version')
    architecture = 'amd64' if args.target.startswith('x86_64') else 'arm64'
    body = args.binary.read_bytes()
    if args.target.endswith('musl'):
        headers = command('readelf', '-l', str(args.binary.resolve()))
        if 'INTERP' in headers:
            raise RuntimeError('The musl release must be a static ELF without PT_INTERP')
    if args.notices:
        if not args.target.endswith('gnu'):
            parser.error('--notices reuse only applies to the historical GNU test candidate')
        notices, dependency_count = args.notices.read_bytes(), None
    else:
        notices, dependency_count = dependency_notices(args.target)
    try:
        commit = command('git', 'rev-parse', 'HEAD')
    except (subprocess.CalledProcessError, FileNotFoundError):
        commit = 'local-uncommitted-test-candidate'
    source_files = {}
    for pattern in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'crates/**/*.rs', 'crates/**/Cargo.toml', 'vendor/**/*.rs', 'vendor/**/Cargo.toml']:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file():
                source_files[path.relative_to(ROOT).as_posix()] = sha(path.read_bytes())
    metadata = {'repository': REPOSITORY, 'version': args.version, 'commit': commit,
        'architecture': architecture, 'target': args.target,
        'libc': 'musl' if args.target.endswith('musl') else 'gnu',
        'binary_bytes': len(body), 'binary_sha256': sha(body),
        'cargo_lock_sha256': sha((ROOT / 'Cargo.lock').read_bytes()),
        'runtime_dependency_notice_count': dependency_count,
        'state_format': 'native-traffic-v1-and-controller-outbox-v1',
        'source_files': source_files, 'rustc': command('rustc', '--version')}
    if metadata['libc'] == 'gnu':
        metadata['minimum_glibc'] = '2.39'
    files = {'bin/xboard-node-rust': body, 'install.sh': (ROOT / 'install.sh').read_bytes(),
        'VERSION': (args.version + '\n').encode(),
        'BUILDINFO.json': (json.dumps(metadata, indent=2) + '\n').encode(),
        'LICENSE': (ROOT / 'LICENSE').read_bytes(), 'NOTICE.md': (ROOT / 'NOTICE.md').read_bytes(),
        'examples/runtime.json': (ROOT / 'examples/runtime-rust-native.json').read_bytes(),
        'third-party-notices.tar.gz': notices}
    files['SHA256SUMS'] = ''.join(sha(data) + '  ' + name + '\n' for name, data in sorted(files.items())).encode()
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / ('xboard-node-rust-linux-' + architecture + '.tar.gz')
    if output.exists():
        raise RuntimeError('Refusing to overwrite an existing release archive: ' + str(output))
    write_tar(output, 'xboard-node-rust', files)
    digest = sha(output.read_bytes())
    (args.output / 'SHA256SUMS').write_text(digest + '  ' + output.name + '\n', encoding='utf-8')
    print(json.dumps({'asset': str(output), 'bytes': output.stat().st_size, 'sha256': digest, 'target': args.target}))


if __name__ == '__main__':
    main()
