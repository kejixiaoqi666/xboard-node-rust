#!/usr/bin/env python3
"""Combine independently built architecture assets, never duplicate checksums."""
import hashlib
from pathlib import Path
import shutil
import sys

source, destination = map(Path, sys.argv[1:])
destination.mkdir(parents=True, exist_ok=True)
checksums = []
for arch in ['amd64', 'arm64']:
    directory = source / ('linux-' + arch)
    archive = directory / ('xboard-node-rust-linux-' + arch + '.tar.gz')
    expected = (directory / 'SHA256SUMS').read_text().strip()
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert expected == digest + '  ' + archive.name
    shutil.copy2(archive, destination / archive.name)
    checksums.append(expected)
    for prefix in ['installer-tests-', 'systemd-tests-']:
        path = directory / (prefix + arch + '.json')
        shutil.copy2(path, destination / path.name)
root = Path(__file__).resolve().parents[1]
shutil.copy2(root / 'install.sh', destination / 'install.sh')
checksums.append(hashlib.sha256((destination / 'install.sh').read_bytes()).hexdigest() + '  install.sh')
(destination / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n')
print('Verified both architecture archives; combined release checksums written')
