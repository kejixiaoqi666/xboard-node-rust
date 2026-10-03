"""Fetch strictly pinned official QA clients, outside the shipped Rust server.

Example: python fetch_clients.py --client sing-box --platform linux-arm64
         --output /tmp/qa-clients/sing-box
Existing output is reused only when its independently pinned binary SHA matches.
"""
import argparse
import hashlib
import json
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_upstream_checksum(asset):
    request = urllib.request.Request(
        asset["checksum_source"],
        headers={"User-Agent": "xboard-rust-compatibility-test"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        evidence = response.read(1024 * 1024 + 1)
    if len(evidence) > 1024 * 1024:
        raise RuntimeError("official checksum metadata exceeds bounded size")
    if asset["client"] == "sing-box":
        release = json.loads(evidence)
        entry = next(
            item for item in release["assets"] if item["name"] == asset["archive"]
        )
        if entry.get("digest") != "sha256:" + asset["archive_sha256"]:
            raise RuntimeError("sing-box official release digest differs from the fixed archive pin")
    elif asset["archive_sha256"] not in evidence.decode("ascii"):
        raise RuntimeError("Xray upstream .dgst checksum differs from the fixed archive pin")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=("sing-box", "xray"), required=True)
    parser.add_argument("--platform", choices=("windows-amd64", "linux-amd64", "linux-arm64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    lock = json.loads(Path(__file__).with_name("clients-lock.json").read_text(encoding="utf-8"))
    asset = next(item for item in lock["assets"] if item["client"] == args.client and item["platform"] == args.platform)
    output = args.output.resolve()
    if output.exists():
        if not output.is_file() or digest_file(output) != asset["binary_sha256"]:
            raise RuntimeError("existing client differs from its fixed binary SHA; preserve it and choose a fresh output")
        print(json.dumps(dict(asset, output=str(output), cached=True)))
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xboard-official-client-") as temporary:
        archive = Path(temporary) / asset["archive"]
        digest = hashlib.sha256()
        size = 0
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "xboard-rust-compatibility-test"})
        with urllib.request.urlopen(request, timeout=45) as response, archive.open("xb") as destination:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 100 * 1024 * 1024:
                    raise RuntimeError("official archive exceeds bounded download size")
                digest.update(chunk)
                destination.write(chunk)
        if digest.hexdigest() != asset["archive_sha256"]:
            raise RuntimeError("archive differs from the pinned official release checksum")
        verify_upstream_checksum(asset)
        if archive.name.endswith(".zip"):
            owner = zipfile.ZipFile(archive)
            entry = owner.getinfo(asset["member"])
            if entry.is_dir() or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise RuntimeError("client zip entry must be a regular file")
            source = owner.open(entry)
        else:
            owner = tarfile.open(archive, "r:gz")
            entry = owner.getmember(asset["member"])
            if not entry.isfile():
                raise RuntimeError("client tar entry must be a regular file")
            source = owner.extractfile(entry)
        binary = Path(temporary) / "verified-binary"
        size = 0
        with owner, source, binary.open("xb") as destination:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > 300 * 1024 * 1024:
                    raise RuntimeError("client exceeds bounded extraction size")
                destination.write(chunk)
        if digest_file(binary) != asset["binary_sha256"]:
            raise RuntimeError("extracted binary differs from the independently pinned SHA")
        with binary.open("rb") as source, output.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
        output.chmod(0o755)
    print(json.dumps(dict(asset, output=str(output), cached=False)))


if __name__ == "__main__":
    main()
