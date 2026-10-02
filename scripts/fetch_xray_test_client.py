"""Fetch a pinned official test client; never bundled with the Rust server."""
import argparse, hashlib, io, json
from pathlib import Path
import urllib.request, zipfile
ASSETS = {
    'amd64': ('Xray-linux-64.zip', '23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'),
    'arm64': ('Xray-linux-arm64-v8a.zip', '4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c')}
parser=argparse.ArgumentParser();parser.add_argument('--arch',choices=ASSETS,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
name,digest=ASSETS[args.arch]
url='https://github.com/XTLS/Xray-core/releases/download/v26.3.27/'+name
with urllib.request.urlopen(url,timeout=60) as response: body=response.read(100*1024*1024+1)
assert len(body)<=100*1024*1024 and hashlib.sha256(body).hexdigest()==digest
with zipfile.ZipFile(io.BytesIO(body)) as archive: binary=archive.read('xray')
assert binary[:4]==b'\x7fELF' and not args.output.exists()
args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(binary);args.output.chmod(0o755)
print(json.dumps({'url':url,'archive_sha256':digest,'client_binary_sha256':hashlib.sha256(binary).hexdigest()}))
