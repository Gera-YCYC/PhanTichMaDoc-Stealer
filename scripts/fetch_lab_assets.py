"""Fetch pinned official lab runtime assets into C: workspace; never model weights."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "private" / "lab-assets"
OUT.mkdir(parents=True, exist_ok=True)
UBUNTU = "https://cloud-images.ubuntu.com/noble/20261017/"
NAME = "noble-server-cloudimg-amd64.vmdk"


def fetch(url: str, path: Path):
    if path.exists():
        return
    partial = path.with_suffix(path.suffix + ".partial")
    with urllib.request.urlopen(url, timeout=60) as response, partial.open("wb") as output:
        while data := response.read(1024 * 1024):
            output.write(data)
    partial.replace(path)
    print(f"Downloaded {path.name}: {path.stat().st_size} bytes", flush=True)


def sha(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        while data := handle.read(4 * 1024 * 1024):
            h.update(data)
    return h.hexdigest()


fetch(UBUNTU + "SHA256SUMS", OUT / "ubuntu-SHA256SUMS")
expected = next(line.split()[0] for line in (OUT / "ubuntu-SHA256SUMS").read_text().splitlines()
                if line.split()[-1].lstrip("*") == NAME)
fetch(UBUNTU + NAME, OUT / NAME)
actual = sha(OUT / NAME)
if actual != expected:
    raise RuntimeError("Ubuntu image hash mismatch")
print("Ubuntu image SHA256 verified", flush=True)
version = "11.2.0.10050"
url = f"https://api.nuget.org/v3-flatcontainer/ilspycmd.linux-x64/{version}/ilspycmd.linux-x64.{version}.nupkg"
fetch(url, OUT / "ilspy-linux.nupkg")
with zipfile.ZipFile(OUT / "ilspy-linux.nupkg") as archive:
    members = [name for name in archive.namelist() if name.endswith("/ilspycmd")]
    if len(members) != 1:
        raise RuntimeError(f"Unexpected ILSpy package members: {archive.namelist()}")
    (OUT / "ilspycmd").write_bytes(archive.read(members[0]))
receipt = {"ubuntu_url": UBUNTU + NAME, "sha256_expected": expected, "sha256_actual": actual,
           "checksum_source": "official HTTPS SHA256SUMS; GPG signature not separately verified",
           "ilspy_url": url, "ilspy_nupkg_sha256": sha(OUT / "ilspy-linux.nupkg"),
           "ilspy_binary_sha256": sha(OUT / "ilspycmd")}
(OUT / "asset-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
print(json.dumps(receipt), flush=True)
