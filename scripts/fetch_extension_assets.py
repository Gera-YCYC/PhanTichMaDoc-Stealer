"""Host-only downloads; VM remains offline. Check distro digests and pin upstream commits."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "private/lab-assets/extensions"
OUT.mkdir(parents=True, exist_ok=True)


def fetch(item):
    url, name, md5 = item
    path = OUT / name
    if not path.exists():
        with urllib.request.urlopen(url, timeout=60) as response:
            content = response.read(100_000_000)
        if md5 and hashlib.md5(content).hexdigest() != md5:
            raise ValueError(f"Distro package digest mismatch: {name}")
        path.write_bytes(content)
    content = path.read_bytes()
    if md5 and hashlib.md5(content).hexdigest() != md5:
        raise ValueError(f"Cached digest mismatch: {name}")
    return {"url": url, "name": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


if __name__ == "__main__":
    items = []
    for line in (ROOT / "private/lab-assets/build-package-uris.txt").read_text(encoding="utf-8-sig").splitlines():
        match = re.fullmatch(r"'([^']+)' (\S+) \d+ MD5Sum:([a-f0-9]{32})", line)
        if match:
            url, name, md5 = match.groups()
            items.append((url.replace("http://", "https://"), name, md5))
    items.extend([
        ("https://codeload.github.com/zrax/pycdc/tar.gz/b4289760970dbc399684f1e155ec6d1ea1cc787e", "pycdc-source.tar.gz", None),
        ("https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/815d31cf26bc71e62f851b2e549452e7b7c9dd98/pyinstxtractor.py", "pyinstxtractor.py", None),
        ("https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/815d31cf26bc71e62f851b2e549452e7b7c9dd98/LICENSE", "pyinstxtractor-LICENSE", None),
    ])
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for result in executor.map(fetch, items):
            results.append(result)
            print(result["name"], result["bytes"], flush=True)
    (OUT / "receipt.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
