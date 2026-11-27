"""Review the exact staged Git tree before publication. Never print secret values."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def check(repo, secret_roots):
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=repo)

    lock = json.loads(git('show', ':config/release-assets.lock.json'))
    origin = git('remote', 'get-url', 'origin').decode().strip()
    if origin.removesuffix('.git') != 'https://github.com/' + lock['repository']:
        raise ValueError('Git origin does not match the selected Release repository')
    secrets = []
    for base in secret_roots:
        secrets.extend(p.read_bytes().strip() for p in (base/'config').glob('*.token') if p.stat().st_size)
        for key in ('admin_ed25519', 'host_ed25519'):
            file = base/'private/lab-vm'/key
            if file.is_file():
                secrets.append(file.read_bytes().strip())
    paths = [n for n in git('ls-files', '-z').decode().split('\0') if n]
    legacy_hashes={}
    if 'docs/legacy-source-manifest.json' in paths:
        legacy_hashes={r['path']:r['sha256'] for r in json.loads(git('show',':docs/legacy-source-manifest.json'))['files']}
    # Literal FAKE/TEST markers in the original benign simulation and its reports, reviewed
    # by fingerprint. Only exact preserved files may retain them; no broad skip.
    legacy_fake_markers={
        '4d20f45c802bc87af0a873fa14cd77c36b968c358c900f9dd7e8d8121123b849',
        '2178094d9daf912b94c9790e15081be462e59ab78d5c1df4ccd549b9013ebc21',
        'a097fbabd842450464a6b426a7ded1869bf8e7e80f57f7ebbb5df43dfe5423c5',
    }
    contents = {}
    blocked, candidates, synthetic_markers = [], [], []
    patterns = [rb'(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}',
                rb'https?://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{20,}',
                rb'\b\d{8,12}:[A-Za-z0-9_-]{25,}',
                rb'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----']
    for name in paths:
        parts = Path(name).parts
        if (any(p in parts for p in ('private', '.venv', 'runs', '__pycache__')) or
            name.endswith(('.token', '.exe', '.dll', '.bin', '.vmdk', '.vmx', '.iso',
                           '.gguf', '.safetensors', '.research.zip', '.pt', '.pth')) or
            name.startswith(('evidence/local/', 'training/data/'))):
            blocked.append(name)
        data = git('show', ':' + name)
        contents[name] = data
        payloads = [data]
        if name.endswith('.pptx'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                payloads.extend(archive.read(n) for n in archive.namelist() if n.endswith('.xml'))
        if any(secret in p for secret in secrets if len(secret) > 20 for p in payloads):
            blocked.append(name)
        matches = [m.group(0) for pattern in patterns for p in payloads for m in re.finditer(pattern, p)]
        # Reviewed, deliberately fake marker in the historical audit, never an API credential.
        audit_marker = b'123456789:' + b'FAKE_REVIEW_TOKEN_NOT_A_REAL_SECRET'
        if matches:
            if name == 'audit/review_checks.py' and all(m == audit_marker for m in matches):
                synthetic_markers.append(name)
            elif (name.startswith('legacy/initial-version/') and
                  hashlib.sha256(data).hexdigest()==legacy_hashes.get(name) and
                  all(hashlib.sha256(m).hexdigest() in legacy_fake_markers for m in matches)):
                synthetic_markers.append(name)
            else:
                candidates.append(name)
    mismatches = []
    manifest = json.loads(contents['source-manifest.json'])
    expected_paths = {r['path'] for r in manifest} | {'source-manifest.json'}
    for record in manifest:
        data = contents.get(record['path'])
        if data is None or len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            mismatches.append(record['path'])
    unexpected = sorted(set(paths) - expected_paths)
    for record in json.loads(contents['docs/reference-manifest.json']):
        name = 'docs/reference/' + record['file']
        data = contents.get(name)
        if data is None or len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            mismatches.append(name)
    result = {'repository': lock['repository'], 'tracked_files': len(paths),
              'blocked_paths': sorted(set(blocked)), 'credential_pattern_candidates': sorted(set(candidates)),
              'hash_mismatches': sorted(set(mismatches)), 'unexpected_paths': unexpected,
              'original_references': 13, 'reviewed_synthetic_markers': synthetic_markers, 'remote_write': False,
              'scope': 'Git index bytes, known local tokens/keys, selected secret patterns, path allowlist, source/reference hashes'}
    print(json.dumps(result, ensure_ascii=False))
    return not (blocked or candidates or mismatches or unexpected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=ROOT if (ROOT/'.git').is_dir() else ROOT/'private/group-delivery-repo')
    parser.add_argument('--secret-root', type=Path, action='append', default=[])
    args = parser.parse_args()
    roots = [ROOT, ROOT/'private/publish-repo/coursework/StealerLab', *args.secret_root]
    raise SystemExit(0 if check(args.repo, roots) else 2)
