"""VM-only bounded importer for pinned research archives; does not run samples."""
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

RECORDS = {
    'gomorrah': {'git_blob': '3b269dfaa659a1f230a2809f9d34661838e34e50',
                'member_basename': '2fd45662e3d0ec0077ea2fa66b6378f0.bin',
                'md5': '2fd45662e3d0ec0077ea2fa66b6378f0', 'sample': 'public_gomorrah.bin'},
    'agenttesla': {'git_blob': 'b81ca5b4b655fb5bdd23032ecd32cbd81c3d71ce',
                   'member_basename': 'b0f2d519ccae5bf1435264e0979770ce.bin',
                   'md5': 'b0f2d519ccae5bf1435264e0979770ce', 'sample': 'public_agenttesla.bin'},
}


def main():
    if not Path('/sys/class/dmi/id/product_name').read_text().strip().startswith('VMware'):
        raise ValueError('Public malware import is allowed only in this VMware lab')
    record = RECORDS[sys.argv[1]]
    blob = sys.stdin.buffer.read(8_000_001)
    if len(blob) > 8_000_000:
        raise ValueError('Archive exceeds import bound')
    git_hash = hashlib.sha1(b'blob ' + str(len(blob)).encode() + b'\0' + blob).hexdigest()
    if git_hash != record['git_blob']:
        raise ValueError('Archive differs from pinned public Git blob')
    root = Path('/opt/stealer-lab')
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        choices = [i for i in archive.infolist() if Path(i.filename).name == record['member_basename']]
        if len(choices) != 1 or choices[0].file_size > 16_777_216:
            raise ValueError('Expected one bounded sample member')
        data = archive.read(choices[0], pwd=b'infected')
    if hashlib.md5(data).hexdigest() != record['md5'] or not data.startswith(b'MZ'):
        raise ValueError('Published member identity does not match')
    target = root / 'samples' / record['sample']
    if target.exists() and target.read_bytes() != data:
        raise ValueError('Refusing to overwrite existing sample')
    target.write_bytes(data)
    target.chmod(0o440)
    import grp, os
    os.chown(target, 0, grp.getgrnam('analyst').gr_gid)
    receipt = {**record, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data),
               'archive_sha256': hashlib.sha256(blob).hexdigest(), 'executed': False,
               'scope': 'public replacement; not lecturer I/J'}
    (root / 'private' / ('import-' + sys.argv[1] + '.json')).write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
