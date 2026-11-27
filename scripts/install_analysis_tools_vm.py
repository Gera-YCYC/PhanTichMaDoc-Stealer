"""Install verified DIE/FLOSS offline inside the isolated VM only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

BASE = Path('/home/labadmin/analysis-tools')
ROOT = Path('/opt/stealer-lab')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if os.name == 'nt' or not (ROOT/'BOOTSTRAP_READY').is_file():
        raise RuntimeError('This installer is for the prepared isolated Linux lab VM')
    if subprocess.check_output(['ip', 'route', 'show', 'default']).strip():
        raise RuntimeError('Default route present; preserve offline VM boundary')
    lock = json.loads((BASE/'analysis-tools.lock.json').read_text())
    required = {'floss-v3.2.0-linux.zip', 'Detect_It_Easy-4.0.0-x86_64.AppImage', 'die_4.0.0_noble_amd64.deb'}
    if {item['path'] for item in lock['assets']} != required:
        raise ValueError('Unexpected tool inventory; review installer before using another release')
    for item in lock['assets']:
        path = BASE/item['path']
        if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Tool asset hash/size mismatch: '+path.name)
    vendor = ROOT/'vendor/analysis-tools'
    vendor.mkdir(parents=True, exist_ok=True)
    target = vendor/'die-4.0.0-floss-3.2.0'
    lock_hash = digest(BASE/'analysis-tools.lock.json')
    if target.exists():
        receipt = json.loads((target/'install-receipt.json').read_text())
        if receipt['assets_lock_sha256'] != lock_hash or any(digest(target/name) != sha for name,sha in receipt['pinned_files'].items()):
            raise RuntimeError('Existing tool installation differs; no overwrite')
    else:
        with tempfile.TemporaryDirectory(prefix='install-', dir=vendor) as temp:
            build = Path(temp)
            appimage = BASE/'Detect_It_Easy-4.0.0-x86_64.AppImage'
            appimage.chmod(0o755)
            subprocess.run([str(appimage), '--appimage-extract'], cwd=build,
                           stdout=subprocess.DEVNULL, check=True, timeout=120)
            subprocess.run(['dpkg-deb', '-x', str(BASE/'die_4.0.0_noble_amd64.deb'), str(build/'deb')],
                           check=True, timeout=60)
            with zipfile.ZipFile(BASE/'floss-v3.2.0-linux.zip') as archive:
                if archive.namelist() != ['floss']:
                    raise ValueError('Unexpected FLOSS archive members')
                (build/'floss').write_bytes(archive.read('floss'))
            (build/'floss').chmod(0o755)
            pinned = {'floss':digest(build/'floss'), 'deb/usr/bin/diec':digest(build/'deb/usr/bin/diec')}
            receipt = {'assets_lock_sha256':lock_hash, 'pinned_files':pinned,
                       'die_version':'4.0.0', 'floss_version':'3.2.0', 'sample_executed':False}
            (build/'install-receipt.json').write_text(json.dumps(receipt, indent=2))
            build.rename(target)
    # TemporaryDirectory starts at 0700. The service runs as analyst, not root.
    # Keep vendor files root-owned/read-only while allowing directory traversal.
    target.chmod(0o755)
    for path in target.rglob('*'):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file():
            path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    config_path = ROOT/'config/vm.json'
    config = json.loads(config_path.read_text())
    config.update(diec=str(target/'deb/usr/bin/diec'), diec_sha256=receipt['pinned_files']['deb/usr/bin/diec'],
                  diec_library_dir=str(target/'squashfs-root/usr/lib'), diec_database=str(target/'deb/usr/lib/die/db'),
                  diec_version='4.0.0', floss=str(target/'floss'), floss_sha256=receipt['pinned_files']['floss'],
                  floss_version='3.2.0')
    config_path.write_text(json.dumps(config, indent=2))
    env = {**os.environ, 'LD_LIBRARY_PATH':config['diec_library_dir'], 'FLOSS_LOAD_VIV_WORKSPACE':'0'}
    for exe in (config['diec'], config['floss']):
        subprocess.run([exe, '--version'], env=env, check=True, timeout=30)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
