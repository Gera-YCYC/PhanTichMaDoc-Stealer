"""Install pinned syntax parser wheels into the existing offline project VM."""
import json
from pathlib import Path
import subprocess
from fetch_setup_assets import fetch
from sync_vm import SSH, DEST

ROOT = Path(__file__).resolve().parents[1]
PREFIXES = ('wheels/tree_sitter-', 'wheels/tree_sitter_python-', 'wheels/tree_sitter_c_sharp-')


def main():
    assets = [r for r in json.loads((ROOT/'config/setup-assets.lock.json').read_text())['assets']
              if r['path'].startswith(PREFIXES)]
    if len(assets) != 3:
        raise ValueError('Expected exactly three pinned parser wheels')
    paths = [fetch(r, ROOT/'private/lab-assets') for r in assets]
    manifest = ROOT/'private/lab-assets/syntax-assets.json'
    manifest.write_text(json.dumps([{'file': p.name, 'sha256': r['sha256'], 'bytes': r['bytes']}
                                   for p,r in zip(paths, assets)], indent=2), encoding='utf-8')
    subprocess.run(['ssh', *SSH, DEST, 'mkdir -p /home/labadmin/syntax-tools'], check=True, timeout=20)
    subprocess.run(['scp', *SSH, *map(str, paths), str(manifest), str(ROOT/'scripts/install_syntax_tools_vm.py'),
                    DEST+':/home/labadmin/syntax-tools/'], check=True, timeout=60)
    subprocess.run(['ssh', *SSH, DEST, 'sudo python3 /home/labadmin/syntax-tools/install_syntax_tools_vm.py'],
                   check=True, timeout=30)
    print('Pinned parser wheels installed offline. Sync source before analysis.')


if __name__ == '__main__':
    main()
