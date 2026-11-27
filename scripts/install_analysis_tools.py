"""Explicit maintainer update of pinned tools in this project's VM; no service restart."""
import json
from pathlib import Path
import subprocess
from fetch_setup_assets import fetch
from sync_vm import SSH, DEST

ROOT = Path(__file__).resolve().parents[1]


def main():
    lock = ROOT/'config/analysis-tools.lock.json'
    assets = json.loads(lock.read_text())['assets']
    paths = [fetch(item, ROOT/'private/lab-assets/analysis-tools', verify_only=True) for item in assets]
    subprocess.run(['ssh', *SSH, DEST, 'mkdir -p /home/labadmin/analysis-tools'], check=True, timeout=30)
    subprocess.run(['scp', *SSH, *map(str,paths), str(lock),
                    str(ROOT/'scripts/install_analysis_tools_vm.py'), DEST+':/home/labadmin/analysis-tools/'],
                   check=True, timeout=120)
    subprocess.run(['ssh', *SSH, DEST, 'sudo python3 /home/labadmin/analysis-tools/install_analysis_tools_vm.py'],
                   check=True, timeout=240)
    print('DIE/FLOSS installed offline. Sync source and verify before starting a new run.')


if __name__ == '__main__':
    main()
