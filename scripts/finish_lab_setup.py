"""Install offline tools, take a clean snapshot, then enable the authenticated service."""
import json
from pathlib import Path
import subprocess
import time
from sync_vm import SSH, DEST, sync
from install_analysis_tools import main as install_analysis_tools

ROOT=Path(__file__).resolve().parents[1]
VMRUN=Path(r'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe')
VMX=ROOT/'private/lab-vm/StealerLab.vmx'
snapshot='clean-all-tools-offline-before-public-samples'


def remote(command):
    return subprocess.check_output(['ssh',*SSH,DEST,command],timeout=600,text=True)


def main():
    if not VMRUN.is_file() or not VMX.is_file():
        raise FileNotFoundError('Prepare/start the project VM first')
    current=subprocess.check_output([str(VMRUN),'listSnapshots',str(VMX)],text=True)
    if snapshot in current.splitlines():
        raise RuntimeError('Clean setup already completed; use Start-Lab. No snapshot or data replaced.')
    check=remote("test -f /opt/stealer-lab/BOOTSTRAP_READY && test -z \"$(ip route show default)\" && find /opt/stealer-lab/samples -maxdepth 1 -name 'public_*' -print")
    if check.strip():
        raise RuntimeError('Public samples already present. This cannot be called a clean pre-sample snapshot.')
    remote('sudo systemctl stop stealer-lab.service')
    subprocess.run(['scp',*SSH,'-r',str(ROOT/'private/lab-assets/extensions'),DEST+':/home/labadmin/'],check=True)
    subprocess.run(['scp',*SSH,str(ROOT/'scripts/install_extensions_vm.py'),str(ROOT/'scripts/activate_vm.py'),DEST+':/home/labadmin/'],check=True)
    print(remote('sudo python3 /home/labadmin/install_extensions_vm.py'),flush=True)
    install_analysis_tools()
    # Powered-off snapshot avoids lengthy live RAM snapshots on low-memory hosts.
    print('Tools installed. Shutting down this VM for a clean disk snapshot...',flush=True)
    subprocess.run(['ssh',*SSH,DEST,'sudo poweroff'],timeout=30,check=False)
    for _ in range(60):
        running=subprocess.check_output([str(VMRUN),'list'],text=True,timeout=10)
        if str(VMX).casefold() not in running.casefold():
            break
        time.sleep(1)
    else:
        raise RuntimeError('Guest did not shut down; no forced power-off performed')
    subprocess.run([str(VMRUN),'snapshot',str(VMX),snapshot],check=True,timeout=120)
    snapshots=subprocess.check_output([str(VMRUN),'listSnapshots',str(VMX)],text=True)
    if snapshot not in snapshots.splitlines():
        raise RuntimeError('Snapshot not observed')
    subprocess.run([str(VMRUN),'-T','ws','start',str(VMX),'nogui'],check=True,timeout=60)
    for _ in range(90):
        ready=subprocess.run(['ssh',*SSH,'-o','ConnectTimeout=2',DEST,
            'test -f /opt/stealer-lab/BOOTSTRAP_READY'],capture_output=True,timeout=5)
        if ready.returncode==0:
            break
        time.sleep(1)
    else:
        raise RuntimeError('Guest has not rebooted; inspect console before proceeding')
    print(remote('sudo python3 /home/labadmin/activate_vm.py'),flush=True)
    (ROOT/'evidence/local').mkdir(parents=True,exist_ok=True)
    sync()
    (ROOT/'evidence/local/setup-complete.json').write_text(json.dumps({'snapshot':snapshot,
        'public_samples_present_at_snapshot':False,'service_enabled':True},indent=2))
    print('VM prepared. Import encrypted public samples next.')


if __name__=='__main__':
    main()
