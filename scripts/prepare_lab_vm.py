"""Create an offline, host-only Ubuntu lab on C:. Does not start or alter existing VMs."""
from __future__ import annotations
import base64
import io
import json
from pathlib import Path
import secrets
import shutil
import hashlib
import socket
import subprocess
import tarfile
import pycdlib

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "private/lab-assets"
VM = ROOT / "private/lab-vm"
if VM.exists() and any(VM.iterdir()):
    raise FileExistsError("Existing lab-vm directory: preserve its keys, seed and disks. Use Start-Lab, not provisioning.")
with socket.socket() as probe:
    probe.settimeout(1)
    if probe.connect_ex(("192.168.56.101",22)) == 0:
        raise RuntimeError("A VM already uses 192.168.56.101. Stop that lab before creating another one.")
asset_lock=json.loads((ROOT/"config/setup-assets.lock.json").read_text())
for item in asset_lock["assets"]:
    path=ASSETS/item["path"]
    with path.open("rb") as source:
        if hashlib.file_digest(source,"sha256").hexdigest()!=item["sha256"]:
            raise ValueError("Setup asset hash mismatch: "+item["path"])
VM.mkdir(parents=True, exist_ok=True)
KEY = VM / "admin_ed25519"
if not KEY.exists():
    subprocess.run([shutil.which("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", str(KEY)], check=True)
pubkey = KEY.with_suffix(".pub").read_text().strip()
host_key = VM / "host_ed25519"
subprocess.run([shutil.which("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)], check=True)
host_public = " ".join(host_key.with_suffix(".pub").read_text().split()[:2])
(VM / "known_hosts").write_text("192.168.56.101 " + host_public + "\n", encoding="utf-8")
host_private_yaml = "\n".join("    " + line for line in host_key.read_text().splitlines())
token_path = ROOT / "config/lab.token"
if not token_path.exists():
    token_path.write_text(secrets.token_urlsafe(36), encoding="utf-8")
token = token_path.read_text().strip()
config = json.loads((ROOT / "config/vm.example.json").read_text())
config.update(sample_dir="/opt/stealer-lab/samples", evidence_dir="/opt/stealer-lab/private/tool-evidence",
              ilspycmd="/opt/stealer-lab/bin/ilspycmd", page_chars=2800, max_sample_bytes=32000000)
config["isolation_attestation"].update(host_only_network=True, no_default_gateway=True,
    shared_folders_disabled=True, clipboard_disabled=True, clean_snapshot_created=False)
(ROOT / "config/vm.linux.local.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

payload = VM / "payload.tar"
with tarfile.open(payload, "w") as tar:
    for folder in ("stealer_agent", "vm_tools"):
        for path in [*(ROOT / folder).glob("*.py"), *(ROOT / folder).glob("code_ranker.json")]:
            tar.add(path, arcname=str(path.relative_to(ROOT)).replace("\\", "/"))
    for item in asset_lock["assets"]:
        if item["path"].startswith("wheels/"):
            path=ASSETS/item["path"]
            tar.add(path, arcname="wheels/" + path.name)
    tar.add(ASSETS / "ilspycmd", arcname="bin/ilspycmd")
    tar.add(ROOT / "config/vm.linux.local.json", arcname="config/vm.json")
    for path in (ROOT / "fixtures/safe").glob("*"):
        if path.suffix.lower() in (".py", ".dll"):
            tar.add(path, arcname="samples/" + path.name)
    environment = f"STEALER_LAB_TOKEN={token}\n".encode()
    info = tarfile.TarInfo("config/server.env")
    info.mode, info.size = 0o600, len(environment)
    tar.addfile(info, io.BytesIO(environment))

bootstrap = '''import os, pathlib, subprocess, tarfile, zipfile
root=pathlib.Path('/opt/stealer-lab')
root.mkdir(parents=True,exist_ok=True)
with tarfile.open('/mnt/stealer-seed/payload.tar') as archive:
    archive.extractall(root,filter='data')
deps=root/'deps'
deps.mkdir(exist_ok=True)
for wheel in (root/'wheels').glob('*.whl'):
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(deps)
os.chmod(root/'bin/ilspycmd',0o755)
(root/'private/tool-evidence').mkdir(parents=True,exist_ok=True)
(root/'samples').mkdir(exist_ok=True)
subprocess.run(['chown','-R','analyst:analyst',str(root/'private'),str(root/'samples')],check=True)
unit=''' + repr("""[Unit]
Description=StealerLab VM Static Tool Server
After=network-online.target
[Service]
Type=simple
User=analyst
WorkingDirectory=/opt/stealer-lab
Environment=PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps
EnvironmentFile=/opt/stealer-lab/config/server.env
ExecStart=/usr/bin/python3 -m vm_tools.server --config /opt/stealer-lab/config/vm.json
Restart=no
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/stealer-lab/private /opt/stealer-lab/samples
[Install]
WantedBy=multi-user.target
""") + '''
pathlib.Path('/etc/systemd/system/stealer-lab.service').write_text(unit)
subprocess.run(['systemctl','daemon-reload'],check=True)
# Server remains disabled until clean snapshot evidence is recorded by host.
pathlib.Path('/opt/stealer-lab/BOOTSTRAP_READY').write_text('offline setup complete; snapshot pending\\n')
'''
user_data = f'''#cloud-config
hostname: stealer-lab
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
ssh_keys:
  ed25519_private: |
{host_private_yaml}
  ed25519_public: {host_public}
users:
  - name: labadmin
    groups: [adm]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: true
    ssh_authorized_keys:
      - {pubkey}
  - name: analyst
    shell: /usr/sbin/nologin
    lock_passwd: true
package_update: false
package_upgrade: false
runcmd:
  - [mkdir, -p, /mnt/stealer-seed]
  - [mount, -o, ro, /dev/sr0, /mnt/stealer-seed]
  - [python3, /mnt/stealer-seed/bootstrap.py]
'''
network = '''version: 2
ethernets:
  lab0:
    match:
      macaddress: "00:50:56:38:04:10"
    set-name: lab0
    dhcp4: false
    dhcp6: false
    addresses: [192.168.56.101/24]
    link-local: []
'''
meta = "instance-id: stealer-lab-20261127-v1\nlocal-hostname: stealer-lab\n"
iso = pycdlib.PyCdlib()
iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
buffers=[]
for name, raw in (("user-data",user_data.encode()),("meta-data",meta.encode()),
                  ("network-config",network.encode()),("bootstrap.py",bootstrap.encode())):
    stream=io.BytesIO(raw)
    buffers.append(stream)
    iso.add_fp(stream,len(raw),iso_path="/"+name.upper().replace("-","_")+";1",rr_name=name,joliet_path="/"+name)
iso.add_file(str(payload),iso_path="/PAYLOAD.TAR;1",rr_name="payload.tar",joliet_path="/payload.tar")
iso.write(str(VM/"seed.iso"))
iso.close()
disk = VM / "lab.vmdk"
if not disk.exists():
    diskmanager=Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe")
    subprocess.run([str(diskmanager),"-r",str(ASSETS/"noble-server-cloudimg-amd64.vmdk"),"-t","0",str(disk)],check=True)
vmx = VM / "StealerLab.vmx"
if not vmx.exists():
    vmx.write_text('''.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "19"
displayName = "StealerLab-Static-C"
guestOS = "ubuntu-64"
memsize = "2048"
numvcpus = "2"
firmware = "efi"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
scsi0:0.present = "TRUE"
scsi0:0.fileName = "lab.vmdk"
sata0.present = "TRUE"
sata0:0.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "seed.iso"
ethernet0.present = "TRUE"
ethernet0.connectionType = "hostonly"
ethernet0.vnet = "VMnet1"
ethernet0.virtualDev = "e1000"
ethernet0.addressType = "static"
ethernet0.address = "00:50:56:38:04:10"
ethernet0.startConnected = "TRUE"
usb.present = "FALSE"
sound.present = "FALSE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
sharedFolder.maxNum = "0"
tools.syncTime = "FALSE"
uuid.action = "create"
msg.autoAnswer = "TRUE"
''',encoding="utf-8")
print(json.dumps({"vmx":str(vmx),"seed_iso":str(VM/'seed.iso'),"private_admin_key":str(KEY),
                  "tool_token_file":str(token_path),"snapshot":"pending"},indent=2))
