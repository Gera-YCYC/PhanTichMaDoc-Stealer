"""Fail closed outside a VM. Operator attestations supplement, not replace, checks."""
from __future__ import annotations

import json
import os
import platform
import subprocess
from pathlib import Path


def inspect_isolation(config: dict) -> dict:
    identity = ""
    gateways = []
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            identity = " ".join(str(winreg.QueryValueEx(key, item)[0])
                                for item in ("SystemManufacturer", "SystemProductName"))
        command = "Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Select-Object -ExpandProperty NextHop | ConvertTo-Json -Compress"
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, text=True, timeout=10, check=True,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        gateways = json.loads(result.stdout) if result.stdout.strip() else []
    elif platform.system() == "Linux":
        identity = " ".join(Path(p).read_text().strip() for p in (
            "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"))
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 1:
                gateways.append(fields[2])
        for line in Path("/proc/net/ipv6_route").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00" and fields[-1] != "lo":
                # Kernel's unreachable default (flag reject) is not a usable route.
                if not (int(fields[8], 16) & 0x200):
                    gateways.append(fields[4])
    else:
        raise RuntimeError("Unsupported VM OS")
    low = identity.lower()
    is_vm = any(marker in low for marker in ("vmware", "virtualbox", "qemu", "kvm")) or (
        "microsoft" in low and "virtual machine" in low)
    attestation = config.get("isolation_attestation", {})
    required = ("host_only_network", "no_default_gateway", "shared_folders_disabled",
                "clipboard_disabled", "clean_snapshot_created")
    checks = {"vm_hardware": is_vm, "no_default_gateway": not gateways,
              "operator_attestations": all(attestation.get(k) is True for k in required)}
    receipt = {"identity": identity, "gateways": gateways, "checks": checks,
               "attestations": attestation,
               "limits": "VM hardware and route checks do not independently prove all hypervisor settings"}
    if not all(checks.values()):
        raise RuntimeError("VM isolation not ready: " + json.dumps(receipt, ensure_ascii=False))
    return receipt
