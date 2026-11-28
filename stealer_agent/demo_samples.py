"""Hash-pinned inputs for the live demo, including a signed clean comparator."""
import json
from pathlib import Path

MALWARE = "real-public-malware-local-slm-vm"
CLEAN = "signed-clean-control-local-slm-vm"
CONTROL = "clean_ms_addinprocess.bin"


def registry(root: Path):
    public = json.loads((root / "config/public-samples.json").read_bytes())["samples"]
    manifest = json.loads((root / "eval/corpora/real-yara-development-v3.json").read_bytes())
    row, = (r for r in manifest["source_manifest"]["rows"] if r["sample"] == CONTROL)
    if (row["positive"] is not False or row["signature_status"] != "Valid" or
            "Microsoft Corporation" not in row["publisher"] or not any(
                r["sample"] == CONTROL and r["positive"] is False and r["sha256"] == row["sha256"]
                for r in manifest["corpora"]["holdout"])):
        raise ValueError("Hồ sơ đối chứng khác bộ tệp sạch đã kiểm chữ ký.")
    return {**{name: {**r, "evidence_kind": MALWARE} for name, r in public.items()},
            CONTROL: {"branch": ".NET · đối chứng sạch có chữ ký Microsoft", "sha256": row["sha256"],
                      "size_bytes": row["bytes"], "evidence_kind": CLEAN}}
