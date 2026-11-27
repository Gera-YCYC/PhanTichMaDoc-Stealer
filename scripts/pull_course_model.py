"""User-authorized pull of the course's 7B model into the configured local server store."""
import json
from pathlib import Path
import time
import urllib.request

MODEL = "qwen2.5-coder:7b"
ROOT = Path(__file__).resolve().parents[1]
receipt = ROOT / "evidence/local/model-download-7b.jsonl"
receipt.parent.mkdir(parents=True, exist_ok=True)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(30):
    try:
        with opener.open("http://127.0.0.1:11435/api/version", timeout=2) as response:
            json.load(response)
        break
    except Exception:
        time.sleep(1)
else:
    raise RuntimeError("Project Ollama server is not ready")
request = urllib.request.Request("http://127.0.0.1:11435/api/pull",
    data=json.dumps({"model": MODEL, "stream": True}).encode(), headers={"Content-Type": "application/json"})
last_status, last_pct = "", -1
with opener.open(request, timeout=300) as response, receipt.open("a", encoding="utf-8") as output:
    for line in response:
        row = json.loads(line)
        row["recorded_epoch"] = time.time()
        output.write(json.dumps(row) + "\n")
        output.flush()
        if "error" in row:
            raise RuntimeError(row["error"])
        status = row.get("status", "")
        pct = int(100 * row.get("completed", 0) / row["total"]) if row.get("total") else -1
        if status != last_status or pct >= last_pct + 5:
            print(json.dumps({"status": status, "percent": pct, "total_bytes": row.get("total")}), flush=True)
            last_status, last_pct = status, pct
print("Course model pull completed", flush=True)
