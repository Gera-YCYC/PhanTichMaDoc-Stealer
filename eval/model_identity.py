"""Audit the model/VM identity boundary of a finished, registered web analysis."""
import argparse
from collections import Counter
from hashlib import sha256
import json

from lab_web.cases import ROOT, directory
from stealer_agent.demo_samples import CLEAN, registry
from stealer_agent.journal import canonical
from stealer_agent.sample_binding import SampleBinding


def audit(run):
    path = directory(run) / "events.jsonl"
    previous = "0" * 64
    journal_hash = sha256()
    requests, responses, dispatches, observations = {}, set(), {}, set()
    phases = Counter()
    fields = ("messages", "schema", "evidence")
    exposure = dict.fromkeys(fields, 0)
    receipt = None
    started = final = source_digest = None
    with path.open("rb") as stream:
        for index, line in enumerate(stream, 1):
            journal_hash.update(line)
            event = json.loads(line)
            digest = event.pop("sha256")
            if (event["sequence"] != index or event["previous_sha256"] != previous
                    or sha256(canonical(event)).hexdigest() != digest):
                raise ValueError("Chuỗi băm nhật ký không khớp.")
            previous = digest
            kind = event["event"]
            if index == 1:
                if kind != "run_started":
                    raise ValueError("Thiếu thông tin đầu lượt.")
                started = event
                sample = event["sample"]
                registered = registry(ROOT)[sample]["sha256"]
                if event["config"].get("expected_sample_sha256") != registered:
                    raise ValueError("Lượt chưa ghim SHA-256 theo danh mục.")
                binding = SampleBinding(sample)
                neutral = event["config"].get("neutral_sample_id") is True
                model_id = binding.alias if neutral else sample
            if final is not None:
                raise ValueError("Nhật ký có dữ liệu sau bước kết thúc.")
            step = event.get("step")
            if kind == "sample_binding":
                if receipt or requests or not neutral or (
                    event["run"], event["sample"], event["alias"], event["expected_sha256"]
                ) != (run, sample, model_id, registered):
                    raise ValueError("Bản ghi ánh xạ mẫu không khớp.")
                receipt = event
            elif kind == "source_version":
                source_digest = sha256(canonical(event["files"])).hexdigest()
                if source_digest != event["manifest_sha256"]:
                    raise ValueError("Mã băm phiên bản nguồn không khớp.")
            elif kind == "model_request":
                key = (event["phase"], step)
                if key in requests or (neutral and not receipt):
                    raise ValueError("Thứ tự yêu cầu model không hợp lệ.")
                for field in fields:
                    exposure[field] += int(binding.contains_registry_data(event[field]))
                for field in ("messages", "schema"):
                    if sha256(canonical(event[field])).hexdigest() != event[field + "_sha256"]:
                        raise ValueError("Nội dung gửi model khác mã băm đã lưu.")
                if event["phase"] == "react":
                    states = [json.loads(msg["content"].removeprefix("CONTROLLER_STATE "))
                              for msg in event["messages"] if msg["content"].startswith("CONTROLLER_STATE ")]
                    if states and (len(states) != 1 or states[0].get("authorized_sample") != model_id):
                        raise ValueError("Mã mẫu trong trạng thái ReAct khác mã đã cấp.")
                    for branch in event["schema"].get("anyOf", []):
                        args = branch["properties"]["arguments"]
                        rule = args.get("properties", {}).get("sample")
                        if rule is not None and rule not in ({"const":model_id}, {"enum":[model_id]}):
                            raise ValueError("Schema cho phép chọn mã mẫu ngoài lượt.")
                phases[event["phase"]] += 1
                requests[key] = None
            elif kind == "model_response":
                key = (event["phase"], step)
                if key not in requests or key in responses:
                    raise ValueError("Phản hồi model thiếu yêu cầu tương ứng.")
                responses.add(key)
                if key[0] == "react":
                    action = event["action"]
                    requests[key] = (action["action"], (action.get("arguments") or {}).get("sample"))
            elif kind == "action_dispatched":
                if (step in dispatches or requests.get(("react", step)) != (event["action"], model_id)
                        or event["arguments"].get("sample") != sample):
                    raise ValueError("Lệnh tới VM khác lựa chọn của model hoặc sai mẫu.")
                dispatches[step] = event["action"]
            elif kind == "observation":
                if step not in dispatches or step in observations:
                    raise ValueError("Quan sát VM thiếu lệnh tương ứng.")
                for response in (event["raw"], event["model_visible"]):
                    if (response["sample"], response["sample_sha256"]) != (sample, registered):
                        raise ValueError("Mẫu trong kết quả VM khác danh mục.")
                observations.add(step)
            elif kind == "run_finished":
                final = event["result"]
    if (not started or not final or not source_digest
            or (final["run_id"], final["sample"], final["sample_sha256"]) != (run, sample, registered)):
        raise ValueError("Thiếu kết quả có mã lượt và SHA-256 mẫu khớp.")
    if (len(responses) != final["metrics"]["model_calls"] or len(dispatches) != final["metrics"]["tool_calls"]
            or (neutral and (not receipt or any(exposure.values())))):
        raise ValueError("Số lượt gọi hoặc thông tin giấu tên khác nhật ký.")
    config = {k:v for k,v in started["config"].items() if k != "neutral_sample_id"}
    return {"run":run, "sample":sample, "sample_sha256":registered, "model_digest":final["model"]["digest"],
            "other_config_sha256":sha256(canonical(config)).hexdigest(), "source_sha256":source_digest,
            "report_method":final["analysis"].get("report_method"),
            "neutral_id":neutral, "model_id":model_id, "requests":len(requests), "responses":len(responses),
            "phases":dict(phases), "exposure":exposure, "dispatches":len(dispatches),
            "observations":len(observations), "status":final["status"], "verdict":final["analysis"]["verdict"],
            "seconds":final["metrics"]["elapsed_s"], "tool_errors":final["metrics"]["tool_errors"],
            "journal_sha256":journal_hash.hexdigest()}


def compare(before, after):
    if (before["neutral_id"] or not after["neutral_id"] or before["run"] == after["run"]
            or any(before[k] != after[k] for k in ("sample", "sample_sha256", "model_digest", "other_config_sha256"))):
        raise ValueError("Hai lượt cần cùng mẫu, model và cấu hình phân tích ngoài cách đặt tên.")
    entry = registry(ROOT)[after["sample"]]
    label = "benign" if entry["evidence_kind"] == CLEAN else "malicious"
    return {"expected":label, "before":before, "after":after,
            "strict_correct":[row["status"].startswith("completed_") and row["verdict"] == label
                              for row in (before, after)],
            "method_changed":before["report_method"] != after["report_method"]}


def published():
    """Verify public counts against exported reports; the raw audit needs private journals."""
    folder = ROOT / "deliverables/real-demo-evidence"
    pairs = json.loads((folder / "model-identity-comparison.json").read_bytes())["pairs"]
    for pair in pairs:
        if compare(pair["before"], pair["after"]) != pair:
            raise ValueError("Bảng chấm verdict khác quy tắc đối chiếu.")
        for row in (pair["before"], pair["after"]):
            report = json.loads((folder / f"web-{row['run']}.json").read_bytes())
            expected = (report["journal_sha256"], report["sha256"], report["model_digest"], report["verdict"],
                        report["metrics"]["model_calls"], report["metrics"]["tool_calls"], report["status"])
            if expected != tuple(row[k] for k in ("journal_sha256", "sample_sha256", "model_digest", "verdict",
                                                  "responses", "dispatches", "status")):
                raise ValueError("Kết quả so sánh khác hồ sơ đã xuất.")
            if (sum(row["phases"].values()) != row["requests"] or row["responses"] > row["requests"]
                    or row["observations"] > row["dispatches"]
                    or any(not 0 <= n <= row["requests"] for n in row["exposure"].values())
                    or row["neutral_id"] and any(row["exposure"].values())):
                raise ValueError("Số đếm đầu vào model hoặc quan sát VM không nhất quán.")
    return pairs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", nargs="*")
    parser.add_argument("--pair", action="store_true", help="Compare a named run with a subsequent neutral run")
    args = parser.parse_args()
    rows = [audit(run) for run in args.run]
    if args.pair and len(rows) != 2:
        parser.error("--pair accepts two run IDs")
    print(json.dumps(compare(*rows) if args.pair else rows or published(), indent=2))
