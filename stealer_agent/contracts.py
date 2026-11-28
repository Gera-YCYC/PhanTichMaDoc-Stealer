"""Versioned wire contracts shared by host and VM; no execution policy in prompts."""
from __future__ import annotations

from jsonschema import Draft202012Validator

PROTOCOL = "stealer-lab/1"
ANALYSIS_TOOLS = ("identify", "detect_it_easy", "floss", "decompile_dotnet", "strings", "python_ast", "extract_ioc", "unpack_pyinstaller", "decompile_python", "disassemble_python", "decode_python_literals")
TOOLS = (*ANALYSIS_TOOLS, "read_evidence", "search_evidence", "test_yara", "yara_candidates")
ATTACK = {
    "T1555.003": "Credentials from Web Browsers",
    "T1555.004": "Windows Credential Manager",
    "T1539": "Steal Web Session Cookie",
    "T1528": "Steal Application Access Token",
    "T1005": "Data from Local System",
    "T1083": "File and Directory Discovery",
    "T1113": "Screen Capture",
    "T1082": "System Information Discovery",
    "T1560": "Archive Collected Data",
    "T1560.002": "Archive via Library",
    "T1567": "Exfiltration Over Web Service",
    "T1567.004": "Exfiltration Over Webhook",
    "T1041": "Exfiltration Over C2 Channel",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1027": "Obfuscated Files or Information",
    "T1140": "Deobfuscate/Decode Files or Information",
}

EVIDENCE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "evidence_id": {"type": "string", "pattern": "^ev_[a-f0-9]{16}$"},
        "line": {"type": "integer", "minimum": 1},
        "end_line": {"type": "integer", "minimum": 1},
        "quote": {"type": "string", "minLength": 4, "maxLength": 4800},
    }, "required": ["evidence_id", "line", "quote"],
}
CLAIM_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "pattern": "^C[1-9][0-9]{0,2}$"},
        "kind": {"enum": ["observation", "behavior", "ioc", "attack"]},
        "text": {"type": "string", "minLength": 4, "maxLength": 500},
        "value": {"type": "string", "maxLength": 500},
        "technique_id": {"type": "string", "enum": ["", *ATTACK]},
        "evidence": {"type": "array", "items": EVIDENCE_SCHEMA, "minItems": 1, "maxItems": 6},
    }, "required": ["id", "kind", "text", "value", "technique_id", "evidence"],
}
REPORT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "verdict": {"enum": ["inconclusive", "benign", "malicious", "suspicious"]},
        "verdict_claim_ids": {"type": "array", "items": {"type": "string", "pattern":"^C[1-9][0-9]{0,2}$"}, "maxItems": 10},
        "claims": {"type": "array", "items": CLAIM_SCHEMA, "maxItems": 50},
        "limitations": {"type": "array", "items": {"type": "string", "maxLength": 300}, "maxItems": 10},
    }, "required": ["verdict", "verdict_claim_ids", "claims", "limitations"],
}
ACTION_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "action": {"enum": [*TOOLS, "finish"]},
        "reason": {"type": "string", "minLength": 1, "maxLength": 300},
        "arguments": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "sample": {"type": "string", "maxLength": 100},
                "evidence_id": {"type": "string", "pattern": "^ev_[a-f0-9]{16}$"},
                "page": {"type": "integer", "minimum": 0, "maximum": 1000},
                "field_call_line": {"type": "integer", "minimum": 1, "maximum": 16000},
                "type_name": {"type": "string", "maxLength": 150},
                "entry_index": {"type": "integer", "minimum": 0, "maximum": 31},
                "rule": {"type": "string", "minLength": 10, "maxLength": 6000},
                "corpus": {"enum": ["training", "holdout"]},
                "profile": {"enum": ["fixture", "real-v1", "real-v3"]},
                "query": {"type": "string", "minLength": 3, "maxLength": 80},
                "occurrence_order": {"type":"boolean"},
                "verify_staging": {"type":"boolean"},
            },
        },
        "report": {"anyOf": [REPORT_SCHEMA, {"type": "null"}]},
    }, "required": ["action", "reason", "arguments", "report"],
}
# Enforce action/report coupling in the decoding grammar, not only afterwards.
# This materially helps the existing 1.5B model avoid inventing a report on tool calls.
import copy as _copy
_tool_action = _copy.deepcopy(ACTION_SCHEMA)
_tool_action["properties"]["action"] = {"enum": list(TOOLS)}
_tool_action["properties"]["report"] = {"type": "null"}
_finish_action = _copy.deepcopy(ACTION_SCHEMA)
_finish_action["properties"]["action"] = {"const": "finish"}
_finish_action["properties"]["arguments"] = {"type": "object", "additionalProperties": False, "properties": {}}
_finish_action["properties"]["report"] = REPORT_SCHEMA
_finalize_action = _copy.deepcopy(_finish_action)
_finalize_action['properties']['action'] = {'const': 'finalize'}
_finalize_action['properties']['report'] = {'type': 'null'}
ACTION_SCHEMA = {"anyOf": [_tool_action, _finish_action, _finalize_action]}


def validate_action(value: dict) -> dict:
    Draft202012Validator(ACTION_SCHEMA).validate(value)
    action, args = value["action"], value["arguments"]
    allowed = {
        "detect_it_easy": {"sample"}, "floss": {"sample"},
        "identify": {"sample"}, "strings": {"sample"}, "python_ast": {"sample"},
        "decompile_dotnet": {"sample", "type_name"},
        "extract_ioc": {"sample", "evidence_id"},
        "decode_python_literals": {"sample", "evidence_id"},
        "read_evidence": {"sample", "evidence_id", "page", "field_call_line"}, "finish": set(), "finalize": set(),
        "unpack_pyinstaller": {"sample"}, "decompile_python": {"sample", "entry_index"},
        "disassemble_python": {"sample", "entry_index"},
        "test_yara": {"sample", "rule", "corpus", "profile"},
        "yara_candidates": {"sample"},
        "search_evidence": {"sample", "evidence_id", "query", "occurrence_order", "verify_staging"},
    }[action]
    required = {"sample"} if action not in {"finish", "finalize"} else set()
    if action in {"extract_ioc", "read_evidence", "search_evidence", "decode_python_literals"}:
        required.add("evidence_id")
    if action == "search_evidence":
        required.add("query")
    if action == "read_evidence" and "field_call_line" in args and "page" in args:
        raise ValueError("Choose one evidence row or one page")
    if action in {"decompile_python", "disassemble_python"}:
        required.add("entry_index")
    if action == "test_yara":
        required.update({"rule", "corpus"})
    if not required <= args.keys() or not args.keys() <= allowed:
        raise ValueError(f"Invalid arguments for {action}; required={sorted(required)} allowed={sorted(allowed)}")
    if action == "finish" and value["report"] is None:
        raise ValueError("finish requires report")
    if action != "finish" and value["report"] is not None:
        raise ValueError("Tool actions require report=null")
    return value


def decision_schema(sample: str, allowed: list[str], evidence_ids: list[str], can_finish: bool,
                    unread_pages: dict | None = None, ioc_sources: list[str] | None = None,
                    python_entries: list[int] | None = None, citation_options: list[dict] | None = None,
                    search_options: dict | None = None, card_report: bool = False) -> dict:
    """Constrain decoding to executable actions while the model chooses their order."""
    branches = []
    for name in allowed:
        if name == 'search_evidence':
            for eid, queries in (search_options or {}).items():
                if not queries:
                    continue
                branch = _copy.deepcopy(_tool_action)
                branch['properties']['action'] = {'const': name}
                branch['properties']['arguments'] = {'type': 'object', 'additionalProperties': False,
                    'properties': {'sample': {'const': sample}, 'evidence_id': {'const': eid}, 'query': {'enum': queries}},
                    'required': ['sample', 'evidence_id', 'query']}
                branches.append(branch)
            continue
        if name == "read_evidence":
            for eid, pages in (unread_pages or {}).items():
                if not pages:
                    continue
                branch = _copy.deepcopy(_tool_action)
                branch["properties"]["action"] = {"const": name}
                branch["properties"]["arguments"] = {"type": "object", "additionalProperties": False,
                    "properties": {"sample": {"const": sample}, "evidence_id": {"const": eid}, "page": {"enum": pages}},
                    "required": ["sample", "evidence_id", "page"]}
                branches.append(branch)
            continue
        if name == "extract_ioc":
            evidence_ids_for_tool = ioc_sources if ioc_sources is not None else evidence_ids
            if not evidence_ids_for_tool:
                continue
        else:
            evidence_ids_for_tool = evidence_ids
        if name in {"extract_ioc", "read_evidence", "search_evidence", "decode_python_literals"} and not evidence_ids:
            continue
        properties = {"sample": {"const": sample}}
        required = ["sample"]
        if name in {"decompile_python", "disassemble_python"}:
            if not python_entries:
                continue
            properties["entry_index"] = {"enum": python_entries}
            required.append("entry_index")
        if name in {"extract_ioc", "read_evidence", "search_evidence", "decode_python_literals"}:
            properties["evidence_id"] = {"enum": evidence_ids_for_tool}
            required.append("evidence_id")
        if name == "search_evidence":
            properties["query"] = {"type": "string", "minLength": 3, "maxLength": 80}
            required.append("query")
        if name == "read_evidence":
            properties["page"] = {"type": "integer", "minimum": 0, "maximum": 1000}
            required.append("page")
        # Whole-assembly decompilation is the initial operation; a type name must
        # not be invented before a type inventory exists.
        branch = _copy.deepcopy(_tool_action)
        branch["properties"]["action"] = {"const": name}
        branch["properties"]["arguments"] = {"type": "object", "additionalProperties": False,
                                               "properties": properties, "required": required}
        branches.append(branch)
    if can_finish:
        if card_report:
            branches.append(_copy.deepcopy(_finalize_action))
            return {"anyOf": branches}
        finish = _copy.deepcopy(_finish_action)
        finish["properties"]["report"] = _copy.deepcopy(REPORT_SCHEMA)
        finish["properties"]["report"]["properties"]["claims"]["minItems"] = 1
        finish["properties"]["report"]["properties"]["claims"]["maxItems"] = 8
        typed_claims=[]
        for kind in ('observation','behavior','ioc','attack'):
            branch = _copy.deepcopy(CLAIM_SCHEMA)
            branch['properties']['kind']={'const':kind}
            if kind!='ioc':
                branch['properties']['value']={'const':''}
            if kind!='attack':
                branch['properties']['technique_id']={'const':''}
            else:
                branch['properties']['technique_id']={'enum':list(ATTACK)}
            if citation_options:
                branch['properties']['evidence']['items']={'enum':[
                    ref.get('citation_id',ref['evidence_id']+':'+str(ref['line'])) for ref in citation_options]}
            typed_claims.append(branch)
        finish['properties']['report']['properties']['claims']['items']={'anyOf':typed_claims}
        branches.append(finish)
    if not branches:
        raise ValueError("No valid next action is available")
    return {"anyOf": branches}


TOOL_DESCRIPTIONS = {
    "decode_python_literals": "Decode embedded Python candidates from prior Python evidence with bounded literal-only base64/Fernet/zlib transforms; never executes code. Args: sample,evidence_id (Python evidence only).",
    "detect_it_easy": "Detect It Easy CLI: signature-based format/compiler/packer hints. Fixed local database, no updates or sample execution. Args: sample.",
    "floss": "FLOSS strings with category/address evidence. For managed .NET only static strings; native PE can use stack/tight/decoded emulation. Not executed behavior. Args: sample.",
    "disassemble_python": "pycdas fallback after pycdc failure: inspect opcodes/constants of entry_index. NOT complete decompilation; state the limitation.",
    "search_evidence": "Search literal text in a whole evidence record, e.g. Upload, WebClient, cookie, webhook; returns original cited lines. Not a distinct analysis tool.",
    "unpack_pyinstaller": "pyinstxtractor: list and extract entry scripts without executing; returns entry_index values.",
    "decompile_python": "pycdc: decompile one previously extracted entry_index. Unsupported opcodes fail explicitly.",
    "identify": "pefile: identify PE/CLR, SHA256, size; .py source recognised. Args: sample.",
    "decompile_dotnet": "ILSpy: decompile .NET without executing it. Args: sample, optional type_name.",
    "strings": "Extract UTF-8 (including Vietnamese), ASCII and ASCII-range UTF16LE strings with byte offsets. Not a decoder. Args: sample.",
    "python_ast": "Python ast.parse: static source features, never execution. Args: sample (.py).",
    "extract_ioc": "Extract IOC candidates from an existing evidence record. Args: sample,evidence_id.",
    "read_evidence": "Read another page; does not count as a distinct analysis tool. Args: sample,evidence_id,page.",
}
