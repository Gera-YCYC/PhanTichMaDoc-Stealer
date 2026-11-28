"""Flag a bounded Python slice that contradicts an explicit leading-byte claim."""

import ast
import re


def slice_discrepancy(claim, tool):
    if tool not in {"python_ast", "decode_python_literals", "decompile_python"}:
        return None
    text = claim["text"].casefold()
    first = re.search(r"\bfrom the first ([1-9]\d{0,5}) bytes of\b", text)
    if not first or re.search(r"\b(?:not|never|excluding|except)\b", text):
        return None
    refs = claim["evidence"]
    if len(refs) != 1 or refs[0]["line"] != refs[0]["end_line"]:
        return None
    try:
        statements = ast.parse(refs[0]["quote"].strip()).body
    except (SyntaxError, ValueError, RecursionError):
        return None
    if len(statements) != 1 or not isinstance(statements[0], ast.Assign):
        return None
    assignment = statements[0]
    if len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
        return None
    name = assignment.targets[0].id.casefold()
    if not re.search(r"\b" + re.escape(name) + r"\b", text[:first.start()]):
        return None
    value = assignment.value
    if not isinstance(value, ast.Subscript) or not isinstance(value.value, ast.Name):
        return None
    sl = value.slice
    if not isinstance(sl, ast.Slice) or sl.step is not None:
        return None
    if not all(isinstance(n, ast.Constant) and type(n.value) is int for n in (sl.lower, sl.upper)):
        return None
    start, stop, count = sl.lower.value, sl.upper.value, int(first[1])
    if 0 <= start < stop and stop > count:
        return {"line": refs[0]["line"], "start": start, "stop": stop, "claimed_prefix": count}
    return None
