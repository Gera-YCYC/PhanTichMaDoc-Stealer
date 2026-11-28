"""Screen interpretations of a positional read in a guarded .NET excerpt."""

import re

from jsonschema import Draft202012Validator

VERSION = "ordinal-review/1"
GUIDANCE = """
The local reader uses integer column positions. A table name and a position alone do
not identify a SQL column or its real-world meaning. Describe the selected table,
numeric reads or other independently visible operations. A string variable type is
not a semantic column name. An observed later use may be described as a use."""
REVIEW = """
Classify the actual claim before deciding support. independent_operation means the
statement stands without naming the value read by position (e.g. a file copy).
position_only describes the table, index, assignment or visible use without naming
what the column represents. assigns_identity says what an indexed value means, even
implicitly (e.g. 'reads the product price' when the only access is by integer).
Use unresolved if you cannot distinguish these. Do not infer the schema of a
custom reader from surrounding strings, variable names or known software layouts."""

KINDS = ["independent_operation", "position_only", "assigns_identity", "unresolved"]
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "column_basis": {"enum": KINDS},
        "reason": {"type": "string", "minLength": 1, "maxLength": 400},
        "supported": {"type": "boolean"},
    },
    "required": ["column_basis", "reason", "supported"],
}

# Catch an explicit linguistic mapping even if the same-model reviewer overlooks
# it. A numeric read and a later use, or the type of a variable, is not a mapping.
POSITION = re.compile(r"\b(?:ordinals?|index(?:es)?|indices|positions?|\d+(?:st|nd|rd|th))\b", re.I)
MAPPING = re.compile(r"\b(?:correspond(?:s|ing)? to|represent(?:s|ing)?|stand(?:s)? for|maps? to)\b", re.I)


def decision(text, assessment):
    if not Draft202012Validator(SCHEMA).is_valid(assessment):
        return "invalid_review"
    if assessment["column_basis"] in {"assigns_identity", "unresolved"}:
        return "unverified_column_identity"
    if POSITION.search(text) and MAPPING.search(text) and not re.search(
        r"\b(?:do(?:es)? not|cannot|unknown|unresolved|not known)\b", text, re.I
    ):
        return "explicit_ordinal_mapping"
    return "ordinary_review"
