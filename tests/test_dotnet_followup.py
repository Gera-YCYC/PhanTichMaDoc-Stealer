from eval.dotnet_followup import intervals, menu, score


def test_followup_uses_observed_calls_and_skips_strings_comments_and_prior_queries():
    record = {
        "line_map": {
            1: 'var hint = "FromTextOnly()";',
            2: "// ForCommentOnly()",
            3: "var first = ReadIndex();",
            4: "InspectEntry(first);",
        },
    }
    assert menu({"e": record}, {"readindex"}) == {
        "InspectEntry": {"role": "observed_call"}
    }


def test_retrieval_counts_each_line_once_and_requires_every_missing_coordinate():
    calls = [
        {"added": intervals([50, 52, 51, 51]), "model_usage": None},
        {"added": intervals([52, 57]), "model_usage": None},
    ]
    result = score({"a": [50, 57], "b": [51, 53]}, calls)
    assert result == {
        "covered": ["a"],
        "eligible": 2,
        "new_source_rows": 4,
        "vm_calls": 2,
        "model_calls": 0,
    }
