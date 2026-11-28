from stealer_agent.column_review import decision


def assess(basis="position_only", supported=True):
    return {"column_basis": basis, "reason": "Checked the cited lines.", "supported": supported}


def test_explicit_mapping_requires_independent_schema_even_if_reviewer_agrees():
    assert decision("Ordinals 0 and 4 correspond to a product and its price.", assess()) == "explicit_ordinal_mapping"
    assert decision("Reads the sales price.", assess("assigns_identity")) == "unverified_column_identity"


def test_positions_ordinary_operations_and_explicit_uncertainty_remain_reviewable():
    for text in ["The code reads column index 4 into a string.", "The table is copied to a temporary file.",
                 "It is unknown what the indices represent."]:
        assert decision(text, assess()) == "ordinary_review"


def test_missing_classification_cannot_support_a_claim():
    assert decision("Reads a field.", {"supported": True, "reason": "OK"}) == "invalid_review"
