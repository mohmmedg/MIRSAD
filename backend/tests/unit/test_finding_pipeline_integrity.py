from app.core.finding_pipeline import _verification_record


def test_unverified_scanner_observation_does_not_claim_live_verification():
    record = _verification_record({
        "finding_id": "fnd-example",
        "rule_id": "NUCLEI-EXAMPLE",
        "verification_status": "DETECTED",
    })
    assert record["result"] == "DETECTED"
    assert record["method"] is None
    assert record["timestamp"] is None


def test_live_verification_metadata_is_preserved_without_rewriting():
    record = _verification_record({
        "finding_id": "fnd-example",
        "rule_id": "WEB-CORS-CONFIG",
        "verification_status": "VERIFIED",
        "verification_method": "GET-REPLAY-READONLY",
        "verification_timestamp": "2026-10-30T04:00:00+00:00",
    })
    assert record["result"] == "VERIFIED"
    assert record["method"] == "GET-REPLAY-READONLY"
    assert record["timestamp"] == "2026-10-30T04:00:00+00:00"
