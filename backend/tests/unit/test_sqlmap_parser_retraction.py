"""sqlmap may retract an early "injectable" verdict; the report must follow the final verdict (2026-11-01)."""
from app.modules.external_scanners.engines import parse_sqlmap_output

T = "http://target.test/search?q=1"

RETRACTED = """
[18:10:12] [WARNING] heuristic (basic) test shows that GET parameter 'q' might not be injectable
[18:11:14] [INFO] GET parameter 'q' appears to be 'IBM DB2 stacked queries (heavy query - comment)' injectable
[18:11:36] [WARNING] GET parameter 'q' does not seem to be injectable
[18:11:43] [ERROR] all tested parameters do not appear to be injectable.
"""


def test_early_positive_cancelled_by_later_negative():
    assert parse_sqlmap_output(RETRACTED, T) == []


def test_positive_without_retraction_is_kept():
    out = "[INFO] GET parameter 'q' appears to be 'AND boolean-based blind' injectable\n"
    assert [f["parameter"] for f in parse_sqlmap_output(out, T)] == ["q"]


def test_negative_before_positive_does_not_cancel():
    out = ("[WARNING] GET parameter 'q' does not seem to be injectable\n"
           "[INFO] GET parameter 'q' appears to be 'AND boolean-based blind' injectable\n")
    assert len(parse_sqlmap_output(out, T)) == 1


def test_other_parameter_unaffected():
    out = ("[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable\n"
           "[WARNING] GET parameter 'q' does not seem to be injectable\n")
    assert [f["parameter"] for f in parse_sqlmap_output(out, T)] == ["id"]
