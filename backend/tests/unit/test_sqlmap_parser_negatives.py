from app.modules.external_scanners.engines import parse_sqlmap_output

T = "http://127.0.0.1:3000/rest/products/search?q=1"


def test_negative_verdicts_and_banner_are_not_findings():
    out = """
        ___
       __H__
 [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal
[INFO] GET parameter 'q' does not seem to be injectable
[WARNING] heuristic (basic) test shows that GET parameter 'q' might not be injectable
[CRITICAL] all tested parameters do not appear to be injectable
"""
    assert parse_sqlmap_output(out, T) == []


def test_positive_fallback_names_parameter_and_keeps_only_evidence_line():
    out = "banner text\n[INFO] GET parameter 'q' appears to be 'AND boolean-based blind' injectable\nlegal disclaimer\n"
    f = parse_sqlmap_output(out, T)
    assert len(f) == 1
    assert f[0]["parameter"] == "q" and f[0]["endpoint"] == T
    assert "banner" not in f[0]["description"] and "legal" not in f[0]["description"]
    assert "'q'" in f[0]["name"]


def test_structured_block_still_parsed():
    out = "Parameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n    Payload: id=1 AND 1=1\n"
    f = parse_sqlmap_output(out, T)
    assert f[0]["parameter"] == "id" and f[0]["type"] == "boolean-based blind"
