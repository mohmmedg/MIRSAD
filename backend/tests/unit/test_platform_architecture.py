from app.modules.normalizer.normalizer import make_id
from app.modules.risk_engine.engine import assess
from app.modules.correlator.correlator import correlate
from app.schemas.platform import NormalizedFinding, FindingEvidence
from app.modules.auth_session.session import analyze_jwt

def test_risk_and_correlation():
    f=NormalizedFinding(finding_id=make_id("web","Missing CSP","https://example.test"),source_module="web",title="Missing CSP",severity="Medium",confidence=.9,evidence=[FindingEvidence(source="test",asset="https://example.test",evidence="missing")],affected_asset="https://example.test")
    # Trust contract: an unconfirmed candidate never contributes confirmed risk.
    assert assess(f).score==0
    assert assess(f.model_copy(update={"confirmation_state":"CONFIRMED"})).score>0
    out=correlate([f,f])
    assert len(out)==1 and out[0].duplicate_count==2

def test_jwt_analysis():
    token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMiLCJleHAiOjIwMDAwMDAwMDB9.signature"
    r=analyze_jwt("Bearer "+token)
    assert r["present"] is True
    assert r["expiry_present"] is True
