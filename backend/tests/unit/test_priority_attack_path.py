from app.modules.risk_engine.priority import priority_score
from app.modules.risk_engine.attack_path import shortest_paths_to_critical

def test_priority_score_is_bounded_and_kev_raises_priority():
    base = priority_score(risk_score=70, epss=.5)
    kev = priority_score(risk_score=70, epss=.5, in_kev=True, direct_exposure=True, asset_value=1)
    assert 0 <= base <= 100
    assert kev > base

def test_shortest_safe_path_to_critical_asset():
    nodes = [{"id":"internet","exposed":True},{"id":"app"},{"id":"db","critical":True}]
    edges = [{"source":"internet","target":"app"},{"source":"app","target":"db"}]
    assert shortest_paths_to_critical(nodes, edges)[0]["path"] == ["internet","app","db"]
