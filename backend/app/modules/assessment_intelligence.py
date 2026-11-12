"""MIRSAD assessment intelligence layer.

Coordinates endpoint inventory, parameter classification, technology-aware test
selection, evidence quality, finding correlation context and attack-chain hints.
All checks are bounded and non-destructive; it does not execute arbitrary commands.
"""
from __future__ import annotations
import re
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlparse

PARAM_HINTS = {
    "ssrf": {"url","uri","webhook","callback","dest","destination","target","src","source","feed","link","fetch","proxy","endpoint","host","site"},
    "redirect": {"redirect","return","returnurl","return_to","next","continue","callback","dest","destination","target","redirect_uri","redirect_url","out","forward"},
    "file": {"file","path","include","template","page","view","load","doc","document","filename"},
    "identifier": {"id","uid","user","userid","account","accountid","order","orderid","customer","customerid"},
    "query": {"q","query","search","keyword","term","name","filter","sort"},
}
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*[\"'][^\"']{12,}[\"']")),
]


def classify_parameter(name: str) -> list[str]:
    low = name.strip().lower()
    return [kind for kind, names in PARAM_HINTS.items() if low in names or any(low.endswith("_"+x) or low.startswith(x+"_") for x in names)]


def build_endpoint_inventory(web=None, api=None):
    rows=[]; seen=set()
    for e in getattr(web, "endpoints", []) or []:
        key=(str(e.method).upper(), e.url)
        if key in seen: continue
        seen.add(key)
        params=list(e.parameters or [])
        if not params:
            params=[k for k,_ in parse_qsl(urlparse(e.url).query, keep_blank_values=True)]
        rows.append({"url":e.url,"method":str(e.method).upper(),"source":e.source,"status_code":e.status_code,"content_type":e.content_type,"parameters":[{"name":p,"classes":classify_parameter(p)} for p in params],"test_plan":sorted(set(c for p in params for c in classify_parameter(p)))})
    for e in getattr(api, "endpoints", []) or []:
        # NOTE: APIEndpoint carries a *list* of HTTP methods (`methods`), unlike the
        # web-crawler's endpoint objects which carry a single `.method`. Accessing
        # `.method` here used to raise AttributeError and crash the worker mid-scan.
        methods = list(getattr(e, "methods", None) or ["GET"])
        observations = getattr(e, "observations", None) or []
        params=[]
        for p in getattr(e, "parameters", []) or []:
            name=getattr(p,"name",None) or (p if isinstance(p,str) else None)
            if name: params.append(str(name))
        param_rows=[{"name":p,"classes":classify_parameter(p)} for p in params]
        test_plan=sorted(set(c for p in params for c in classify_parameter(p)))
        for m in methods:
            key=(str(m).upper(), e.url)
            if key in seen: continue
            seen.add(key)
            obs = next((o for o in observations if str(getattr(o,"method","")).upper()==str(m).upper()), None)
            rows.append({"url":e.url,"method":str(m).upper(),"source":"api-discovery","status_code":getattr(obs,"status_code",None),"content_type":getattr(obs,"content_type",None),"parameters":param_rows,"test_plan":test_plan})
    return rows[:2000]


def scan_js_secrets(bodies: list[str]) -> list[dict]:
    out=[]
    for idx, body in enumerate(bodies):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(body):
                out.append({"type":label,"source_index":idx,"value":"<redacted>","confidence":0.72 if label=="Generic secret assignment" else 0.9})
    # preserve distinct signal types while retaining count
    return out[:100]


def evidence_quality(evidence: list, verified: bool | None = None) -> dict:
    texts=[str(getattr(e,"evidence","") or "") for e in evidence]
    chars=sum(len(x) for x in texts)
    sources=len({str(getattr(e,"source","") or "") for e in evidence})
    if sources >= 2 or chars >= 500: level="HIGH"
    elif chars >= 120: level="MEDIUM"
    else: level="LOW"
    # 2.2: an independently-reproduced match (see
    # web_scan/scanner.py::_verify_template_match) is stronger evidence than
    # volume/source-count alone, so it can raise a volume-based MEDIUM/LOW to
    # HIGH. A repeat request that failed to reproduce the match (verified is
    # explicitly False, not just absent) caps confidence at MEDIUM even if
    # the raw evidence volume would otherwise read as HIGH - contradicting
    # evidence should never be silently outweighed by more text.
    if verified is True:
        level = "HIGH"
    elif verified is False and level == "HIGH":
        level = "MEDIUM"
    return {"level":level,"sources":sources,"characters":chars,"reproducibility":round(min(1.0, 0.35+0.2*sources+min(chars,1000)/2500),2),"verified":verified}


def _finding_signals(f) -> list[str]:
    tags={t.lower() for t in (getattr(f,"tags",[]) or [])}
    title=str(getattr(f,"title","")).lower()
    haystack=tags | {title}
    signals=[]
    if any("auth" in t or "idor" in t or "bola" in t for t in haystack): signals.append("authorization/authentication")
    if any("sqli" in t or "injection" in t for t in haystack): signals.append("injection")
    if any("admin" in t or "exposed" in t for t in haystack): signals.append("exposure")
    if any("ssrf" in t for t in haystack): signals.append("server-side request")
    return signals


def _single_host_chains(findings, asset_links: dict[str, set[str]] | None = None) -> list[dict]:
    """Original single-host grouping: every finding is attributed to the
    hostname parsed out of its own affected_asset. Kept as the fallback when
    no graph/asset_links is supplied, and as the building block
    _graph_chains() extends.

    When `asset_links` (a cheap host->host adjacency built from shared
    IPs, see build_asset_links below) is given, hosts connected through it
    are merged into one component via bounded-depth BFS before signals are
    collected - so this now finds cross-host chains WITHOUT needing the
    full attack-surface graph, which matters because build_attack_surface_graph()
    is only ever built on-demand by the /assessment routes, not during the
    scan pipeline itself (manager.py has no graph to pass at scan time, but
    it does already have DNS-resolved IPs it can turn into asset_links).
    """
    groups=defaultdict(list)
    for f in findings:
        asset=str(getattr(f,"affected_asset","") or "")
        host=urlparse(asset).hostname or asset.split(":")[0]
        groups[host].append(f)

    MAX_ASSET_LINK_DEPTH = 3
    components: list[set[str]] = []
    visited: set[str] = set()
    for host in groups:
        if host in visited:
            continue
        component = {host}
        visited.add(host)
        frontier = [(host, 0)]
        while frontier:
            current, depth = frontier.pop()
            if depth >= MAX_ASSET_LINK_DEPTH:
                continue
            for neighbor in (asset_links or {}).get(current, ()):
                if neighbor in groups and neighbor not in visited:
                    visited.add(neighbor)
                    component.add(neighbor)
                    frontier.append((neighbor, depth + 1))
        components.append(component)

    chains=[]
    for component in components:
        fs=[f for host in component for f in groups[host]]
        signals=sorted({s for f in fs for s in _finding_signals(f)})
        if len(signals)>=2:
            assets_sorted = sorted(component)
            chains.append({"assets":assets_sorted,"signals":signals,"finding_ids":[f.finding_id for f in fs],
                           "priority":"HIGH" if len(signals)>=3 else "MEDIUM","path":assets_sorted,
                           "cross_host": len(component) > 1})
    return chains


def build_asset_links(assets: list[dict]) -> dict[str, set[str]]:
    """Undirected host adjacency derived from shared infrastructure, cheap
    enough to build directly inside manager.py at scan time from data it
    already has (DNS-resolved IPs for the root target + subdomains) -
    unlike the full attack-surface graph, which is only built on-demand by
    the /assessment routes.

    `assets` is a list of {"host": str, "ips": list[str]}. Two hosts that
    resolve to at least one common IP are linked - the same
    shared-infrastructure signal build_attack_surface_graph() encodes as
    host -> ip -> host edges. This is what lets _single_host_chains() above
    traverse across hosts instead of only within a single one.
    """
    ip_to_hosts: dict[str, set[str]] = defaultdict(set)
    for a in assets:
        host = str(a.get("host") or "").strip().lower().rstrip(".")
        if not host:
            continue
        for ip in a.get("ips") or []:
            ip_to_hosts[str(ip)].add(host)
    links: dict[str, set[str]] = defaultdict(set)
    for hosts in ip_to_hosts.values():
        for h in hosts:
            links[h].update(hosts - {h})
    return dict(links)


def _graph_chains(findings, graph: dict) -> list[dict]:
    """Bounded BFS across the attack-surface graph (see
    app/api/routes/assessment.py::build_attack_surface_graph) to find attack
    chains that span *multiple* hosts/assets connected through shared
    infrastructure (same IP, port, service, or subdomain relationship) - not
    just findings that happen to share one affected_asset string.

    `graph` is the {"nodes": [...], "edges": [...]} dict that already feeds
    AttackSurfaceIntelligenceGraphPage.tsx; this function does not build its
    own graph representation, it traverses the existing one.
    """
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    adjacency: dict[str, set[str]] = defaultdict(set)
    for e in graph.get("edges", []):
        s, t = e.get("source"), e.get("target")
        if s in nodes and t in nodes:
            adjacency[s].add(t)
            adjacency[t].add(s)

    finding_by_id = {str(getattr(f, "finding_id", "")): f for f in findings if getattr(f, "finding_id", None)}
    finding_node_ids = {
        nid: n["details"].get("finding_id")
        for nid, n in nodes.items()
        if n.get("type") == "finding" and n.get("details", {}).get("finding_id") in finding_by_id
    }

    MAX_DEPTH = 4  # finding -> asset -> shared-infra-node -> asset -> finding
    chains: list[dict] = []
    seen_pairs: set[frozenset] = set()
    for start_nid, start_fid in finding_node_ids.items():
        # Bounded BFS from this finding's node, stopping at other finding nodes.
        visited = {start_nid}
        frontier = [(start_nid, [start_nid])]
        for _ in range(MAX_DEPTH):
            next_frontier = []
            for nid, path in frontier:
                for neighbor in adjacency.get(nid, ()):
                    if neighbor in visited:
                        continue
                    visited.add(neighbor)
                    new_path = path + [neighbor]
                    if neighbor in finding_node_ids and neighbor != start_nid:
                        end_fid = finding_node_ids[neighbor]
                        pair = frozenset({start_fid, end_fid})
                        if pair in seen_pairs:
                            continue
                        f1, f2 = finding_by_id[start_fid], finding_by_id[end_fid]
                        signals = sorted(set(_finding_signals(f1)) | set(_finding_signals(f2)))
                        if len(signals) < 2:
                            continue
                        seen_pairs.add(pair)
                        asset_path = [nodes[p]["label"] for p in new_path if nodes[p]["type"] in
                                      {"asset", "ip", "port", "service", "subdomain", "domain"}]
                        chains.append({
                            "assets": sorted(set(asset_path)) or ["unknown"],
                            "signals": signals,
                            "finding_ids": [start_fid, end_fid],
                            "priority": "HIGH" if len(signals) >= 3 else "MEDIUM",
                            "path": [nodes[p]["label"] for p in new_path],
                            "hops": len(new_path) - 1,
                            "cross_host": len(set(asset_path)) > 1,
                        })
                    else:
                        next_frontier.append((neighbor, new_path))
            frontier = next_frontier
            if not frontier:
                break
    return chains


def attack_chain_hints(findings, graph: dict | None = None, asset_links: dict[str, set[str]] | None = None) -> list[dict]:
    """Attack-chain detection. `asset_links` (cheap, from build_asset_links -
    available at scan time in manager.py) merges same-infrastructure hosts
    into one component for the base grouping. `graph` (from
    build_attack_surface_graph, only available on-demand from the
    /assessment routes) additionally traverses the full attack-surface
    graph for chains asset_links alone wouldn't catch (e.g. same service,
    not just same IP). Both are optional and independent; without either,
    behavior is the original single-host heuristic."""
    chains = _single_host_chains(findings, asset_links=asset_links)
    if graph:
        chains += _graph_chains(findings, graph)
    # Longer/multi-asset chains and higher-signal chains are the more
    # actionable ones for a triage view; stable sort keeps ties in discovery order.
    chains.sort(key=lambda c: (len(c.get("assets", [])), len(c["signals"])), reverse=True)
    return chains[:100]


def build_assessment_intelligence(web=None, api=None, findings=None, js_bodies=None, technologies=None, graph: dict | None = None, asset_links: dict[str, set[str]] | None = None):
    inventory=build_endpoint_inventory(web,api)
    plans=Counter(x for row in inventory for x in row.get("test_plan",[]))
    return {
        "version":"1.1",
        "endpoint_inventory":inventory,
        "endpoint_count":len(inventory),
        "parameter_class_counts":dict(plans),
        "js_secret_indicators":scan_js_secrets(js_bodies or []),
        "technology_profile":sorted(set(technologies or [])),
        # `graph` is optional (build_attack_surface_graph, on-demand only) and
        # `asset_links` is optional (build_asset_links, cheap enough to build
        # at scan time - see manager.py) - both feed cross-host chain
        # detection; without either this degrades to the original
        # single-host heuristic rather than failing.
        "attack_chain_hints":attack_chain_hints(findings or [], graph=graph, asset_links=asset_links),
        "test_families":["XSS","SQLi","SSRF","IDOR/BOLA","Path Traversal/LFI","Open Redirect","API schema/authz","WebSocket","Misconfiguration","Secrets"],
    }