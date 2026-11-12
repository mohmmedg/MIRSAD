"""Safe, deterministic attack-path analysis over an asset graph.
Nodes/edges are descriptive; this module never performs exploitation."""
from collections import defaultdict, deque

def shortest_paths_to_critical(nodes, edges, *, max_paths=20):
    critical = {n["id"] for n in nodes if n.get("critical") is True}
    graph = defaultdict(list)
    for e in edges:
        graph[e["source"]].append(e["target"])
    results = []
    for start in [n["id"] for n in nodes if n.get("exposed") is True]:
        q = deque([(start, [start])]); seen = {start}
        while q:
            cur, path = q.popleft()
            if cur in critical and len(path) > 1:
                results.append({"start": start, "target": cur, "path": path, "hops": len(path)-1})
                break
            for nxt in graph[cur]:
                if nxt not in seen and len(path) < 32:
                    seen.add(nxt); q.append((nxt, path+[nxt]))
        if len(results) >= max_paths: break
    return sorted(results, key=lambda x: (x["hops"], x["start"], x["target"]))
