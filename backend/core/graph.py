"""Dependency graph (NetworkX): direct vs transitive, 'introduced via' paths, blast radius, layered layout."""
import networkx as nx

ROOT = "__root__"


def node_id(e: dict) -> str:
    return f"{e['ecosystem']}|{e['name']}|{e['version'] or e['specifier'] or '*'}"


def build_graph(entries: list[dict]) -> nx.DiGraph:
    """Adds e['node'] to scannable entries, infers direct/transitive where a lockfile has edges but no roots."""
    G, by_name, file_edges = nx.DiGraph(), {}, {}
    for e in entries:
        if not e["name"] or e["status"] not in ("exact", "unresolved"):
            continue
        nid = e["node"] = node_id(e)
        if nid not in G:
            G.add_node(nid, package=e["name"], version=e["version"] or e["specifier"] or "*", ecosystem=e["ecosystem"])
        by_name.setdefault((e["file"], e["ecosystem"], e["name"]), set()).add(nid)
    for e in entries:
        if "node" not in e:
            continue
        for dname, dver in e.get("deps", []):
            cands = by_name.get((e["file"], e["ecosystem"], dname), ())
            targets = [t for t in cands if dver is None or G.nodes[t]["version"] == dver] or []
            for t in targets:
                if t != e["node"]:
                    G.add_edge(e["node"], t)
                    file_edges.setdefault(e["file"], set()).add((e["node"], t))
    for f, edges in file_edges.items():            # lockfile has edges but no declared roots -> infer
        depended_on = {t for _, t in edges}
        for e in entries:
            if e["file"] == f and "node" in e and e["direct"] is None:
                e["direct"] = e["node"] not in depended_on
                e["direct_inferred"] = True
    return G


def paths_from_roots(G: nx.DiGraph, entries: list[dict]) -> dict:
    """node -> shortest path (list of node ids) from a direct dependency; direct deps map to themselves."""
    H = G.copy()
    H.add_node(ROOT)
    for e in entries:
        if e.get("node") and e["direct"]:
            H.add_edge(ROOT, e["node"])
    return {n: p[1:] for n, p in nx.single_source_shortest_path(H, ROOT).items() if n != ROOT}


def blast_radius(G: nx.DiGraph, node: str) -> int:
    """How many packages (transitively) depend on this one."""
    return len(nx.ancestors(G, node)) if node in G else 0


def to_dict(G: nx.DiGraph, entries: list[dict], vulnerable: set) -> dict:
    direct = {e["node"] for e in entries if e.get("node") and e["direct"]}
    return {"nodes": [{"id": n, "package": d["package"], "version": d["version"], "ecosystem": d["ecosystem"],
                       "direct": n in direct, "vulnerable": n in vulnerable} for n, d in G.nodes(data=True)],
            "edges": [list(x) for x in G.edges()]}


def layered_layout(gd: dict, only_vulnerable: bool = True) -> dict:
    """Positions for plotting. only_vulnerable keeps just the chains root -> vulnerable package."""
    G = nx.DiGraph()
    G.add_nodes_from((n["id"], n) for n in gd["nodes"])
    G.add_edges_from(gd["edges"])
    G.add_node(ROOT)
    G.add_edges_from((ROOT, n["id"]) for n in gd["nodes"] if n["direct"])
    depth = nx.single_source_shortest_path_length(G, ROOT)
    keep = set(G.nodes) - {ROOT}
    if only_vulnerable:
        keep = set()
        for n in gd["nodes"]:
            if n["vulnerable"] and n["id"] in depth:
                keep |= set(nx.shortest_path(G, ROOT, n["id"])) - {ROOT}
    layers = {}
    for n in sorted(keep, key=lambda x: (depth.get(x, 99), x)):
        layers.setdefault(depth.get(n, 99), []).append(n)
    pos = {n: (d, -(i - (len(ns) - 1) / 2)) for d, ns in layers.items() for i, n in enumerate(ns)}
    return {"pos": pos, "edges": [(a, b) for a, b in G.edges if a in keep and b in keep],
            "nodes": {n["id"]: n for n in gd["nodes"] if n["id"] in keep}}
