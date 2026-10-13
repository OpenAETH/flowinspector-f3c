"""
Informe determinista a partir del payload de análisis (`run_analysis`).

Todo lo que contiene es computado, sin IA: mismas entradas -> mismo informe (byte a byte, salvo `generated_at`
que se agrega fuera del contenido hasheable). Cada hallazgo lleva evidencia archivo:línea para poder verificarlo.
"""
from __future__ import annotations
import hashlib
import json
from collections import Counter, defaultdict
from typing import Dict, List, Optional

TOP = 10


def _sccs(graph: Dict[str, List[str]]) -> List[List[str]]:
    """Tarjan iterativo; devuelve componentes con >1 nodo (ciclos de import)."""
    index, low, on, stack, out = {}, {}, set(), [], []
    counter = [0]
    for root in sorted(graph):
        if root in index:
            continue
        work = [(root, iter(sorted(graph.get(root, ()))))]
        index[root] = low[root] = counter[0]; counter[0] += 1; stack.append(root); on.add(root)
        while work:
            v, it = work[-1]
            adv = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter[0]; counter[0] += 1; stack.append(w); on.add(w)
                    work.append((w, iter(sorted(graph.get(w, ()))))); adv = True; break
                elif w in on:
                    low[v] = min(low[v], index[w])
            if adv:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop(); on.discard(w); comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1:
                    out.append(sorted(comp))
    return sorted(out, key=lambda c: (-len(c), c))


def _file_graph(analysis) -> Dict[str, List[str]]:
    g: Dict[str, List[str]] = {}
    for f, d in (analysis.get("dependencies") or {}).items():
        g[f] = sorted({p for p in (d.get("internal_map") or {}).values() if p and p != f})
    return g


def _sym_index(analysis):
    u = analysis.get("unified") or {}
    return u.get("symbols") or {}, u.get("edges") or []


def build_report(analysis: dict, project: str = "") -> dict:
    structure = analysis.get("structure") or {}
    deps = analysis.get("dependencies") or {}
    dead = (analysis.get("dead_code") or {}).get("items") or {}
    symbols, uedges = _sym_index(analysis)
    summary = analysis.get("summary") or {}
    files = sorted(structure)

    # ── métricas por archivo ──
    fan_out = {f: len(g) for f, g in _file_graph(analysis).items()}
    fan_in: Counter = Counter()
    for f, tgts in _file_graph(analysis).items():
        for t in tgts:
            fan_in[t] += 1
    loc = {}
    for f, s in structure.items():
        ends = [x.get("end_line") or 0 for x in (s.get("functions") or [])]
        for c in (s.get("classes") or {}).values():
            ends += [x.get("end_line") or 0 for x in (c.get("methods") or [])]
        loc[f] = max(ends) if ends else 0

    # ── resolución de llamadas ──
    calls = [e for e in uedges if e.get("relation") == "CALLS"]
    conf = Counter(e.get("confidence", "?") for e in calls)
    by_res = Counter(e.get("resolved_by", "?") for e in calls)
    resolution = {
        "calls_total": len(calls),
        "by_confidence": dict(sorted(conf.items())),
        "by_resolver": dict(sorted(by_res.items())),
        "ambiguous": sum(1 for e in calls if e.get("ambiguous")),
        "external": sum(1 for e in calls if e.get("external")),
        "internal_resolved_pct": round(100.0 * sum(1 for e in calls if not e.get("external") and not e.get("ambiguous"))
                                       / max(1, sum(1 for e in calls if not e.get("external"))), 1) if any(not e.get("external") for e in calls) else None,
    } if uedges else None

    # ── callers por símbolo ──
    callers: Dict[str, set] = defaultdict(set)
    for e in calls:
        if not e.get("external"):
            callers[e["dst"]].add(e["src"])
    top_called = sorted(((len(v), k) for k, v in callers.items() if k in symbols), key=lambda t: (-t[0], t[1]))[:TOP]
    top_called = [{"uid": k, "name": symbols[k]["qualname"], "file": symbols[k]["file"], "line": symbols[k]["line"], "callers": n}
                  for n, k in top_called]

    # ── funciones más largas (aprox. complejidad estructural) ──
    sized = [(s["end_line"] - s["line"] + 1, s) for s in symbols.values()
             if s.get("kind") in ("function", "method") and s.get("end_line")]
    longest = [{"uid": s["uid"], "name": s["qualname"], "file": s["file"], "line": s["line"], "lines": n}
               for n, s in sorted(sized, key=lambda t: (-t[0], t[1]["uid"]))[:TOP]]

    # ── colisiones de nombres entre archivos ──
    byname = defaultdict(set)
    for s in symbols.values():
        if s.get("kind") in ("function", "class", "method") and not (s["name"].startswith("__") and s["name"].endswith("__")):
            byname[s["name"]].add(s["file"])
    collisions = [{"name": n, "files": sorted(fs)} for n, fs in sorted(byname.items(), key=lambda t: (-len(t[1]), t[0]))
                  if len(fs) > 1][:TOP]

    # ── código muerto (score alto) con ubicación ──
    line_of = {(s["file"], s["qualname"]): s["line"] for s in symbols.values()}
    dead_items = []
    for f, items in dead.items():
        for it in items:
            if it.get("score", 0) >= 0.7:
                q = f"{it['class']}.{it['name']}" if it.get("class") else it["name"]
                dead_items.append({"file": f, "name": q, "kind": it.get("kind"), "score": it["score"], "line": line_of.get((f, q))})
    dead_items.sort(key=lambda d: (-d["score"], d["file"], d["name"]))

    cycles = _sccs(_file_graph(analysis))
    hubs = sorted(files, key=lambda f: (-(fan_in[f] + fan_out.get(f, 0)), f))[:TOP]
    hotspots = [{"file": f, "fan_in": fan_in[f], "fan_out": fan_out.get(f, 0), "lines": loc.get(f, 0)} for f in hubs if fan_in[f] + fan_out.get(f, 0)]

    # ── hallazgos (cada uno con severidad y evidencia) ──
    findings: List[dict] = []
    for c in cycles[:5]:
        findings.append({"id": f"cycle:{c[0]}", "severity": "high" if len(c) > 3 else "medium", "title": f"Ciclo de imports entre {len(c)} archivos",
                         "evidence": [{"file": f} for f in c[:6]]})
    if dead_items:
        findings.append({"id": "dead-high", "severity": "medium", "title": f"{len(dead_items)} símbolos con alta probabilidad de código muerto",
                         "evidence": [{"file": d["file"], "line": d["line"], "symbol": d["name"]} for d in dead_items[:5]]})
    for n in collisions[:3]:
        findings.append({"id": f"collision:{n['name']}", "severity": "low", "title": f"Nombre `{n['name']}` definido en {len(n['files'])} archivos",
                         "evidence": [{"file": f} for f in n["files"][:5]]})
    for l in longest[:3]:
        if l["lines"] >= 80:
            findings.append({"id": f"long:{l['uid']}", "severity": "low", "title": f"Función larga `{l['name']}` ({l['lines']} líneas)",
                             "evidence": [{"file": l["file"], "line": l["line"], "symbol": l["name"]}]})
    if resolution and resolution["internal_resolved_pct"] is not None and resolution["internal_resolved_pct"] < 80:
        findings.append({"id": "resolution", "severity": "info", "title": f"Solo {resolution['internal_resolved_pct']}% de las llamadas internas se resolvió sin ambigüedad",
                         "evidence": []})
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["id"]))

    body = {
        "project": project or "",
        "overview": {
            "files": len(files), "classes": summary.get("total_classes"), "functions": summary.get("total_functions"),
            "nodes": summary.get("total_nodes"), "edges": summary.get("total_edges"),
            "symbols": summary.get("symbols"), "engine": analysis.get("engine"),
            "dead": (analysis.get("dead_code") or {}).get("summary"),
        },
        "resolution": resolution,
        "hotspots": hotspots,
        "most_called": top_called,
        "longest_functions": longest,
        "import_cycles": cycles[:10],
        "name_collisions": collisions,
        "dead_code_high": dead_items[:25],
        "findings": findings,
    }
    body["digest"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return body
