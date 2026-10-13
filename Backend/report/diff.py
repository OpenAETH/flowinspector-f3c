"""Snapshot compacto de un análisis y diff entre dos snapshots (por uid, no por posición)."""
from __future__ import annotations
from typing import Optional

SNAPSHOT_VERSION = 1


def make_snapshot(analysis: dict, report: Optional[dict] = None) -> dict:
    u = analysis.get("unified") or {}
    syms = u.get("symbols") or {}
    edges = u.get("edges") or []
    snap = {
        "version": SNAPSHOT_VERSION,
        "symbols": {uid: [s["kind"], s["file"], s["line"], (s.get("end_line") or s["line"]) - s["line"] + 1] for uid, s in syms.items()},
        "edges": sorted({f"{e['src']}>{e['dst']}|{e['relation']}" for e in edges if e["relation"] in ("CALLS", "IMPORTS", "INHERITS")}),
        "dead": sorted(f"{d['file']}::{d['name']}" for d in ((report or {}).get("dead_code_high") or [])),
        "cycles": sorted("|".join(c) for c in ((report or {}).get("import_cycles") or [])),
        "files": sorted((analysis.get("structure") or {}).keys()),
    }
    if not syms:   # payload recortado o motor legacy: queda diff solo por archivos/código muerto
        snap["limited"] = True
    return snap


def _lim(xs, n=30):
    xs = sorted(xs)
    return {"count": len(xs), "items": xs[:n]}


def diff_snapshots(old: dict, new: dict) -> dict:
    if not old or old.get("version") != SNAPSHOT_VERSION:
        return {"comparable": False, "reason": "sin línea base compatible"}
    os_, ns = old["symbols"], new["symbols"]
    added, removed = set(ns) - set(os_), set(os_) - set(ns)
    changed = [u for u in set(ns) & set(os_) if ns[u][3] != os_[u][3]]
    moved = [u for u in set(ns) & set(os_) if ns[u][1] != os_[u][1]]
    oe, ne = set(old["edges"]), set(new["edges"])
    od, nd = set(old["dead"]), set(new["dead"])
    oc, nc = set(old["cycles"]), set(new["cycles"])
    return {
        "comparable": True,
        "files": {"added": _lim(set(new["files"]) - set(old["files"])), "removed": _lim(set(old["files"]) - set(new["files"]))},
        "symbols": {"added": _lim(added), "removed": _lim(removed), "resized": _lim(changed), "moved": _lim(moved)},
        "edges": {"added": _lim(ne - oe), "removed": _lim(oe - ne)},
        "dead_code": {"new": _lim(nd - od), "resolved": _lim(od - nd)},
        "cycles": {"new": _lim(nc - oc), "resolved": _lim(oc - nc)},
        "limited": bool(old.get("limited") or new.get("limited")),
    }
