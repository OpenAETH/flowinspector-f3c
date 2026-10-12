"""
Enriquecedor SCIP (scip-python / Pyright) — OPCIONAL.

Ejecuta `scip-python index` sobre una COPIA SANEADA del proyecto analizado y usa
las referencias del índice para confirmar o corregir las aristas CALLS del grafo
unificado (confianza `exact`, `resolved_by="scip"`).

Garantías de seguridad (el repositorio analizado nunca se ejecuta):
  * Se copian únicamente archivos .py, con rutas validadas (sin absolutas, sin `..`,
    sin NUL, sin enlaces): un ZIP malicioso no puede escribir fuera del directorio temporal.
  * Se escribe una `scip-pyrightconfig.json` propia; el `pyrightconfig.json`/`pyproject.toml`
    del proyecto no se copian, así que no puede influir en el intérprete ni en los paths.
  * Entorno vacío (`env -i` equivalente): PYTHONSAFEPATH=1, PYTHONNOUSERSITE=1, HOME aislado,
    sin variables heredadas. `--environment` apunta a una lista vacía, por lo que scip-python
    no invoca `pip`.
  * Directorio de trabajo temporal, timeout duro y límites de tamaño/cantidad de archivos.

Activación: FI_SCIP=1 (y `scip-python` en PATH o FI_SCIP_BIN). Cualquier fallo degrada
silenciosamente al grafo base con un diagnóstico; nunca rompe el análisis.
"""

from __future__ import annotations
import json
import os
import posixpath
import shutil
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from .model import Edge, REL_CALLS, CONF_EXACT, KIND_CLASS, KIND_MODULE
from .scip_reader import ScipIndex, parse_index, ScipFormatError

MAX_FILES = int(os.environ.get("FI_SCIP_MAX_FILES", "5000"))
MAX_BYTES = int(os.environ.get("FI_SCIP_MAX_BYTES", str(25 * 1024 * 1024)))
TIMEOUT_S = int(os.environ.get("FI_SCIP_TIMEOUT", "90"))


def enabled() -> bool:
    return os.environ.get("FI_SCIP", "").strip().lower() in ("1", "true", "yes", "on")


def find_binary() -> Optional[str]:
    explicit = os.environ.get("FI_SCIP_BIN", "").strip()
    if explicit:
        return explicit if os.path.isfile(explicit) and os.access(explicit, os.X_OK) else None
    return shutil.which("scip-python")


def safe_relpath(p: str) -> Optional[str]:
    """Ruta relativa normalizada y segura, o None si no es aceptable."""
    if not p or "\x00" in p:
        return None
    p = p.replace("\\", "/")
    if p.startswith("/") or (len(p) > 1 and p[1] == ":"):
        return None
    norm = posixpath.normpath(p)
    if norm in (".", "") or norm.startswith("../") or norm == ".." or "/../" in f"/{norm}/":
        return None
    if not norm.endswith(".py"):
        return None
    return norm


class ScipResult:
    def __init__(self):
        self.index: Optional[ScipIndex] = None
        self.error: Optional[str] = None
        self.seconds: float = 0.0
        self.files_staged: int = 0
        self.files_skipped: int = 0
        self.tool: str = ""


def run_scip(files: Dict[str, str], binary: Optional[str] = None) -> ScipResult:
    res = ScipResult()
    binary = binary or find_binary()
    if not binary:
        res.error = "scip-python no encontrado (instalar con `npm i -g @sourcegraph/scip-python` o definir FI_SCIP_BIN)"
        return res
    work = tempfile.mkdtemp(prefix="fi-scip-")
    try:
        proj = os.path.join(work, "proj")
        runcwd = os.path.join(work, "run")
        home = os.path.join(work, "home")
        for d in (proj, runcwd, home):
            os.makedirs(d)
        total = 0
        for orig, src in files.items():
            rel = safe_relpath(orig)
            data = src.encode("utf-8", "replace")
            total += len(data)
            if rel is None or res.files_staged >= MAX_FILES or total > MAX_BYTES:
                res.files_skipped += 1
                continue
            dest = os.path.join(proj, *rel.split("/"))
            if os.path.commonpath([os.path.realpath(proj), os.path.realpath(os.path.dirname(dest))]) != os.path.realpath(proj):
                res.files_skipped += 1
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(data)
            res.files_staged += 1
        if not res.files_staged:
            res.error = "sin archivos aptos para SCIP"
            return res
        with open(os.path.join(proj, "scip-pyrightconfig.json"), "w") as fh:
            json.dump({"include": ["."], "pythonVersion": "3.12"}, fh)
        envfile = os.path.join(work, "env.json")
        with open(envfile, "w") as fh:
            fh.write("[]")
        out = os.path.join(work, "index.scip")
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": home,
            "TMPDIR": work,
            "PYTHONSAFEPATH": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NODE_OPTIONS": os.environ.get("FI_SCIP_NODE_OPTIONS", "--max-old-space-size=2048"),
            "CI": "1",
        }
        cmd = [binary, "index", "--cwd", proj, "--project-name", "fi", "--project-version", "0",
               "--environment", envfile, "--output", out, "--quiet"]
        t0 = time.perf_counter()
        try:
            cp = subprocess.run(cmd, cwd=runcwd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=TIMEOUT_S, text=True, errors="replace")
        except subprocess.TimeoutExpired:
            res.error = f"scip-python excedió {TIMEOUT_S}s"
            return res
        except OSError as e:
            res.error = f"no se pudo ejecutar scip-python: {e}"
            return res
        res.seconds = time.perf_counter() - t0
        if cp.returncode != 0 or not os.path.isfile(out):
            res.error = f"scip-python terminó con código {cp.returncode}: {(cp.stderr or cp.stdout or '')[-300:].strip()}"
            return res
        try:
            with open(out, "rb") as fh:
                res.index = parse_index(fh.read())
        except (ScipFormatError, OSError) as e:
            res.error = f"índice SCIP inválido: {e}"
            return res
        res.tool = f"{res.index.tool} {res.index.tool_version}".strip()
        return res
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _pretty(symbol: str) -> str:
    """'scip-python python pkg 1.0 `a.b`/f().' -> 'a.b.f' (mejor esfuerzo, solo para externos)."""
    parts = symbol.split(" ", 4)
    tail = parts[4] if len(parts) == 5 else symbol
    return tail.replace("`", "").replace("/", ".").replace("#", ".").replace("().", "").rstrip(".:")


def make_enricher(result: ScipResult):
    """Devuelve un enricher(builder, graph) que aplica `result.index` al grafo."""

    def enrich(builder, graph):
        stats = {"enabled": True, "tool": result.tool, "seconds": round(result.seconds, 3),
                 "files_staged": result.files_staged, "files_skipped": result.files_skipped}
        if result.index is None:
            graph.backends["scip"] = {**stats, "applied": False, "error": result.error}
            graph.diagnostics.append({"level": "info", "code": "scip-unavailable", "message": result.error})
            return
        idx = result.index
        defs: Dict[str, Tuple[str, int, int]] = {}
        for path, doc in idx.documents.items():
            for o in doc.occurrences:
                if o.is_definition and o.symbol and not o.symbol.startswith("local "):
                    defs.setdefault(o.symbol, (path, o.start_line, o.start_char))
        by_pos = {}
        for s in graph.symbols.values():
            if s.kind != KIND_MODULE and s.name_line:
                by_pos[(s.file, s.name_line - 1, s.name_col)] = s

        groups: Dict[tuple, List[Edge]] = {}
        for e in graph.edges:
            if e.relation == REL_CALLS:
                groups.setdefault((e.src, e.file, e.line, e.col), []).append(e)

        c = dict(calls=0, matched=0, confirmed=0, corrected=0, added=0, external_confirmed=0,
                 no_occurrence=0, unmapped=0)
        drop: set = set()
        add: List[Edge] = []
        for fp, ff in builder.facts.items():
            doc = idx.documents.get(fp)
            if doc is None:
                continue
            refs = {}
            for o in doc.occurrences:
                if not o.is_definition and o.symbol:
                    refs.setdefault((o.start_line, o.start_char), o)
            for cs in ff.calls:
                c["calls"] += 1
                occ = refs.get((cs.name_line - 1, cs.name_col))
                if occ is None:
                    c["no_occurrence"] += 1
                    continue
                site = groups.get((cs.caller, cs.file, cs.line, cs.col), [])
                d = defs.get(occ.symbol)
                tgt = by_pos.get((d[0], d[1], d[2])) if d else None
                if tgt is None:
                    if d is None and not occ.symbol.startswith("local "):
                        ext = [e for e in site if e.external]
                        if ext:
                            for e in ext:
                                e.confidence, e.resolved_by = CONF_EXACT, "scip"
                            c["external_confirmed"] += 1
                            c["matched"] += 1
                            continue
                    c["unmapped"] += 1
                    continue
                c["matched"] += 1
                exact = [e for e in site if e.dst == tgt.uid]
                if exact:
                    for e in exact:
                        e.confidence, e.resolved_by, e.ambiguous = CONF_EXACT, "scip", False
                    keep = {id(e) for e in exact}
                    for e in site:                        # fan-out por nombre ya no aplica
                        if id(e) not in keep and e.resolved_by in ("name-fanout", "name-unique"):
                            drop.add(id(e))
                    c["confirmed"] += 1
                    continue
                for e in site:
                    if e.resolved_by == "ctor-init" and tgt.kind == KIND_CLASS \
                            and graph.symbols.get(e.dst) is not None and graph.symbols[e.dst].parent == tgt.uid:
                        continue
                    drop.add(id(e))
                add.append(Edge(cs.caller, tgt.uid, REL_CALLS, cs.file, cs.line, cs.col,
                                confidence=CONF_EXACT, resolved_by="scip", expr=cs.expr))
                c["corrected" if site else "added"] += 1
        graph.edges = [e for e in graph.edges if id(e) not in drop] + add
        graph.backends["scip"] = {**stats, "applied": True, **c,
                                  # acuerdo sobre sitios donde SCIP resolvió a un símbolo interno del proyecto
                                  "agreement": round(c["confirmed"] / (c["confirmed"] + c["corrected"]), 4)
                                  if (c["confirmed"] + c["corrected"]) else None}

    return enrich
