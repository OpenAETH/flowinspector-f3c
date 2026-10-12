"""
Constructor del grafo unificado.

Entrada : {ruta: fuente} de archivos Python (nunca se ejecuta ni importa nada).
Salida  : - `UnifiedGraph`: símbolos con identidad calificada por archivo, aristas
            DEFINES / IMPORTS / INHERITS / CALLS con archivo, línea, confianza y
            vía de resolución.
          - proyecciones con el contrato histórico (`structure`, `dependencies`,
            `call_graph`, `graph`) que consumen la UI y el runtime v4.

Política de IDs históricos (`function:x`, `method:C.m`, `class:C`): se conservan
tal cual cuando son únicos en el proyecto y se califican con `@archivo` solo
cuando colisionan, de modo que nada cambia para el código sin colisiones.
"""

from __future__ import annotations
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .model import (
    Edge, FileFacts, Symbol, module_uid,
    CONF_EXACT, CONF_HIGH, CONF_MEDIUM, CONF_LOW, CONF_ORDER,
    REL_CALLS, REL_DEFINES, REL_IMPORTS, REL_INHERITS,
    KIND_MODULE, KIND_CLASS, KIND_FUNCTION, KIND_METHOD,
)
from .modules import ModuleIndex
from .py_ast import AstExtractor
from .resolver import ProjectResolver

SCHEMA_VERSION = "1"
_PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


@dataclass
class UnifiedGraph:
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    modules: Dict[str, dict] = field(default_factory=dict)
    diagnostics: List[dict] = field(default_factory=list)
    backends: Dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        rel = Counter(e.relation for e in self.edges)
        calls = [e for e in self.edges if e.relation == REL_CALLS]
        return {
            "version": SCHEMA_VERSION,
            "backends": self.backends,
            "modules": self.modules,
            "symbols": {u: s.to_dict() for u, s in self.symbols.items()},
            "edges": [e.to_dict() for e in self.edges],
            "diagnostics": self.diagnostics,
            "stats": {
                "symbols": len(self.symbols),
                "edges": len(self.edges),
                "by_relation": dict(rel),
                "calls_by_confidence": dict(Counter(e.confidence for e in calls)),
                "calls_by_resolver": dict(Counter(e.resolved_by for e in calls)),
                "calls_ambiguous": sum(1 for e in calls if e.ambiguous),
                "calls_external": sum(1 for e in calls if e.external),
            },
        }


class UnifiedGraphBuilder:
    """
    `fallback_extractor`: callable(file, source, modname, is_pkg) -> FileFacts, usado cuando
    `ast` rechaza el archivo (p.ej. el backend tree-sitter, tolerante a errores de sintaxis).
    `enrichers`: callables(builder, graph) que mejoran el grafo ya resuelto (p.ej. SCIP).
    """

    def __init__(self, files: Dict[str, str],
                 fallback_extractor: Optional[Callable] = None,
                 enrichers: Optional[List[Callable]] = None):
        self.files = files
        self.fallback = fallback_extractor
        self.enrichers = enrichers or []
        self.graph = UnifiedGraph()
        self.facts: Dict[str, FileFacts] = {}
        self.mindex: Optional[ModuleIndex] = None
        self.resolver: Optional[ProjectResolver] = None

    # ═════════════════ construcción ═════════════════
    def build(self) -> UnifiedGraph:
        g = self.graph
        self.mindex = ModuleIndex(self.files.keys())
        ast_x = AstExtractor()
        recovered = 0
        for fp in sorted(self.files):
            modname, is_pkg = self.mindex.module_of(fp)
            src = self.files[fp]
            try:
                ff = ast_x.extract(fp, src, modname, is_pkg)
            except _PARSE_ERRORS as e:
                ff = None
                if self.fallback is not None:
                    try:
                        ff = self.fallback(fp, src, modname, is_pkg)
                        recovered += 1
                    except Exception as e2:      # el fallback nunca debe tumbar el análisis
                        e = e2
                if ff is None:
                    ff = self._empty(fp, modname, is_pkg)
                    ff.parse_ok = False
                g.diagnostics.append({
                    "file": fp, "level": "warning", "code": "parse-error",
                    "message": f"{type(e).__name__}: {e}",
                    "recovered_by": ff.backend if ff.symbols and len(ff.symbols) > 1 else None})
            self.facts[fp] = ff
            g.modules[fp] = {"module": modname, "is_package": is_pkg, "backend": ff.backend,
                             "parse_ok": ff.parse_ok, "parse_errors": ff.parse_errors}
            for s in ff.symbols:
                g.symbols[s.uid] = s
        g.backends["ast"] = {"enabled": True, "files": sum(1 for f in self.facts.values() if f.backend == "ast")}
        if recovered:
            g.backends["fallback"] = {"enabled": True, "files_recovered": recovered}

        self.resolver = ProjectResolver(self.facts, self.mindex)
        self._defines()
        self._imports()
        g.edges.extend(self.resolver.inherit_edges())
        for fp in sorted(self.facts):
            for cs in self.facts[fp].calls:
                g.edges.extend(self.resolver.resolve_call(cs))
        for enr in self.enrichers:
            enr(self, g)
        self._dedupe()
        self._assign_node_ids()
        return g

    @staticmethod
    def _empty(fp: str, modname: str, is_pkg: bool) -> FileFacts:
        ff = FileFacts(file=fp, module=modname, is_package=is_pkg, module_uid=module_uid(fp), backend="none")
        ff.symbols.append(Symbol(uid=ff.module_uid, kind=KIND_MODULE, name=modname.split(".")[-1] or fp,
                                 qualname="", file=fp, module=modname, line=1, end_line=1, sources=["none"]))
        return ff

    def _defines(self):
        for s in self.graph.symbols.values():
            if s.kind != KIND_MODULE and s.parent:
                self.graph.edges.append(Edge(s.parent, s.uid, REL_DEFINES, s.file, s.line,
                                             confidence=CONF_EXACT, resolved_by="syntax"))

    def _imports(self):
        for fp in sorted(self.facts):
            ff = self.facts[fp]
            for entry, kind, rf, names, b, res in self.resolver.dependency_entries(fp):
                if kind == "file":
                    dst, ext = module_uid(rf), False
                elif kind == "namespace":
                    dst, ext = f"ns:{res.modname}", False
                else:
                    dst, ext = f"ext:{entry}", True
                self.graph.edges.append(Edge(
                    ff.module_uid, dst, REL_IMPORTS, fp, b.line, confidence=res.confidence,
                    resolved_by=res.how, ambiguous=res.ambiguous, external=ext, expr=entry, symbols=names))

    def _dedupe(self):
        best: Dict[tuple, Edge] = {}
        for e in self.graph.edges:
            k = e.key()
            cur = best.get(k)
            if cur is None or CONF_ORDER[e.confidence] > CONF_ORDER[cur.confidence]:
                best[k] = e
        self.graph.edges = list(best.values())

    # ═════════════════ IDs históricos ═════════════════
    def _legacy_visible(self, s: Symbol) -> bool:
        """Símbolos que existen en el esquema histórico: clases/funciones de nivel módulo y sus métodos directos."""
        if s.kind in (KIND_CLASS, KIND_FUNCTION):
            return s.parent == module_uid(s.file)
        if s.kind == KIND_METHOD:
            p = self.graph.symbols.get(s.parent or "")
            return p is not None and p.kind == KIND_CLASS and p.parent == module_uid(p.file)
        return False

    def _legacy_base(self, s: Symbol) -> str:
        if s.kind == KIND_CLASS:
            return f"class:{s.name}"
        if s.kind == KIND_METHOD:
            return f"method:{self.graph.symbols[s.parent].name}.{s.name}"
        return f"function:{s.name}"

    def _assign_node_ids(self):
        vis = [s for s in self.graph.symbols.values() if self._legacy_visible(s)]
        count = Counter(self._legacy_base(s) for s in vis)
        for s in vis:
            base = self._legacy_base(s)
            s.legacy_id = base
            if count[base] == 1:
                s.node_id = base
            else:
                n = s.uid.rsplit("#", 1)[1] if "#" in s.uid.rsplit("::", 1)[-1] else ""
                s.node_id = f"{base}@{s.file}" + (f"#{n}" if n else "")
        for s in self.graph.symbols.values():
            if s.kind == KIND_MODULE:
                s.node_id = f"file:{s.file}"

    # ═════════════════ proyecciones históricas ═════════════════
    def legacy_structure(self) -> dict:
        syms = self.graph.symbols
        members: Dict[str, List[Symbol]] = defaultdict(list)
        for s in syms.values():
            if s.parent:
                members[s.parent].append(s)

        def meta(s: Symbol) -> dict:
            return {"id": s.node_id, "uid": s.uid, "line": s.line, "end_line": s.end_line}

        out = {}
        for fp, ff in self.facts.items():
            classes, funcs = {}, []
            for s in sorted(members.get(ff.module_uid, []), key=lambda x: x.line):
                if s.kind == KIND_CLASS:
                    methods = [{"name": m.name, "decorators": m.decorators, **meta(m)}
                               for m in sorted(members.get(s.uid, []), key=lambda x: x.line) if m.kind == KIND_METHOD]
                    classes[s.name] = {"methods": methods, "inherits": s.bases, "decorators": s.decorators, **meta(s)}
                elif s.kind == KIND_FUNCTION:
                    funcs.append({"name": s.name, "decorators": s.decorators, **meta(s)})
            out[fp] = {"classes": classes, "functions": funcs}
        return out

    def legacy_dependencies(self) -> dict:
        out = {}
        for fp in self.facts:
            allm, internal, external, imap, symused = [], [], [], {}, {}
            for entry, kind, rf, names, b, res in self.resolver.dependency_entries(fp):
                allm.append(entry)
                if kind == "external":
                    external.append(entry)
                    continue
                internal.append(entry)
                if kind == "file":
                    imap[entry] = rf
                    cur = symused.setdefault(rf, [])
                    cur.extend(n for n in names if n not in cur)
            out[fp] = {"all": allm, "internal": internal, "external": external,
                       "internal_map": imap, "symbols_used": symused}
        return out

    def legacy_call_graph(self) -> dict:
        syms = self.graph.symbols
        out: Dict[str, Dict[str, list]] = {}
        for fp, ff in self.facts.items():
            cg: Dict[str, list] = {}
            for cs in ff.calls:
                s = syms.get(cs.caller)
                key = "<module>" if s is None or s.kind == KIND_MODULE else s.qualname
                cg.setdefault(key, []).append({"name": cs.expr, "line": cs.line})
            out[fp] = cg
        return out

    def legacy_graph(self, deps: dict, structure: dict) -> dict:
        """graph.nodes / graph.edges con las mismas relaciones y tipos que la UI ya sabe dibujar."""
        syms = self.graph.symbols
        nodes: Dict[str, dict] = {}
        edges: List[dict] = []
        fid = lambda fp: f"file:{fp}"

        for fp in deps:
            nodes[fid(fp)] = {"type": "file", "label": os.path.basename(fp), "path": fp}

        # imports -> nodos módulo + IMPORTS + FILE_USES
        for fp in deps:
            for entry, kind, rf, names, b, res in self.resolver.dependency_entries(fp):
                if kind == "file":
                    mkey = res.modname
                elif kind == "namespace":
                    mkey = res.modname
                else:
                    mkey = entry
                mid = f"module:{mkey}"
                nodes.setdefault(mid, {"type": "module", "label": mkey})
                edges.append({"from": fid(fp), "to": mid, "relation": "IMPORTS", "is_internal": kind != "external"})
        for fp, d in deps.items():
            for entry, rf in d["internal_map"].items():
                edges.append({"from": fid(fp), "to": fid(rf), "relation": "FILE_USES",
                              "symbols": d["symbols_used"].get(rf, []), "module": entry})

        # estructura -> nodos class/function + DEFINES
        def lbl(nid: str, text: str, fp: str) -> str:
            """Si el id fue calificado por colisión, la etiqueta agrega el archivo para distinguir nodos homónimos."""
            return f"{text} ({os.path.basename(fp)})" if "@" in nid else text

        for fp, data in structure.items():
            for cname, c in data["classes"].items():
                nodes[c["id"]] = {"type": "class", "label": lbl(c["id"], cname, fp), "decorators": c["decorators"],
                                  "inherits": c["inherits"], "path": fp, "line": c["line"], "uid": c["uid"]}
                edges.append({"from": fid(fp), "to": c["id"], "relation": "DEFINES"})
                for m in c["methods"]:
                    nodes[m["id"]] = {"type": "function", "label": lbl(m["id"], f"{cname}.{m['name']}", fp), "short_name": m["name"],
                                      "class": cname, "decorators": m["decorators"], "path": fp,
                                      "line": m["line"], "uid": m["uid"]}
                    edges.append({"from": c["id"], "to": m["id"], "relation": "DEFINES"})
            for f in data["functions"]:
                nodes[f["id"]] = {"type": "function", "label": lbl(f["id"], f["name"], fp), "decorators": f["decorators"],
                                  "path": fp, "line": f["line"], "uid": f["uid"]}
                edges.append({"from": fid(fp), "to": f["id"], "relation": "DEFINES"})

        # llamadas
        def visible_anchor(uid: str) -> Optional[str]:
            """node id histórico del símbolo o de su ancestro visible más cercano."""
            cur = syms.get(uid)
            while cur is not None:
                if cur.kind == KIND_MODULE:
                    return fid(cur.file)
                if cur.node_id and self._legacy_visible(cur):
                    return cur.node_id
                cur = syms.get(cur.parent or "")
            return None

        seen = set()
        for e in self.graph.edges:
            if e.relation != REL_CALLS:
                continue
            if e.resolved_by in ("name-fanout", "ctor-init"):
                continue                                    # solo en el grafo unificado
            src = visible_anchor(e.src)
            if src is None:
                continue
            from_module = src.startswith("file:")
            if e.external:
                if from_module:
                    continue                                # sin ruido de builtins/librerías a nivel módulo
                dotted = e.dst[4:]                          # "ext:os.getcwd" -> "os.getcwd"
                tid = f"unknown:{dotted[2:]}" if dotted.startswith("*.") else f"unknown:{dotted}"
                nodes.setdefault(tid, {"type": "external", "label": e.expr or dotted})
            else:
                tid = visible_anchor(e.dst)
                if tid is None or tid == src:
                    continue
            k = (src, tid, e.line)
            if k in seen:
                continue
            seen.add(k)
            edges.append({"from": src, "to": tid, "relation": "CALLS", "line": e.line,
                          "confidence": e.confidence, "resolved_by": e.resolved_by, "file": e.file})
        return {"nodes": nodes, "edges": edges}

    def legacy_bundle(self) -> dict:
        structure = self.legacy_structure()
        deps = self.legacy_dependencies()
        return {"structure": structure, "dependencies": deps,
                "call_graph": self.legacy_call_graph(),
                "graph": self.legacy_graph(deps, structure)}
