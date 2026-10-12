"""
Resolución de nombres, imports, herencia y llamadas sobre `FileFacts`.

Orden de búsqueda de un nombre (reglas léxicas de Python):
    funciones contenedoras (defs anidados, imports locales)  ->  módulo (defs e imports,
    gana la línea más tardía)  ->  `from x import *`  ->  builtins.
Los cuerpos de clase NO son visibles desde sus métodos, igual que en Python.

Cada arista lleva `confidence` y `resolved_by`; nunca se elige un candidato al azar:
si solo se conoce el nombre, o hay un único candidato (low/name-unique) o se emiten
todos marcados `ambiguous` (low/name-fanout).
"""

from __future__ import annotations
import builtins
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .model import (
    Edge, FileFacts, Symbol, ImportBinding, CallSite, module_uid,
    CONF_HIGH, CONF_MEDIUM, CONF_LOW, CONF_ORDER,
    REL_CALLS, REL_INHERITS, REL_IMPORTS,
    KIND_CLASS, KIND_FUNCTION, KIND_METHOD, KIND_MODULE,
)
from .modules import ModuleIndex, ModuleRes

_BUILTINS = frozenset(dir(builtins))
MAX_FANOUT = 4


def _min_conf(a: str, b: str) -> str:
    return a if CONF_ORDER[a] <= CONF_ORDER[b] else b


@dataclass
class Target:
    kind: str                       # symbol | module | external | unknown
    symbol: Optional[Symbol] = None
    file: Optional[str] = None      # módulo con archivo
    modname: str = ""               # dotted: módulo interno/externo o nombre pedido
    confidence: str = CONF_HIGH
    how: str = "lexical"
    ambiguous: bool = False
    ns: bool = False                # namespace package (sin archivo)
    external_kind: str = ""
    alts: List[Symbol] = field(default_factory=list)   # defs condicionales homónimas (if/else, try/except)

    def with_conf(self, conf: str, how: Optional[str] = None, amb: bool = False) -> "Target":
        return Target(self.kind, self.symbol, self.file, self.modname, _min_conf(self.confidence, conf),
                      how or self.how, self.ambiguous or amb, self.ns, self.external_kind, self.alts)


class ProjectResolver:
    def __init__(self, facts: Dict[str, FileFacts], mindex: ModuleIndex):
        self.facts = facts
        self.mi = mindex
        self.sym: Dict[str, Symbol] = {}
        self.top: Dict[str, Dict[str, List[Symbol]]] = defaultdict(lambda: defaultdict(list))
        self.members: Dict[str, Dict[str, List[Symbol]]] = defaultdict(lambda: defaultdict(list))
        self.binds: Dict[Tuple[str, str], List[ImportBinding]] = defaultdict(list)
        self.stars: Dict[str, List[ImportBinding]] = defaultdict(list)
        self.methods_by_name: Dict[str, List[Symbol]] = defaultdict(list)
        self.defs_by_name: Dict[str, List[Symbol]] = defaultdict(list)
        self._bind_cache: Dict[int, Optional[Target]] = {}
        self._bases_cache: Dict[str, List[Target]] = {}
        for ff in facts.values():
            for s in ff.symbols:
                self.sym[s.uid] = s
                if s.kind == KIND_MODULE:
                    continue
                if s.parent == ff.module_uid:
                    self.top[ff.file][s.name].append(s)
                    self.defs_by_name[s.name].append(s)
                else:
                    self.members[s.parent][s.name].append(s)
                if s.kind == KIND_METHOD:
                    self.methods_by_name[s.name].append(s)
            for b in ff.imports:
                if b.is_star and b.scope == ff.module_uid:
                    self.stars[ff.file].append(b)
                else:
                    self.binds[(ff.file, b.scope)].append(b)

    # ── imports ──────────────────────────────────────
    def _mod_target(self, res: ModuleRes, name: str) -> Target:
        if res.kind == "file":
            return Target("module", file=res.file, modname=res.modname, confidence=res.confidence,
                          how=res.how, ambiguous=res.ambiguous)
        if res.kind == "namespace":
            return Target("module", modname=res.modname or name, confidence=res.confidence, how=res.how, ns=True)
        return Target("external", modname=res.modname or name, how="external", external_kind=res.external_kind)

    def bind_target(self, b: ImportBinding, seen: Optional[Set] = None) -> Optional[Target]:
        """Destino al que queda ligado el nombre local de un import."""
        seen = seen if seen is not None else set()
        ck = id(b)
        if ck in self._bind_cache:
            return self._bind_cache[ck]
        if ck in seen or b.is_star:
            return None
        seen.add(ck)
        t: Optional[Target]
        if b.name is None:                                  # import a.b.c [as x]
            mod = b.module.split(".")[0] if b.bound_top else b.module
            t = self._mod_target(self.mi.resolve(mod, 0, b.file), mod)
        else:                                               # from m import n [as k]
            res = self.mi.resolve(b.module, b.level, b.file)
            if not res.internal:
                written = b.written
                sep = "" if written.endswith(".") else "."
                t = Target("external", modname=f"{written}{sep}{b.name}", how="external",
                           external_kind=res.external_kind)
            else:
                full = f"{b.module}.{b.name}" if b.module else b.name
                sub = self.mi.resolve(full, b.level, b.file, strict=True)
                if sub.internal:
                    t = self._mod_target(sub, full)
                elif res.kind == "file":
                    t = self._find_exported(res.file, b.name, seen)
                    if t is not None:
                        t = t.with_conf(res.confidence, amb=res.ambiguous)
                    else:
                        t = Target("unknown", modname=f"{res.modname}.{b.name}", confidence=CONF_LOW, how="import")
                else:
                    t = Target("unknown", modname=f"{res.modname}.{b.name}", confidence=CONF_LOW, how="import")
        self._bind_cache[ck] = t
        return t

    def _find_exported(self, file: str, name: str, seen: Set) -> Optional[Target]:
        """Símbolo `name` visible en el módulo `file` (definido o re-exportado)."""
        key = ("exp", file, name)
        if key in seen:
            return None
        seen.add(key)
        cands: List[Tuple[int, Target]] = [(s.line, Target("symbol", symbol=s)) for s in self.top[file].get(name, [])]
        ff = self.facts.get(file)
        if ff is not None:
            for b in self.binds.get((file, ff.module_uid), []):
                if b.local == name:
                    t = self.bind_target(b, seen)
                    if t is not None:
                        cands.append((b.line, t))
        if cands:
            best = max(cands, key=lambda c: c[0])[1]
            defs = self.top[file].get(name, [])
            if best.kind == "symbol" and len(defs) > 1 and any(d.conditional for d in defs):
                best = Target("symbol", symbol=best.symbol, confidence=best.confidence, how=best.how,
                              ambiguous=best.ambiguous, alts=[d for d in defs if d.uid != best.symbol.uid])
            return best
        for b in self.stars.get(file, []):
            res = self.mi.resolve(b.module, b.level, file)
            if res.kind == "file":
                t = self._find_exported(res.file, name, seen)
                if t is not None:
                    return t.with_conf(CONF_MEDIUM, "star-import")
        return None

    def dependency_entries(self, file: str):
        """
        Una entrada por dependencia de módulo del archivo (la que muestra la UI):
        [(texto, kind, archivo_resuelto, nombres_importados, binding)]
        kind: file | namespace | external
        """
        out = []
        seen = set()
        ff = self.facts[file]
        for b in sorted(ff.imports, key=lambda x: x.line):
            if b.is_star:
                res = self.mi.resolve(b.module, b.level, file)
                entry, kind, rf, names = b.written, res.kind, res.file, []
            elif b.name is None:
                res = self.mi.resolve(b.module, 0, file)
                entry, kind, rf, names = b.module, res.kind, res.file, []
            else:
                res = self.mi.resolve(b.module, b.level, file)
                full = f"{b.module}.{b.name}" if b.module else b.name
                sub = self.mi.resolve(full, b.level, file, strict=True)
                if sub.internal:
                    sep = "" if b.written.endswith(".") else "."
                    entry, kind, rf, names = f"{b.written}{sep}{b.name}", sub.kind, sub.file, []
                else:
                    entry, kind, rf, names = b.written, res.kind, res.file, [b.name]
            k = (b.line, entry)
            if k in seen:
                for e in out:
                    if (e[4].line, e[0]) == k:
                        e[3].extend(n for n in names if n not in e[3])
                continue
            seen.add(k)
            out.append([entry, kind, rf, list(names), b, res])
        return out

    # ── búsqueda léxica ──────────────────────────────
    def lookup_name(self, file: str, scope_uid: str, name: str) -> Optional[Target]:
        ff = self.facts[file]
        cur: Optional[str] = scope_uid
        while cur and cur != ff.module_uid:
            s = self.sym.get(cur)
            if s is None:
                break
            if s.kind in (KIND_FUNCTION, KIND_METHOD):
                inner = self.members.get(cur, {}).get(name)
                loc = [(c.line, Target("symbol", symbol=c)) for c in (inner or [])]
                for b in self.binds.get((file, cur), []):
                    if b.local == name:
                        t = self.bind_target(b)
                        if t is not None:
                            loc.append((b.line, t))
                if loc:
                    return max(loc, key=lambda c: c[0])[1]
            cur = s.parent                                  # las clases intermedias se saltean
        t = self._find_exported(file, name, set())
        if t is not None:
            return t
        if name in _BUILTINS:
            return Target("external", modname=f"builtins.{name}", how="builtin")
        return None

    # ── clases: bases y miembros ─────────────────────
    def bases_of(self, cls: Symbol) -> List[Target]:
        if cls.uid in self._bases_cache:
            return self._bases_cache[cls.uid]
        self._bases_cache[cls.uid] = []                     # corta ciclos de herencia
        out: List[Target] = []
        for expr in cls.bases:
            toks = expr.split(".")
            t = self.lookup_name(cls.file, cls.parent or "", toks[0])
            if t is not None:
                t = self.follow(t, toks[1:], cls.file)
            out.append(t if t is not None else Target("unknown", modname=expr, confidence=CONF_LOW))
        self._bases_cache[cls.uid] = out
        return out

    def find_member(self, cls: Symbol, name: str, seen: Optional[Set] = None, depth: int = 0):
        """(símbolo, heredado?) buscando en la clase y luego en sus bases, en orden declarado."""
        seen = seen if seen is not None else set()
        if cls.uid in seen:
            return None
        seen.add(cls.uid)
        ms = self.members.get(cls.uid, {}).get(name)
        if ms:
            return ms[-1], depth > 0
        for b in self.bases_of(cls):
            if b.kind == "symbol" and b.symbol.kind == KIND_CLASS:
                r = self.find_member(b.symbol, name, seen, depth + 1)
                if r:
                    return r
        return None

    def attr_type(self, cls: Symbol, attr: str, seen: Optional[Set] = None) -> Optional[Target]:
        """Clase del atributo de instancia `self.attr` (declarado en la clase o heredado)."""
        seen = seen if seen is not None else set()
        if cls.uid in seen:
            return None
        seen.add(cls.uid)
        ff = self.facts.get(cls.file)
        expr = ff.attr_types.get(cls.uid, {}).get(attr) if ff else None
        if expr:
            toks = expr.split(".")
            t = self.lookup_name(cls.file, cls.parent or "", toks[0])
            if t is not None:
                t = self.follow(t, toks[1:], cls.file)
            if t is not None and t.kind == "symbol" and t.symbol.kind == KIND_CLASS:
                return t
        for b in self.bases_of(cls):
            if b.kind == "symbol" and b.symbol.kind == KIND_CLASS:
                r = self.attr_type(b.symbol, attr, seen)
                if r is not None:
                    return r
        return None

    def follow(self, t: Target, rest: List[str], from_file: str) -> Optional[Target]:
        """Recorre `a.b.c` a partir de un destino ya resuelto (módulo -> submódulo/símbolo -> miembro)."""
        for tok in rest:
            if t.kind == "module":
                full = f"{t.modname}.{tok}" if t.modname else tok
                sub = self.mi.resolve(full, 0, from_file, strict=True)
                if sub.internal:
                    t = self._mod_target(sub, full).with_conf(t.confidence, t.how, t.ambiguous)
                    continue
                nxt = self._find_exported(t.file, tok, set()) if t.file else None
                if nxt is None:
                    return None
                t = nxt.with_conf(t.confidence, nxt.how, t.ambiguous)
            elif t.kind == "symbol" and t.symbol.kind == KIND_CLASS:
                m = self.find_member(t.symbol, tok)
                if m is None:
                    return None
                t = Target("symbol", symbol=m[0], confidence=CONF_MEDIUM if m[1] else t.confidence,
                           how="mro" if m[1] else t.how, ambiguous=t.ambiguous)
            elif t.kind == "external":
                t = Target("external", modname=f"{t.modname}.{tok}", confidence=t.confidence,
                           how=t.how, external_kind=t.external_kind)
            else:
                return None
        return t

    # ── contexto de un caller ────────────────────────
    def class_of_scope(self, uid: str) -> Optional[Symbol]:
        cur: Optional[str] = uid
        while cur:
            s = self.sym.get(cur)
            if s is None or s.kind == KIND_MODULE:
                return None
            if s.kind == KIND_METHOD:
                p = self.sym.get(s.parent or "")
                return p if p is not None and p.kind == KIND_CLASS else None
            cur = s.parent
        return None

    def self_name(self, file: str, uid: str) -> Optional[str]:
        ff = self.facts[file]
        cur: Optional[str] = uid
        while cur:
            if cur in ff.self_names:
                return ff.self_names[cur]
            s = self.sym.get(cur)
            cur = s.parent if s is not None else None
        return None

    def local_type(self, file: str, uid: str, var: str) -> Optional[str]:
        ff = self.facts[file]
        cur: Optional[str] = uid
        while cur:
            t = ff.local_types.get(cur, {}).get(var)
            if t:
                return t
            s = self.sym.get(cur)
            cur = s.parent if s is not None else None
        return None

    # ── herencia ─────────────────────────────────────
    def inherit_edges(self) -> List[Edge]:
        out: List[Edge] = []
        for s in self.sym.values():
            if s.kind != KIND_CLASS:
                continue
            for expr, t in zip(s.bases, self.bases_of(s)):
                if t.kind == "symbol" and t.symbol.kind == KIND_CLASS:
                    out.append(Edge(s.uid, t.symbol.uid, REL_INHERITS, s.file, s.line,
                                    confidence=t.confidence, resolved_by=t.how, ambiguous=t.ambiguous, expr=expr))
                else:
                    dst = t.modname if t.kind in ("external", "unknown") and t.modname else expr
                    out.append(Edge(s.uid, f"ext:{dst}", REL_INHERITS, s.file, s.line, confidence=CONF_MEDIUM,
                                    resolved_by="external" if t.kind == "external" else "unresolved",
                                    external=True, expr=expr))
        return out

    # ── llamadas ─────────────────────────────────────
    def resolve_call(self, cs: CallSite) -> List[Edge]:
        base = dict(src=cs.caller, relation=REL_CALLS, file=cs.file, line=cs.line, col=cs.col, expr=cs.expr)
        toks = cs.expr.split(".")
        head, rest = toks[0], toks[1:]
        cls = self.class_of_scope(cs.caller)

        if head == "super()":
            if cls is not None and rest:
                for bt in self.bases_of(cls):
                    if bt.kind == "symbol" and bt.symbol.kind == KIND_CLASS:
                        m = self.find_member(bt.symbol, rest[0])
                        if m:
                            return [Edge(dst=m[0].uid, confidence=CONF_MEDIUM, resolved_by="super", **base)]
                    elif bt.kind == "external":
                        return [Edge(dst=f"ext:{bt.modname}.{rest[0]}", confidence=CONF_MEDIUM,
                                     resolved_by="super", external=True, **base)]
            return [self._ext(base, cs.expr, "unresolved")]

        if head == "?":
            return self._by_method_name(base, rest[-1])

        sn = self.self_name(cs.file, cs.caller)
        if cls is not None and sn is not None and head == sn and rest:
            if len(rest) == 1:
                m = self.find_member(cls, rest[0])
                if m:
                    return [Edge(dst=m[0].uid, confidence=CONF_MEDIUM if m[1] else CONF_HIGH,
                                 resolved_by="mro" if m[1] else "self", **base)]
                return self._by_method_name(base, rest[0])
            at = self.attr_type(cls, rest[0])
            if at is not None:
                fin = self.follow(at, rest[1:], cs.file)
                if fin is not None:
                    return self._edges_for(base, fin.with_conf(CONF_MEDIUM, "attr-type"), cs.expr)
            return self._by_method_name(base, rest[-1])

        if rest:
            ty = self.local_type(cs.file, cs.caller, head)
            if ty:
                ttoks = ty.split(".")
                tt = self.lookup_name(cs.file, cs.caller, ttoks[0])
                if tt is not None:
                    tt = self.follow(tt, ttoks[1:], cs.file)
                if tt is not None and tt.kind == "symbol" and tt.symbol.kind == KIND_CLASS:
                    fin = self.follow(tt, rest, cs.file)
                    if fin is not None:
                        return self._edges_for(base, fin.with_conf(CONF_MEDIUM, "local-type"), cs.expr)

        t = self.lookup_name(cs.file, cs.caller, head)
        if t is None:
            if rest:
                return self._by_method_name(base, rest[-1])
            cands = [s for s in self.defs_by_name.get(head, []) if s.kind in (KIND_FUNCTION, KIND_CLASS)]
            if len(cands) == 1:
                return [Edge(dst=cands[0].uid, confidence=CONF_LOW, resolved_by="name-unique", **base)]
            return [self._ext(base, head, "unresolved")]
        fin = self.follow(t, rest, cs.file)
        if fin is None:
            if t.kind == "module" and not t.ns and rest:
                return [self._ext(base, f"{t.modname}.{'.'.join(rest)}", "module-attr-missing")]
            return self._by_method_name(base, rest[-1]) if rest else [self._ext(base, cs.expr, "unresolved")]
        return self._edges_for(base, fin, cs.expr)

    def _edges_for(self, base: dict, t: Target, expr: str) -> List[Edge]:
        if t.kind == "symbol":
            s = t.symbol
            conf, amb = (_min_conf(t.confidence, CONF_MEDIUM), True) if t.alts else (t.confidence, t.ambiguous)
            edges = [Edge(dst=s.uid, confidence=conf, resolved_by="ctor" if s.kind == KIND_CLASS else t.how,
                          ambiguous=amb, **base)]
            for alt in t.alts:
                edges.append(Edge(dst=alt.uid, confidence=conf, resolved_by="conditional-def", ambiguous=True, **base))
            if s.kind == KIND_CLASS:
                init = self.find_member(s, "__init__")
                if init:
                    edges.append(Edge(dst=init[0].uid, confidence=_min_conf(t.confidence, CONF_MEDIUM),
                                      resolved_by="ctor-init", ambiguous=t.ambiguous, **base))
            return edges
        if t.kind == "external":
            return [Edge(dst=f"ext:{t.modname}", confidence=t.confidence, resolved_by=t.how or "external",
                         external=True, **base)]
        return [self._ext(base, t.modname or expr, "unresolved")]

    @staticmethod
    def _ext(base: dict, name: str, how: str) -> Edge:
        return Edge(dst=f"ext:{name}", confidence=CONF_LOW, resolved_by=how, external=True, **base)

    def _by_method_name(self, base: dict, name: str) -> List[Edge]:
        cands = self.methods_by_name.get(name, [])
        if len(cands) == 1:
            return [Edge(dst=cands[0].uid, confidence=CONF_LOW, resolved_by="name-unique", **base)]
        if 1 < len(cands) <= MAX_FANOUT:
            return [Edge(dst=c.uid, confidence=CONF_LOW, resolved_by="name-fanout", ambiguous=True, **base)
                    for c in sorted(cands, key=lambda c: (c.file, c.line))]
        return [Edge(dst=f"ext:*.{name}", confidence=CONF_LOW, resolved_by="unresolved", external=True, **base)]
