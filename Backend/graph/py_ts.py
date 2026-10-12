"""
Extractor de hechos Python basado en tree-sitter (py-tree-sitter + tree-sitter-python).

Produce el mismo `FileFacts` que `AstExtractor`, pero tolera errores de sintaxis
(sintaxis Python 2, archivos truncados, merges a medio resolver): los nodos ERROR
se recorren igual y los símbolos válidos se recuperan. Solo parsea; no ejecuta.

Dependencia OPCIONAL: si `tree_sitter`/`tree_sitter_python` no están instalados,
`available()` devuelve False y el motor sigue con `ast`.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Dict, List, Optional

from .model import (
    FileFacts, Symbol, ImportBinding, CallSite, make_uid, module_uid,
    KIND_MODULE, KIND_CLASS, KIND_FUNCTION, KIND_METHOD,
)
from .positions import split_lines, byte_col_to_utf16, line_bytes_at

try:                                        # pragma: no cover - depende del entorno
    import tree_sitter_python as _tsp
    from tree_sitter import Language as _Language, Parser as _Parser
    _LANG = _Language(_tsp.language())
    _IMPORT_ERROR = None
except Exception as _e:                     # ImportError, ABI mismatch, etc.
    _tsp = _Language = _Parser = _LANG = None
    _IMPORT_ERROR = repr(_e)


def available() -> bool:
    return _LANG is not None


def version_info() -> dict:
    if not available():
        return {"available": False, "error": _IMPORT_ERROR}
    try:
        from importlib.metadata import version
        return {"available": True, "tree_sitter": version("tree-sitter"),
                "tree_sitter_python": version("tree-sitter-python")}
    except Exception:
        return {"available": True}


class TreeSitterExtractor:
    backend = "tree-sitter"

    def __init__(self):
        if not available():
            raise RuntimeError(f"tree-sitter no disponible: {_IMPORT_ERROR}")
        self._parser = _Parser(_LANG)

    def __call__(self, file: str, source: str, modname: str, is_pkg: bool) -> FileFacts:
        return self.extract(file, source, modname, is_pkg)

    def extract(self, file: str, source: str, modname: str, is_pkg: bool) -> FileFacts:
        data = source.encode("utf-8", "surrogatepass")
        tree = self._parser.parse(data)
        facts = FileFacts(file=file, module=modname, is_package=is_pkg,
                          module_uid=module_uid(file), backend="tree-sitter")
        w = _TSWalker(facts, split_lines(source), data)
        w.run(tree.root_node)
        facts.parse_errors = w.errors
        return facts


_COND_NODES = frozenset({"if_statement", "elif_clause", "else_clause", "try_statement", "except_clause",
                         "except_group_clause", "finally_clause", "match_statement", "case_clause"})
_SCOPE_NODES = frozenset({"function_definition", "class_definition", "module"})


def _is_conditional(n) -> bool:
    p = n.parent
    while p is not None and p.type not in _SCOPE_NODES:
        if p.type in _COND_NODES:
            return True
        p = p.parent
    return False


class _TSWalker:
    def __init__(self, facts: FileFacts, lines: List[bytes], data: bytes):
        self.f = facts
        self.lines = lines
        self.data = data
        self.scope: List[tuple] = [(facts.module_uid, KIND_MODULE, "")]
        self.seen: Dict[tuple, int] = defaultdict(int)
        self.by_uid: Dict[str, Symbol] = {}
        self.errors = 0

    # ── helpers ──────────────────────────────────────
    def _txt(self, n) -> str:
        return self.data[n.start_byte:n.end_byte].decode("utf-8", "replace")

    def _col(self, row0: int, bcol: int) -> int:
        return byte_col_to_utf16(line_bytes_at(self.lines, row0 + 1), bcol)

    def _exec_scope(self) -> str:
        for uid, kind, _ in reversed(self.scope):
            if kind != KIND_CLASS:
                return uid
        return self.f.module_uid

    def _enclosing_class(self) -> Optional[str]:
        uid, kind, _ = self.scope[-1]
        return uid if kind == KIND_CLASS else None

    def _dotted(self, n) -> Optional[str]:
        if n is None:
            return None
        if n.type == "identifier":
            return self._txt(n)
        if n.type == "attribute":
            o = self._dotted(n.child_by_field_name("object"))
            a = n.child_by_field_name("attribute")
            return f"{o}.{self._txt(a)}" if o and a is not None else None
        return None

    # ── entrada ──────────────────────────────────────
    def run(self, root):
        f = self.f
        f.symbols.append(Symbol(
            uid=f.module_uid, kind=KIND_MODULE, name=f.module.split(".")[-1] or f.file, qualname="",
            file=f.file, module=f.module, line=1, end_line=max(1, len(self.lines)), sources=["tree-sitter"]))
        for ch in root.children:
            self.visit(ch)

    def visit(self, n):
        t = n.type
        m = getattr(self, "v_" + t, None)
        if m is not None:
            m(n)
            return
        if t == "ERROR" or n.is_missing:
            self.errors += 1
        for ch in n.children:
            self.visit(ch)

    # ── definiciones ─────────────────────────────────
    def _define(self, n, kind: str, name_node, decorators: List[str], start_node=None) -> Symbol:
        name = self._txt(name_node)
        parent_uid, _, parent_q = self.scope[-1]
        qual = f"{parent_q}.{name}" if parent_q else name
        self.seen[(parent_uid, name)] += 1
        s0 = start_node or n
        nrow, ncol = name_node.start_point
        sym = Symbol(
            uid=make_uid(self.f.file, qual, self.seen[(parent_uid, name)]), kind=kind, name=name,
            qualname=qual, file=self.f.file, module=self.f.module,
            line=s0.start_point[0] + 1, end_line=n.end_point[0] + 1,
            col=self._col(s0.start_point[0], s0.start_point[1]),
            name_line=nrow + 1, name_col=self._col(nrow, ncol),
            parent=parent_uid, decorators=decorators, sources=["tree-sitter"], conditional=_is_conditional(n))
        self.f.symbols.append(sym)
        self.by_uid[sym.uid] = sym
        return sym

    def v_decorated_definition(self, n):
        decs = []
        for ch in n.children:
            if ch.type == "decorator":
                expr = next((c for c in ch.children if c.is_named), None)
                target = expr.child_by_field_name("function") if expr is not None and expr.type == "call" else expr
                d = self._dotted(target)
                if d:
                    decs.append(d)
                self.visit(ch)
        definition = n.child_by_field_name("definition")
        if definition is not None:
            self._pending_decs = decs                    # `Symbol.line` es la del `def`/`class`, igual que `ast` >= 3.8
            self.visit(definition)

    def v_class_definition(self, n):
        decs = getattr(self, "_pending_decs", [])
        self._pending_decs = []
        name = n.child_by_field_name("name")
        if name is None:
            self.errors += 1
            return
        sup = n.child_by_field_name("superclasses")
        bases: List[str] = []
        if sup is not None:
            for a in sup.children:
                if a.type in ("identifier", "attribute"):
                    d = self._dotted(a)
                    if d:
                        bases.append(d)
                elif a.is_named:
                    self.visit(a)
        sym = self._define(n, KIND_CLASS, name, decs)
        sym.bases = bases
        self.scope.append((sym.uid, KIND_CLASS, sym.qualname))
        body = n.child_by_field_name("body")
        if body is not None:
            for ch in body.children:
                self.visit(ch)
        self.scope.pop()

    def _param_names(self, params):
        """(nombre, anotación|None) de cada parámetro posicional/keyword, en orden."""
        out = []
        if params is None:
            return out
        for p in params.children:
            if p.type == "identifier":
                out.append((self._txt(p), None))
            elif p.type == "typed_parameter":
                ident = next((c for c in p.children if c.type == "identifier"), None)
                ann = p.child_by_field_name("type")
                if ident is not None:
                    out.append((self._txt(ident), self._ann(ann)))
            elif p.type in ("default_parameter", "typed_default_parameter"):
                nm = p.child_by_field_name("name")
                ann = p.child_by_field_name("type")
                if nm is not None and nm.type == "identifier":
                    out.append((self._txt(nm), self._ann(ann)))
                dv = p.child_by_field_name("value")
                if dv is not None:
                    self.visit(dv)
        return out

    def _ann(self, t) -> Optional[str]:
        """Anotación simple -> expresión de clase (mismas reglas que el backend ast)."""
        if t is None:
            return None
        inner = t.children[0] if t.type == "type" and t.children else t
        if inner.type in ("identifier", "attribute"):
            return self._dotted(inner)
        if inner.type == "string":
            s = self._txt(inner).strip("'\"").strip()
            return s if s.replace(".", "").replace("_", "").isalnum() else None
        if inner.type == "generic_type":
            base = self._dotted(inner.children[0]) if inner.children else None
            if base and base.split(".")[-1] in ("Optional", "Final", "ClassVar"):
                tp = next((c for c in inner.children if c.type == "type_parameter"), None)
                first = next((c for c in tp.children if c.type == "type"), None) if tp is not None else None
                return self._ann(first)
        if inner.type == "binary_operator":
            for side in (inner.child_by_field_name("left"), inner.child_by_field_name("right")):
                if side is not None and self._txt(side) != "None":
                    return self._ann(side)
        return None

    def v_function_definition(self, n):
        decs = getattr(self, "_pending_decs", [])
        self._pending_decs = []
        name = n.child_by_field_name("name")
        if name is None:
            self.errors += 1
            return
        in_class = self._enclosing_class() is not None
        kind = KIND_METHOD if in_class else KIND_FUNCTION
        sym = self._define(n, kind, name, decs)
        sym.is_async = any(c.type == "async" for c in n.children)
        params = self._param_names(n.child_by_field_name("parameters"))
        if kind == KIND_METHOD and params and "staticmethod" not in {d.split(".")[-1] for d in decs}:
            self.f.self_names[sym.uid] = params[0][0]
        types = {nm: ann for nm, ann in params if ann}
        if types:
            self.f.local_types[sym.uid] = types
        self.scope.append((sym.uid, kind, sym.qualname))
        body = n.child_by_field_name("body")
        if body is not None:
            for ch in body.children:
                self.visit(ch)
        self.scope.pop()

    # ── imports ──────────────────────────────────────
    def v_import_statement(self, n):
        scope, line = self._exec_scope(), n.start_point[0] + 1
        for ch in n.children_by_field_name("name"):
            if ch.type == "aliased_import":
                nm, al = ch.child_by_field_name("name"), ch.child_by_field_name("alias")
                if nm is not None and al is not None:
                    self.f.imports.append(ImportBinding(self.f.file, line, scope, self._txt(al), self._txt(nm)))
            else:
                full = self._txt(ch)
                self.f.imports.append(ImportBinding(self.f.file, line, scope, full.split(".")[0], full,
                                                    bound_top="." in full))

    def v_import_from_statement(self, n):
        scope, line = self._exec_scope(), n.start_point[0] + 1
        mod = n.child_by_field_name("module_name")
        level, dotted = 0, ""
        if mod is not None:
            if mod.type == "relative_import":
                for c in mod.children:
                    if c.type == "import_prefix":
                        level = self._txt(c).count(".")
                    elif c.type == "dotted_name":
                        dotted = self._txt(c)
            else:
                dotted = self._txt(mod)
        if any(c.type == "wildcard_import" for c in n.children):
            self.f.imports.append(ImportBinding(self.f.file, line, scope, "*", dotted, level=level, is_star=True))
            return
        for ch in n.children_by_field_name("name"):
            if ch.type == "aliased_import":
                nm, al = ch.child_by_field_name("name"), ch.child_by_field_name("alias")
                if nm is not None and al is not None:
                    self.f.imports.append(ImportBinding(self.f.file, line, scope, self._txt(al), dotted,
                                                        level=level, name=self._txt(nm)))
            else:
                nm = self._txt(ch)
                self.f.imports.append(ImportBinding(self.f.file, line, scope, nm, dotted, level=level, name=nm))

    def v_future_import_statement(self, n):
        scope, line = self._exec_scope(), n.start_point[0] + 1
        for ch in n.children_by_field_name("name"):
            nm = self._txt(ch.child_by_field_name("name")) if ch.type == "aliased_import" else self._txt(ch)
            al = ch.child_by_field_name("alias") if ch.type == "aliased_import" else None
            self.f.imports.append(ImportBinding(self.f.file, line, scope, self._txt(al) if al is not None else nm,
                                                "__future__", name=nm))

    def v_type_alias_statement(self, n):
        """
        tree-sitter-python trata `type(x).attr = v` como `type X = v` (soft keyword `type`).
        Si el texto empieza con `type(`, es una llamada a `type`, no un alias.
        """
        raw = self._txt(n)
        if raw.lstrip().startswith("type") and raw.lstrip()[4:].lstrip().startswith("("):
            row, col = n.start_point
            self.f.calls.append(CallSite(
                file=self.f.file, line=row + 1, col=self._col(row, col), name_line=row + 1,
                name_col=self._col(row, col), caller=self._exec_scope(), expr="type"))
        for ch in n.children:
            self.visit(ch)

    # ── asignaciones / with: inferencia de tipo local ─
    def _call_type(self, v) -> Optional[str]:
        if v is not None and v.type == "call":
            return self._dotted(v.child_by_field_name("function"))
        return None

    def _record_type(self, target, type_expr: Optional[str]):
        if not type_expr or target is None:
            return
        cls_body = self._enclosing_class()
        if cls_body and target.type == "identifier":
            self.f.attr_types.setdefault(cls_body, {})[self._txt(target)] = type_expr
            return
        scope = self._exec_scope()
        if target.type == "identifier":
            self.f.local_types.setdefault(scope, {})[self._txt(target)] = type_expr
        elif target.type == "attribute":
            obj, attr = target.child_by_field_name("object"), target.child_by_field_name("attribute")
            if obj is not None and obj.type == "identifier" and attr is not None \
                    and self.f.self_names.get(scope) == self._txt(obj):
                sym = self.by_uid.get(scope)
                if sym is not None and sym.kind == KIND_METHOD and sym.parent:
                    self.f.attr_types.setdefault(sym.parent, {})[self._txt(attr)] = type_expr

    def v_assignment(self, n):
        left, right, ann = n.child_by_field_name("left"), n.child_by_field_name("right"), n.child_by_field_name("type")
        if right is not None:
            self.visit(right)
        self._record_type(left, self._ann(ann) or self._call_type(right))
        if left is not None and left.type != "identifier":
            self.visit(left)

    def v_with_item(self, n):
        val = n.child_by_field_name("value")
        if val is not None and val.type == "as_pattern":
            expr = next((c for c in val.children if c.is_named and c.type != "as_pattern_target"), None)
            tgt = val.child_by_field_name("alias")
            tgt = tgt.children[0] if tgt is not None and tgt.children else tgt
            self._record_type(tgt, self._call_type(expr))
        for ch in n.children:
            self.visit(ch)

    # ── llamadas ─────────────────────────────────────
    def v_call(self, n):
        fn = n.child_by_field_name("function")
        expr = None
        nrow = ncol = 0
        if fn is not None and fn.type == "identifier":
            expr, (nrow, ncol) = self._txt(fn), fn.start_point
        elif fn is not None and fn.type == "attribute":
            attr = fn.child_by_field_name("attribute")
            obj = fn.child_by_field_name("object")
            base = self._base(obj)
            if attr is not None:
                expr = f"{base}.{self._txt(attr)}" if base else f"?.{self._txt(attr)}"
                nrow, ncol = attr.start_point
        if expr:
            self.f.calls.append(CallSite(
                file=self.f.file, line=n.start_point[0] + 1, col=self._col(*n.start_point),
                name_line=nrow + 1, name_col=self._col(nrow, ncol), caller=self._exec_scope(), expr=expr))
        for ch in n.children:
            self.visit(ch)

    def _base(self, n) -> Optional[str]:
        if n is None:
            return None
        if n.type == "identifier":
            return self._txt(n)
        if n.type == "attribute":
            o = self._base(n.child_by_field_name("object"))
            a = n.child_by_field_name("attribute")
            return f"{o}.{self._txt(a)}" if o and a is not None else None
        if n.type == "call":
            f = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            if f is not None and f.type == "identifier" and self._txt(f) == "super" \
                    and (args is None or not any(c.is_named for c in args.children)):
                return "super()"
        return None
