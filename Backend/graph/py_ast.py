"""
Extractor de hechos Python basado en el módulo `ast` de la stdlib.

A diferencia del análisis histórico (`ast.walk` plano), recorre el árbol con un
stack de scopes, de modo que cada símbolo tiene `qualname` y cada llamada se
atribuye a la función INNERMOST que la contiene (o al módulo si está a nivel
de módulo). Nunca importa ni ejecuta el código analizado: solo `ast.parse`.
"""

from __future__ import annotations
import ast
from collections import defaultdict
from typing import Dict, List, Optional

from .model import (
    FileFacts, Symbol, ImportBinding, CallSite, make_uid, module_uid,
    KIND_MODULE, KIND_CLASS, KIND_FUNCTION, KIND_METHOD,
)
from .positions import split_lines, byte_col_to_utf16, line_bytes_at

_FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)


def _dotted_decorator(d: ast.AST) -> Optional[str]:
    """Nombre dotted de un decorador (`app.route`), ignorando argumentos."""
    if isinstance(d, ast.Call):
        d = d.func
    parts = []
    while isinstance(d, ast.Attribute):
        parts.append(d.attr)
        d = d.value
    if isinstance(d, ast.Name):
        parts.append(d.id)
        return ".".join(reversed(parts))
    return None


def _type_expr(ann: Optional[ast.AST]) -> Optional[str]:
    """Expresión de clase a partir de una anotación simple (`X`, `m.X`, `"X"`, `Optional[X]`, `X | None`)."""
    if ann is None:
        return None
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        txt = ann.value.strip().strip("'\"")
        return txt if txt.replace(".", "").replace("_", "").isalnum() else None
    if isinstance(ann, (ast.Name, ast.Attribute)):
        return _plain_dotted(ann)
    if isinstance(ann, ast.Subscript):
        base = _plain_dotted(ann.value)
        if base and base.split(".")[-1] in ("Optional", "Final", "ClassVar"):
            return _type_expr(ann.slice)
        return None
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
        for side in (ann.left, ann.right):
            if isinstance(side, ast.Constant) and side.value is None:
                continue
            return _type_expr(side)
    return None


def _plain_dotted(n: ast.AST) -> Optional[str]:
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return None


class AstExtractor:
    backend = "ast"

    def extract(self, file: str, source: str, modname: str, is_pkg: bool) -> FileFacts:
        facts = FileFacts(file=file, module=modname, is_package=is_pkg,
                          module_uid=module_uid(file), backend="ast")
        tree = ast.parse(source, filename=file)          # SyntaxError lo maneja el llamador
        _Walker(facts, split_lines(source)).run(tree)
        return facts


class _Walker:
    def __init__(self, facts: FileFacts, lines: List[bytes]):
        self.f = facts
        self.lines = lines
        self.scope: List[tuple] = [(facts.module_uid, KIND_MODULE, "")]   # (uid, kind, qualname)
        self.seen: Dict[tuple, int] = defaultdict(int)
        self.by_uid: Dict[str, Symbol] = {}
        self._cond = 0                       # >0 dentro de if/try/match del scope actual

    # ── helpers ──────────────────────────────────────
    def _col(self, line1: int, byte_col: int) -> int:
        return byte_col_to_utf16(line_bytes_at(self.lines, line1), byte_col)

    def _exec_scope(self) -> str:
        """Scope que ejecuta el código: función o módulo (los cuerpos de clase se atribuyen al contenedor)."""
        for uid, kind, _ in reversed(self.scope):
            if kind != KIND_CLASS:
                return uid
        return self.f.module_uid

    def _enclosing_class(self) -> Optional[str]:
        uid, kind, _ = self.scope[-1]
        return uid if kind == KIND_CLASS else None

    def _name_pos(self, node, name: str):
        """Posición del identificador de un def/class (después de la keyword)."""
        line = node.lineno
        raw = line_bytes_at(self.lines, line)
        idx = raw.find(name.encode("utf-8"), node.col_offset)
        if idx < 0:
            idx = node.col_offset
        return line, self._col(line, idx)

    # ── entrada ──────────────────────────────────────
    def run(self, tree: ast.Module):
        f = self.f
        f.symbols.append(Symbol(
            uid=f.module_uid, kind=KIND_MODULE, name=f.module.split(".")[-1] or f.file,
            qualname="", file=f.file, module=f.module, line=1,
            end_line=max(1, len(self.lines)), sources=["ast"]))
        for stmt in tree.body:
            self.visit(stmt)

    # ── dispatch ─────────────────────────────────────
    def visit(self, node: ast.AST):
        m = getattr(self, "visit_" + type(node).__name__, None)
        if m:
            m(node)
        else:
            for child in ast.iter_child_nodes(node):
                self.visit(child)

    def _visit_all(self, nodes):
        for n in nodes:
            if n is not None:
                self.visit(n)

    # ── definiciones ─────────────────────────────────
    def _define(self, node, kind: str, name: str) -> Symbol:
        parent_uid, _, parent_q = self.scope[-1]
        qual = f"{parent_q}.{name}" if parent_q else name
        key = (parent_uid, name)
        self.seen[key] += 1
        nl, nc = self._name_pos(node, name)
        sym = Symbol(
            uid=make_uid(self.f.file, qual, self.seen[key]), kind=kind, name=name,
            qualname=qual, file=self.f.file, module=self.f.module,
            line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
            col=self._col(node.lineno, node.col_offset), name_line=nl, name_col=nc,
            parent=parent_uid, sources=["ast"], conditional=self._cond > 0,
            decorators=[d for d in map(_dotted_decorator, getattr(node, "decorator_list", [])) if d],
        )
        self.f.symbols.append(sym)
        self.by_uid[sym.uid] = sym
        return sym

    def visit_ClassDef(self, node: ast.ClassDef):
        # decoradores, bases y keywords se evalúan en el scope contenedor
        self._visit_all(node.decorator_list)
        self._visit_all(node.bases)
        self._visit_all(k.value for k in node.keywords)
        sym = self._define(node, KIND_CLASS, node.name)
        sym.bases = [b for b in map(_plain_dotted, node.bases) if b]
        self.scope.append((sym.uid, KIND_CLASS, sym.qualname))
        saved, self._cond = self._cond, 0
        self._visit_all(node.body)
        self._cond = saved
        self.scope.pop()

    def _visit_function(self, node):
        # decoradores, defaults y anotaciones: scope contenedor
        self._visit_all(node.decorator_list)
        a = node.args
        self._visit_all(a.defaults)
        self._visit_all(d for d in a.kw_defaults if d is not None)
        in_class = self._enclosing_class() is not None
        kind = KIND_METHOD if in_class else KIND_FUNCTION
        sym = self._define(node, kind, node.name)
        sym.is_async = isinstance(node, ast.AsyncFunctionDef)

        params = list(a.posonlyargs) + list(a.args)
        is_static = "staticmethod" in {d.split(".")[-1] for d in sym.decorators}
        if kind == KIND_METHOD and params and not is_static:
            self.f.self_names[sym.uid] = params[0].arg
        types = self.f.local_types.setdefault(sym.uid, {})
        for p in params + list(a.kwonlyargs):
            t = _type_expr(p.annotation)
            if t:
                types[p.arg] = t
        if not types:
            self.f.local_types.pop(sym.uid, None)

        self.scope.append((sym.uid, kind, sym.qualname))
        saved, self._cond = self._cond, 0
        self._visit_all(node.body)
        self._cond = saved
        self.scope.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _visit_cond(self, node):
        self._cond += 1
        for child in ast.iter_child_nodes(node):
            self.visit(child)
        self._cond -= 1

    visit_If = visit_Try = visit_Match = _visit_cond
    visit_TryStar = _visit_cond

    # ── imports ──────────────────────────────────────
    def visit_Import(self, node: ast.Import):
        scope = self._exec_scope()
        for al in node.names:
            if al.asname:
                self.f.imports.append(ImportBinding(self.f.file, node.lineno, scope, al.asname, al.name))
            else:
                top = al.name.split(".")[0]
                self.f.imports.append(ImportBinding(self.f.file, node.lineno, scope, top, al.name,
                                                    bound_top="." in al.name))

    def visit_ImportFrom(self, node: ast.ImportFrom):
        scope = self._exec_scope()
        mod = node.module or ""
        for al in node.names:
            if al.name == "*":
                self.f.imports.append(ImportBinding(self.f.file, node.lineno, scope, "*", mod,
                                                    level=node.level, is_star=True))
            else:
                self.f.imports.append(ImportBinding(self.f.file, node.lineno, scope, al.asname or al.name,
                                                    mod, level=node.level, name=al.name))

    # ── asignaciones: inferencia de tipo local ───────
    def _record_type(self, target: ast.AST, type_expr: Optional[str]):
        if not type_expr:
            return
        cls_body = self._enclosing_class()
        if cls_body and isinstance(target, ast.Name):
            # `x: Handler` / `x = Handler()` en el cuerpo de una clase es un atributo de la clase
            self.f.attr_types.setdefault(cls_body, {})[target.id] = type_expr
            return
        scope = self._exec_scope()
        if isinstance(target, ast.Name):
            self.f.local_types.setdefault(scope, {})[target.id] = type_expr
        elif (isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
              and self.f.self_names.get(scope) == target.value.id):
            cls_uid = self._class_of(scope)
            if cls_uid:
                self.f.attr_types.setdefault(cls_uid, {})[target.attr] = type_expr

    def _class_of(self, func_uid: str) -> Optional[str]:
        s = self.by_uid.get(func_uid)
        return s.parent if s is not None and s.kind == KIND_METHOD else None

    @staticmethod
    def _call_type(value: ast.AST) -> Optional[str]:
        if isinstance(value, ast.Call):
            return _plain_dotted(value.func)
        return None

    def visit_Assign(self, node: ast.Assign):
        self.visit(node.value)
        t = self._call_type(node.value)
        for tgt in node.targets:
            self._record_type(tgt, t)
            self.visit(tgt)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self.visit(node.value)
        declared = _type_expr(node.annotation)
        inferred = self._call_type(node.value) if node.value is not None else None
        self._record_type(node.target, declared or inferred)
        self.visit(node.target)

    def visit_With(self, node: ast.With):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._record_type(item.optional_vars, self._call_type(item.context_expr))
                self.visit(item.optional_vars)
        self._visit_all(node.body)

    visit_AsyncWith = visit_With

    # ── llamadas ─────────────────────────────────────
    def visit_Call(self, node: ast.Call):
        expr, nl, nc = self._callee(node.func)
        if expr:
            self.f.calls.append(CallSite(
                file=self.f.file, line=node.lineno, col=self._col(node.lineno, node.col_offset),
                name_line=nl, name_col=nc, caller=self._exec_scope(), expr=expr))
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def _callee(self, fn: ast.AST):
        """(expresión, línea, columna UTF-16) del identificador final del callee."""
        if isinstance(fn, ast.Name):
            return fn.id, fn.lineno, self._col(fn.lineno, fn.col_offset)
        if isinstance(fn, ast.Attribute):
            base = self._base(fn.value)
            line = getattr(fn, "end_lineno", fn.lineno) or fn.lineno
            endc = getattr(fn, "end_col_offset", fn.col_offset) or fn.col_offset
            col = self._col(line, max(0, endc - len(fn.attr.encode("utf-8"))))
            return (f"{base}.{fn.attr}" if base else f"?.{fn.attr}"), line, col
        return None, 0, 0

    def _base(self, n: ast.AST) -> Optional[str]:
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            b = self._base(n.value)
            return f"{b}.{n.attr}" if b else None
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "super" and not n.args):
            return "super()"
        return None
