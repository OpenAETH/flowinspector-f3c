"""
Flow Inspector v4 — Instrumenter  (Fase 4)
============================================
Motor completo de instrumentación automática sin tocar el disco del usuario.

Estrategias disponibles:
  1. InMemoryInstrumenter   — reescribe fuente en memoria, devuelve código listo
  2. ImportHook             — sys.meta_path hook: instrumenta al importar (Python ≥ 3.4)
  3. ZipInstrumenter        — recibe un .zip, devuelve un .zip instrumentado
  4. DependencyOrderedInstrumenter — instrumenta en orden topológico de imports
  5. DiffInstrumenter       — instrumenta solo los archivos cambiados (git diff)

El código generado:
  - Es legible y formateado correctamente (ast.unparse + black si disponible)
  - Preserva type hints, docstrings y decoradores existentes
  - Inyecta configure() automático con flow_id y endpoint correctos
  - Incluye un bloque try/except para que si flowinspector_track no está instalado,
    el código funcione igual sin instrumentación (graceful degradation)
"""

from __future__ import annotations
import ast, importlib, importlib.abc, importlib.machinery, importlib.util
import io, os, sys, zipfile, textwrap, hashlib
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════

GUARD_IMPORT = textwrap.dedent("""\
    # ── FlowInspector auto-instrumentation ──
    try:
        from flowinspector_track import track_flow as _track_flow, configure as _fi_configure
        _fi_configure(flow_id={flow_id!r}, endpoint={endpoint!r})
    except ImportError:
        def _track_flow(fn=None, **kw):
            return fn if fn is not None else (lambda f: f)
    # ────────────────────────────────────────
""")

DECO_NAME = "_track_flow"   # Fase 4 uses a private alias to avoid name collisions


def _format_source(source: str) -> str:
    """Try black, fall back to raw."""
    try:
        import black
        return black.format_str(source, mode=black.Mode())
    except Exception:
        return source


def _file_hash(content: str) -> str:
    return hashlib.md5(content.encode()).hexdigest()[:8]


# ═══════════════════════════════════════════════════════════
# AST Transformer v2  (extended for Fase 4)
# ═══════════════════════════════════════════════════════════

class _Transformer(ast.NodeTransformer):
    """
    AST transformer with configurable rules.

    skip_patterns  — list of glob-style prefixes to skip (e.g. ["test_", "__"])
    min_body_lines — skip functions shorter than N non-pass lines
    instrument_lambdas — wrap lambda bodies (experimental)
    """

    def __init__(
        self,
        deco_name:        str  = DECO_NAME,
        skip_patterns:    List[str] = None,
        min_body_lines:   int  = 2,
        track_returns:    bool = True,
    ):
        self.deco_name      = deco_name
        self.skip_patterns  = skip_patterns or ["__"]
        self.min_body_lines = min_body_lines
        self.track_returns  = track_returns
        self._modified_count = 0

    def _has_deco(self, node) -> bool:
        for d in node.decorator_list:
            name = (d.id if isinstance(d, ast.Name) else
                    d.func.id if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) else None)
            if name in (self.deco_name, "track_flow"):
                return True
        return False

    def _should_skip(self, node) -> bool:
        nm = node.name
        for pat in self.skip_patterns:
            if nm.startswith(pat):
                # Keep __init__ and __call__
                if nm in ("__init__", "__call__"):
                    return False
                return True
        # Skip trivial 1-liners (getters, pass, ellipsis)
        non_trivial = [
            s for s in node.body
            if not isinstance(s, (ast.Pass, ast.Expr))
            or (isinstance(s, ast.Expr) and not isinstance(s.value, (ast.Constant, ast.Ellipsis)))
        ]
        if len(non_trivial) < self.min_body_lines:
            return True
        return False

    def _make_deco(self) -> ast.expr:
        return ast.Name(id=self.deco_name, ctx=ast.Load())

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if not self._has_deco(node) and not self._should_skip(node):
            node.decorator_list.insert(0, self._make_deco())
            self._modified_count += 1
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    @property
    def modified_count(self) -> int:
        return self._modified_count


# ═══════════════════════════════════════════════════════════
# InMemoryInstrumenter
# ═══════════════════════════════════════════════════════════

class InMemoryInstrumenter:
    """
    Instrumenta código Python en memoria.
    Input:  source str
    Output: (instrumented_source str, stats dict)

    stats = {
        "functions_instrumented": int,
        "functions_skipped":      int,
        "parse_error":            bool,
        "source_hash":            str,
    }
    """

    def __init__(
        self,
        flow_id:   str = "default",
        endpoint:  str = "http://localhost:10000/flow-events/batch",
        deco_name: str = DECO_NAME,
        skip_patterns: List[str] = None,
        min_body_lines: int = 2,
        format_output: bool = False,
    ):
        self.flow_id        = flow_id
        self.endpoint       = endpoint
        self.deco_name      = deco_name
        self.skip_patterns  = skip_patterns or ["__"]
        self.min_body_lines = min_body_lines
        self.format_output  = format_output

    def instrument(self, source: str, filename: str = "<unknown>") -> Tuple[str, dict]:
        stats = {
            "functions_instrumented": 0,
            "functions_skipped":      0,
            "parse_error":            False,
            "source_hash":            _file_hash(source),
            "filename":               filename,
        }

        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            stats["parse_error"] = True
            stats["parse_error_msg"] = str(e)
            return source, stats

        # Count total functions before transform
        total_fns = sum(
            1 for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        )

        transformer = _Transformer(
            deco_name      = self.deco_name,
            skip_patterns  = self.skip_patterns,
            min_body_lines = self.min_body_lines,
        )
        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)

        stats["functions_instrumented"] = transformer.modified_count
        stats["functions_skipped"]      = total_fns - transformer.modified_count

        try:
            result = ast.unparse(new_tree)
        except AttributeError:
            stats["parse_error"]     = True
            stats["parse_error_msg"] = "ast.unparse requires Python 3.9+"
            return source, stats

        # Prepend guard import
        guard = GUARD_IMPORT.format(flow_id=self.flow_id, endpoint=self.endpoint)
        result = guard + "\n" + result

        if self.format_output:
            result = _format_source(result)

        return result, stats

    def instrument_files(self, files: Dict[str, str]) -> Dict[str, dict]:
        """
        Instrumenta múltiples archivos. Respeta orden topológico de imports.
        Returns: {filepath: {"source": str, "stats": dict}}
        """
        ordered = _topological_sort(files)
        results = {}
        for fp in ordered:
            src = files[fp]
            instrumented, stats = self.instrument(src, filename=fp)
            results[fp] = {"source": instrumented, "stats": stats}
        return results


# ═══════════════════════════════════════════════════════════
# Topological sort by import order
# ═══════════════════════════════════════════════════════════

def _topological_sort(files: Dict[str, str]) -> List[str]:
    """
    Ordena archivos en orden de dependencia (los que no dependen de nada, primero).
    Garantiza que si A importa B, B aparece antes de A en la lista.
    Usa DFS con detección de ciclos (rompe ciclos arbitrariamente).
    """
    base_map = {os.path.basename(fp).replace(".py", ""): fp for fp in files}
    deps: Dict[str, List[str]] = {fp: [] for fp in files}

    for fp, src in files.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in base_map:
                        deps[fp].append(base_map[alias.name])
            elif isinstance(node, ast.ImportFrom) and node.module:
                target = base_map.get(node.module) or base_map.get(node.module.split(".")[-1])
                if target:
                    deps[fp].append(target)

    visited: set = set()
    order:   List[str] = []

    def dfs(fp, stack=None):
        stack = stack or set()
        if fp in stack:
            return  # cycle — skip
        if fp in visited:
            return
        stack.add(fp)
        for dep in deps.get(fp, []):
            dfs(dep, stack)
        visited.add(fp)
        order.append(fp)

    for fp in files:
        dfs(fp)

    return order


# ═══════════════════════════════════════════════════════════
# ImportHook — instruments at import time
# ═══════════════════════════════════════════════════════════

class FlowImportHook(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """
    sys.meta_path hook: intercepts module imports and instruments
    them on the fly, without touching the source files.

    Usage:
        hook = FlowImportHook(
            flow_id  = "my-project",
            endpoint = "http://localhost:10000/flow-events/batch",
            packages = ["myapp"],   # only instrument these packages
        )
        hook.install()
        import myapp   # instrumented transparently
        hook.uninstall()
    """

    def __init__(
        self,
        flow_id:   str       = "default",
        endpoint:  str       = "http://localhost:10000/flow-events/batch",
        packages:  List[str] = None,
        exclude:   List[str] = None,
    ):
        self.flow_id   = flow_id
        self.endpoint  = endpoint
        self.packages  = packages or []
        self.exclude   = exclude or ["test_", "_test", "conftest"]
        self._instr    = InMemoryInstrumenter(flow_id=flow_id, endpoint=endpoint)
        self._patched: Dict[str, str] = {}  # module_name → instrumented source

    def install(self) -> None:
        if self not in sys.meta_path:
            sys.meta_path.insert(0, self)

    def uninstall(self) -> None:
        if self in sys.meta_path:
            sys.meta_path.remove(self)

    def _should_instrument(self, fullname: str) -> bool:
        if not self.packages:
            return False  # must be explicit
        for excl in self.exclude:
            if excl in fullname:
                return False
        return any(fullname == p or fullname.startswith(p + ".") for p in self.packages)

    # ── MetaPathFinder ────────────────────────────────────
    def find_spec(self, fullname, path, target=None):
        if not self._should_instrument(fullname):
            return None
        spec = importlib.util.find_spec(fullname)
        if spec is None or spec.origin is None:
            return None
        if not spec.origin.endswith(".py"):
            return None
        # Return ourselves as the loader
        new_spec = importlib.machinery.ModuleSpec(
            name        = fullname,
            loader      = self,
            origin      = spec.origin,
            is_package  = spec.submodule_search_locations is not None,
        )
        new_spec.submodule_search_locations = spec.submodule_search_locations
        return new_spec

    # ── Loader ────────────────────────────────────────────
    def create_module(self, spec):
        return None  # use default module creation

    def exec_module(self, module):
        spec   = module.__spec__
        origin = spec.origin
        with open(origin, encoding="utf-8") as f:
            source = f.read()
        instrumented, stats = self._instr.instrument(source, filename=origin)
        self._patched[spec.name] = instrumented
        code = compile(instrumented, origin, "exec")
        exec(code, module.__dict__)

    def get_patched(self) -> Dict[str, str]:
        """Returns instrumented source for each patched module."""
        return dict(self._patched)


# ═══════════════════════════════════════════════════════════
# ZipInstrumenter — instrument a whole project zip
# ═══════════════════════════════════════════════════════════

class ZipInstrumenter:
    """
    Input:  ZIP bytes containing .py files
    Output: ZIP bytes with all .py files instrumented
            + flowinspector_track.py added at root

    The original directory structure is preserved.
    Non-Python files are copied unchanged.
    """

    TRACKER_FILENAME = "flowinspector_track.py"

    def __init__(
        self,
        flow_id:   str = "default",
        endpoint:  str = "http://localhost:10000/flow-events/batch",
        skip_dirs: List[str] = None,
    ):
        self.flow_id   = flow_id
        self.endpoint  = endpoint
        self.skip_dirs = skip_dirs or [
            "__pycache__", ".git", ".venv", "venv", "node_modules",
            "dist", "build", ".eggs", "migrations",
        ]
        self._instr = InMemoryInstrumenter(flow_id=flow_id, endpoint=endpoint)

    def instrument_zip(self, zip_bytes: bytes) -> Tuple[bytes, dict]:
        """
        Returns: (instrumented_zip_bytes, report)
        report = {
            "files_processed": int,
            "files_instrumented": int,
            "files_skipped": int,
            "errors": [...],
            "total_functions_instrumented": int,
        }
        """
        report = {
            "files_processed":           0,
            "files_instrumented":        0,
            "files_skipped":             0,
            "errors":                    [],
            "total_functions_instrumented": 0,
        }

        in_buf  = io.BytesIO(zip_bytes)
        out_buf = io.BytesIO()

        # Collect all .py files first for topological sort
        py_files: Dict[str, str] = {}
        other_files: Dict[str, bytes] = {}

        with zipfile.ZipFile(in_buf, "r") as zin:
            for name in zin.namelist():
                if any(skip in name for skip in self.skip_dirs):
                    continue
                raw = zin.read(name)
                if name.endswith(".py"):
                    try:
                        py_files[name] = raw.decode("utf-8", errors="replace")
                    except Exception:
                        other_files[name] = raw
                else:
                    other_files[name] = raw

        # Instrument in dependency order
        instrumented_map = self._instr.instrument_files(py_files)

        # Write output zip
        with zipfile.ZipFile(out_buf, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            # Write instrumented Python files
            for name, result in instrumented_map.items():
                stats = result["stats"]
                report["files_processed"] += 1
                if stats.get("parse_error"):
                    # Copy original on parse error
                    zout.writestr(name, py_files[name])
                    report["files_skipped"] += 1
                    report["errors"].append({
                        "file": name,
                        "error": stats.get("parse_error_msg", "parse error"),
                    })
                else:
                    zout.writestr(name, result["source"])
                    report["files_instrumented"] += 1
                    report["total_functions_instrumented"] += stats.get("functions_instrumented", 0)

            # Write non-Python files unchanged
            for name, raw in other_files.items():
                zout.writestr(name, raw)

            # Inject flowinspector_track.py at root
            tracker_src = self._get_tracker_source()
            zout.writestr(self.TRACKER_FILENAME, tracker_src)

        return out_buf.getvalue(), report

    def _get_tracker_source(self) -> str:
        """Read flowinspector_track.py from the project root."""
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "flowinspector_track.py"),
            os.path.join(os.path.dirname(__file__), "tracker.py"),
        ]
        for c in candidates:
            if os.path.exists(c):
                with open(c, encoding="utf-8") as f:
                    src = f.read()
                # Patch default flow_id and endpoint
                src = src.replace(
                    '"flow_id":      os.environ.get("FLOW_ID", "default")',
                    f'"flow_id":      os.environ.get("FLOW_ID", {self.flow_id!r})',
                )
                src = src.replace(
                    '"endpoint":     os.environ.get("FLOW_ENDPOINT", "http://localhost:10000/flow-events")',
                    f'"endpoint":     os.environ.get("FLOW_ENDPOINT", {self.endpoint!r})',
                )
                return src
        return "# flowinspector_track.py not found\ndef track_flow(fn=None, **kw):\n    return fn if fn is not None else (lambda f: f)\n"


# ═══════════════════════════════════════════════════════════
# DiffInstrumenter — instrument only changed files
# ═══════════════════════════════════════════════════════════

class DiffInstrumenter:
    """
    Instruments only files modified since a git commit or compared
    to a provided baseline set of file hashes.

    Useful for CI/CD integration: instrument the diff, not the whole repo.
    """

    def __init__(
        self,
        flow_id:  str = "default",
        endpoint: str = "http://localhost:10000/flow-events/batch",
    ):
        self._instr = InMemoryInstrumenter(flow_id=flow_id, endpoint=endpoint)

    def instrument_diff(
        self,
        files:     Dict[str, str],          # current: {path: source}
        baseline:  Dict[str, str] = None,    # previous: {path: source} or None
    ) -> Dict[str, dict]:
        """
        Returns only the files that changed (or all if no baseline).
        Each result has "source" and "stats".
        """
        if not baseline:
            changed = set(files.keys())
        else:
            changed = {
                fp for fp, src in files.items()
                if _file_hash(src) != _file_hash(baseline.get(fp, ""))
            }

        results = {}
        for fp in changed:
            if fp in files:
                instrumented, stats = self._instr.instrument(files[fp], filename=fp)
                results[fp] = {"source": instrumented, "stats": stats}
        return results

    def from_git_diff(self, repo_path: str, ref: str = "HEAD") -> Dict[str, str]:
        """
        Returns {filepath: source} for files changed since `ref`.
        Requires git to be available.
        """
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", ref],
            cwd=repo_path, capture_output=True, text=True,
        )
        changed_files = {}
        for line in result.stdout.strip().splitlines():
            if not line.endswith(".py"):
                continue
            full_path = os.path.join(repo_path, line)
            if os.path.exists(full_path):
                with open(full_path, encoding="utf-8") as f:
                    changed_files[line] = f.read()
        return changed_files


# ═══════════════════════════════════════════════════════════
# Preview builder — for the frontend code diff view
# ═══════════════════════════════════════════════════════════

def build_preview(
    source:    str,
    filename:  str = "<unknown>",
    flow_id:   str = "default",
    endpoint:  str = "http://localhost:10000/flow-events/batch",
    context_lines: int = 3,
) -> dict:
    """
    Builds a diff-like preview showing which lines were added
    by the instrumenter. Used by the frontend to show what will change.

    Returns:
      {
        "original_lines": int,
        "instrumented_lines": int,
        "functions_instrumented": int,
        "added_lines": int,
        "hunks": [{ "line": int, "type": "added"|"context", "content": str }],
        "instrumented_source": str,
      }
    """
    instr = InMemoryInstrumenter(flow_id=flow_id, endpoint=endpoint)
    instrumented, stats = instr.instrument(source, filename=filename)

    orig_lines  = source.split("\n")
    instr_lines = instrumented.split("\n")

    # Simple line-diff: mark decorator lines as "added"
    import difflib
    diff = list(difflib.unified_diff(orig_lines, instr_lines, lineterm="", n=context_lines))

    hunks = []
    line_no = 0
    for d in diff[3:]:  # skip the --- +++ @@ header
        if d.startswith("+"):
            hunks.append({"type": "added",   "content": d[1:], "line": line_no})
        elif d.startswith("-"):
            pass  # original lines removed — usually decorator replaced
        elif d.startswith(" "):
            line_no += 1
            hunks.append({"type": "context", "content": d[1:], "line": line_no})

    return {
        "original_lines":         len(orig_lines),
        "instrumented_lines":     len(instr_lines),
        "functions_instrumented": stats.get("functions_instrumented", 0),
        "added_lines":            sum(1 for h in hunks if h["type"] == "added"),
        "parse_error":            stats.get("parse_error", False),
        "hunks":                  hunks[:200],   # limit for frontend
        "instrumented_source":    instrumented,
    }
