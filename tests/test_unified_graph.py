"""
Pruebas del motor de grafo unificado de Flow Inspector.

    pip install -r requirements.txt -r requirements-dev.txt
    pytest -q

Las pruebas de SCIP se omiten salvo que `FI_SCIP_BIN` apunte a un `scip-python` ejecutable.
Ninguna prueba ejecuta ni importa el código analizado: solo se pasan strings al motor.
"""
import io
import os
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from Backend.graph import UnifiedGraphBuilder                              # noqa: E402
from Backend.graph import py_ts                                            # noqa: E402
from Backend.graph.modules import ModuleIndex                              # noqa: E402
from Backend.graph.positions import byte_col_to_utf16, split_lines         # noqa: E402
from Backend.graph.scip_enricher import safe_relpath, run_scip, make_enricher  # noqa: E402
from Backend.graph.scip_reader import parse_index                          # noqa: E402
import Backend.app as app_mod                                              # noqa: E402

needs_ts = pytest.mark.skipif(not py_ts.available(), reason="tree-sitter no instalado")
SCIP_BIN = os.environ.get("FI_SCIP_BIN", "")
needs_scip = pytest.mark.skipif(not (SCIP_BIN and os.access(SCIP_BIN, os.X_OK)), reason="FI_SCIP_BIN no definido")


def build(files, **kw):
    b = UnifiedGraphBuilder(files, **kw)
    return b, b.build()


def calls(g):
    out = {}
    for e in g.edges:
        if e.relation == "CALLS":
            out.setdefault((e.src, e.line), []).append(e)
    return out


def edge(g, src_q, dst_q, rel="CALLS"):
    """Primera arista rel entre símbolos dados por 'archivo::qualname'."""
    s, d = f"py:{src_q}", f"py:{dst_q}"
    return next((e for e in g.edges if e.relation == rel and e.src == s and e.dst == d), None)


COLLIDE = {
    "app/__init__.py": "",
    "app/util.py": "def process(x):\n    return clean(x)\n\ndef clean(x):\n    return x\n",
    "app/models.py": "class Handler:\n    def run(self, x):\n        return self.process(x)\n    def process(self, x):\n        return x\n",
    "app/service.py": (
        "from .util import process as uproc\nfrom . import models\nfrom .models import Handler\n\n"
        "def process(x):\n    return uproc(x)\n\n"
        "class Handler2(Handler):\n    def run(self, x):\n        return super().run(x) + process(x)\n\n"
        "def main():\n    h = models.Handler()\n    return h.run(process(1))\n"),
    "app/legacy/util.py": "def process(x):\n    return x * 2\n\nclass Handler:\n    def run(self, x):\n        return process(x)\n",
    "main.py": "from app.service import main\nfrom app import util\nfrom app.legacy import util as lutil\n\nmain(); util.process(2); lutil.process(3)\n",
}


# ───────────── colisiones de símbolos ─────────────
def test_same_name_in_different_files_get_distinct_identities():
    _, g = build(COLLIDE)
    procs = [s for s in g.symbols.values() if s.name == "process" and s.kind == "function"]
    assert len(procs) == 3 and len({s.uid for s in procs}) == 3
    # cada llamada a `process` va a la definición correcta, no a una arbitraria
    assert edge(g, "app/service.py::process", "app/util.py::process")                       # via alias `uproc`
    assert edge(g, "app/legacy/util.py::Handler.run", "app/legacy/util.py::process")        # lexical, mismo archivo
    assert edge(g, "main.py::<module>", "app/util.py::process")                             # util.process
    assert edge(g, "main.py::<module>", "app/legacy/util.py::process")                      # lutil.process
    assert edge(g, "app/service.py::Handler2.run", "app/service.py::process")               # NO a util/legacy


def test_self_call_resolves_to_own_class_not_homonym():
    _, g = build(COLLIDE)
    e = edge(g, "app/models.py::Handler.run", "app/models.py::Handler.process")
    assert e and e.resolved_by == "self" and e.confidence == "high"


def test_super_and_inheritance_across_files():
    _, g = build(COLLIDE)
    assert edge(g, "app/service.py::Handler2", "app/models.py::Handler", "INHERITS")
    e = edge(g, "app/service.py::Handler2.run", "app/models.py::Handler.run")
    assert e and e.resolved_by == "super"


def test_local_type_inference_from_constructor():
    _, g = build(COLLIDE)
    e = edge(g, "app/service.py::main", "app/models.py::Handler.run")
    assert e and e.resolved_by == "local-type" and e.confidence == "medium"


def test_constructor_call_links_class_and_init():
    files = {"m.py": "class A:\n    def __init__(self):\n        pass\n\ndef f():\n    return A()\n"}
    _, g = build(files)
    assert edge(g, "m.py::f", "m.py::A")
    assert edge(g, "m.py::f", "m.py::A.__init__")


def test_legacy_ids_stay_plain_when_unique_and_qualified_on_collision():
    b, g = build(COLLIDE)
    st = b.legacy_structure()
    assert st["app/models.py"]["classes"]["Handler"]["id"] == "class:Handler@app/models.py"
    assert st["app/legacy/util.py"]["classes"]["Handler"]["id"] == "class:Handler@app/legacy/util.py"
    assert st["app/service.py"]["classes"]["Handler2"]["id"] == "class:Handler2"           # único: id histórico
    graph = b.legacy_bundle()["graph"]
    assert "class:Handler" not in graph["nodes"]
    assert graph["nodes"]["class:Handler@app/models.py"]["label"].startswith("Handler (")


def test_redefinition_in_same_scope_gets_ordinal():
    _, g = build({"m.py": "def f():\n    return 1\n\ndef f():\n    return 2\n\ndef g():\n    return f()\n"})
    uids = sorted(s.uid for s in g.symbols.values() if s.name == "f")
    assert uids == ["py:m.py::f", "py:m.py::f#2"]
    assert edge(g, "m.py::g", "m.py::f#2")                                                   # gana la última definición


# ───────────── imports ─────────────
def test_relative_imports_resolve_by_level():
    files = {"p/__init__.py": "", "p/a.py": "from .b import x\nfrom ..top import y\n", "p/b.py": "x = 1\n", "top.py": "y = 1\n"}
    b, g = build(files)
    dep = b.legacy_dependencies()["p/a.py"]
    assert dep["internal_map"][".b"] == "p/b.py"
    assert dep["symbols_used"]["p/b.py"] == ["x"]
    assert dep["external"] == []                      # `..top` sale del paquete p pero existe como módulo raíz del proyecto


def test_two_modules_same_basename_not_confused():
    files = {"a/util.py": "def f(): pass\n", "b/util.py": "def f(): pass\n", "a/main.py": "from . import util\nutil.f()\n",
             "b/main.py": "from . import util\nutil.f()\n"}
    _, g = build(files)
    assert edge(g, "a/main.py::<module>", "a/util.py::f")
    assert edge(g, "b/main.py::<module>", "b/util.py::f")
    assert not edge(g, "a/main.py::<module>", "b/util.py::f")


def test_stdlib_name_not_shadowed_by_project_module():
    files = {"utils/logging.py": "x = 1\n", "utils/other.py": "import logging\nlogging.info('x')\n"}
    b, _ = build(files)
    dep = b.legacy_dependencies()["utils/other.py"]
    assert dep["external"] == ["logging"] and not dep["internal"]


def test_reexport_through_package_init():
    files = {"pkg/__init__.py": "from .impl import work\n", "pkg/impl.py": "def work(): pass\n", "run.py": "from pkg import work\nwork()\n"}
    _, g = build(files)
    assert edge(g, "run.py::<module>", "pkg/impl.py::work")


def test_ambiguous_import_is_flagged_not_guessed():
    mi = ModuleIndex(["pkg/__init__.py", "pkg/a.py", "other_pkg/__init__.py", "other_pkg/a.py"])
    r = mi.resolve("a", 0, "main.py")
    assert r.ambiguous and r.confidence == "low" and len(r.candidates) == 2


# ───────────── scopes ─────────────
def test_calls_attributed_to_innermost_function():
    files = {"m.py": "def helper(): pass\n\ndef outer():\n    def inner():\n        helper()\n    return inner\n"}
    _, g = build(files)
    assert edge(g, "m.py::outer.inner", "m.py::helper")
    assert not edge(g, "m.py::outer", "m.py::helper")


def test_class_body_not_visible_from_methods():
    files = {"m.py": "def tool(): return 1\n\nclass C:\n    def tool(self): return 2\n    def run(self):\n        return tool()\n"}
    _, g = build(files)
    assert edge(g, "m.py::C.run", "m.py::tool")                                               # función global, no el método


def test_module_level_calls_are_captured():
    _, g = build({"m.py": "def f(): pass\nf()\n"})
    assert edge(g, "m.py::<module>", "m.py::f")


def test_class_defined_inside_try_is_visible():
    files = {"m.py": "try:\n    import zzz\n    class A:\n        def f(self): pass\nexcept ImportError:\n    pass\n"}
    b, g = build(files)
    assert "A" in b.legacy_structure()["m.py"]["classes"]


# ───────────── trazabilidad ─────────────
def test_every_edge_has_file_and_line():
    _, g = build(COLLIDE)
    for e in g.edges:
        if e.relation in ("CALLS", "IMPORTS"):
            assert e.file and e.line > 0, e
    for s in g.symbols.values():
        assert s.file and s.line >= 1 and s.end_line >= s.line


def test_non_ascii_columns_are_utf16():
    src = "x = 'ñandú 😀'; f()\n"
    line = split_lines(src)[0]
    byte_col = line.index(b"f()")
    assert byte_col_to_utf16(line, byte_col) == src.index("f()") + 1                        # el emoji ocupa 2 unidades UTF-16
    _, g = build({"m.py": "def f(): pass\n" + src})
    cs = [c for c in g.symbols if c]  # sanity
    b = UnifiedGraphBuilder({"m.py": "def f(): pass\n" + src}); b.build()
    assert b.facts["m.py"].calls[0].name_col == src.index("f()") + 1


# ───────────── robustez ─────────────
def test_syntax_error_does_not_break_other_files():
    files = {"bad.py": "def f(:\n  pass\n", "good.py": "def g(): pass\n"}
    _, g = build(files)
    assert "py:good.py::g" in g.symbols
    assert any(d["code"] == "parse-error" and d["file"] == "bad.py" for d in g.diagnostics)


@needs_ts
def test_tree_sitter_recovers_symbols_from_python2_file():
    py2 = "def ok():\n    pass\n\nprint 'hello'\n\nclass K:\n    def m(self):\n        ok()\n"
    _, g = build({"old.py": py2}, fallback_extractor=py_ts.TreeSitterExtractor())
    assert "py:old.py::ok" in g.symbols and "py:old.py::K.m" in g.symbols
    assert edge(g, "old.py::K.m", "old.py::ok")
    d = next(d for d in g.diagnostics if d["file"] == "old.py")
    assert d["recovered_by"] == "tree-sitter"


@needs_ts
def test_tree_sitter_matches_ast_on_collision_fixture():
    ex = py_ts.TreeSitterExtractor()
    from Backend.graph.py_ast import AstExtractor
    for fp, src in COLLIDE.items():
        a = AstExtractor().extract(fp, src, "m", False)
        t = ex.extract(fp, src, "m", False)
        assert {(s.qualname, s.kind, s.name_line, s.name_col) for s in a.symbols} == \
               {(s.qualname, s.kind, s.name_line, s.name_col) for s in t.symbols}
        assert sorted((c.line, c.col, c.expr) for c in a.calls) == sorted((c.line, c.col, c.expr) for c in t.calls)
        assert sorted((i.line, i.local, i.module, i.level, i.name) for i in a.imports) == \
               sorted((i.line, i.local, i.module, i.level, i.name) for i in t.imports)


@needs_ts
def test_tree_sitter_type_soft_keyword_quirk():
    ex = py_ts.TreeSitterExtractor()
    f = ex.extract("m.py", "def f(o):\n    type(o).x = 1\n", "m", False)
    assert any(c.expr == "type" for c in f.calls)


# ───────────── seguridad de rutas / SCIP ─────────────
@pytest.mark.parametrize("p,ok", [("a/b.py", True), ("a\\b.py", True), ("a/./b.py", True), ("../x.py", False),
                                  ("/etc/x.py", False), ("C:/x.py", False), ("a/../../x.py", False),
                                  ("x.txt", False), ("x\x00.py", False), ("", False)])
def test_safe_relpath(p, ok):
    assert (safe_relpath(p) is not None) == ok


def test_run_scip_without_binary_degrades_gracefully(monkeypatch):
    monkeypatch.delenv("FI_SCIP_BIN", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent")
    r = run_scip({"a.py": "x=1\n"})
    assert r.index is None and r.error


def test_scip_reader_decodes_hand_built_index():
    def varint(n):
        out = bytearray()
        while True:
            b = n & 0x7F; n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n: return bytes(out)
    def ld(fno, payload): return varint(fno << 3 | 2) + varint(len(payload)) + payload
    def vi(fno, n): return varint(fno << 3) + varint(n)
    occ = ld(1, b"".join(varint(v) for v in (3, 4, 9))) + ld(2, b"sym f().") + vi(3, 1)
    doc = ld(1, b"a.py") + ld(2, occ)
    idx = parse_index(ld(2, doc) + ld(1, ld(2, ld(1, b"tool") + ld(2, b"1.0"))))
    o = idx.documents["a.py"].occurrences[0]
    assert (o.start_line, o.start_char, o.end_char, o.symbol, o.is_definition) == (3, 4, 9, "sym f().", True)
    assert idx.tool == "tool"


@needs_scip
def test_scip_confirms_and_never_executes_repo(tmp_path):
    sentinel = tmp_path / "ran"
    files = dict(COLLIDE)
    files["sitecustomize.py"] = f"open(r'{sentinel}', 'w').write('x')\n"
    files["conftest.py"] = files["setup.py"] = files["sitecustomize.py"]
    files["../../escape.py"] = "x = 1\n"
    res = run_scip(files, SCIP_BIN)
    assert res.error is None, res.error
    assert not sentinel.exists()
    assert res.files_skipped == 1
    b, g = build(COLLIDE, enrichers=[make_enricher(run_scip(COLLIDE, SCIP_BIN))])
    st = g.backends["scip"]
    assert st["applied"] and st["corrected"] == 0
    assert st["agreement"] >= 0.9
    assert edge(g, "app/service.py::process", "app/util.py::process").confidence == "exact"


# ───────────── contrato HTTP / compatibilidad con la UI ─────────────
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    return TestClient(app_mod.app)


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return buf.getvalue()


def test_health_reports_engine(client):
    j = client.get("/health").json()
    assert j["status"] == "healthy" and j["engine"]["unified"] is True


def test_analyze_zip_keeps_ui_contract(client):
    r = client.post("/analyze/zip", files={"file": ("p.zip", _zip(COLLIDE), "application/zip")})
    assert r.status_code == 200
    j = r.json()
    for k in ("files", "structure", "dependencies", "call_graph", "graph", "dead_code", "summary", "project_type"):
        assert k in j
    for k in ("total_files", "total_classes", "total_functions", "total_nodes", "total_edges", "dead_code_summary"):
        assert k in j["summary"]
    for f in j["files"]:
        for k in ("path", "name", "type", "classes", "functions", "imports_total", "imports_internal",
                  "imports_external", "dead_code_count", "dead_code_high"):
            assert k in f
    assert j["engine"] == "unified" and j["unified"]["stats"]["calls_by_confidence"]
    rels = {e["relation"] for e in j["graph"]["edges"]}
    assert {"IMPORTS", "DEFINES", "CALLS", "FILE_USES"} <= rels
    for n in j["graph"]["nodes"].values():
        assert n["type"] in ("file", "module", "class", "function", "external")
    for e in j["graph"]["edges"]:
        assert e["from"] in j["graph"]["nodes"] and e["to"] in j["graph"]["nodes"]


def test_traceability_roundtrip_and_graph_endpoint(client):
    j = client.post("/analyze/zip", files={"file": ("p.zip", _zip(COLLIDE), "application/zip")}).json()
    t = client.post("/traceability", json={"filepath": "app/service.py", "analysis": j}).json()
    assert {i["resolved_path"] for i in t["imports"] if i["resolved_path"]} == {"app/util.py", "app/models.py"}
    assert [u["file"] for u in client.post("/traceability", json={"filepath": "app/util.py", "analysis": j}).json()["upstream"]] \
        == ["app/service.py", "main.py"]
    full = client.post("/graph/unified", files={"file": ("p.zip", _zip(COLLIDE), "application/zip")}).json()
    assert full["symbols"] and full["edges"] and "truncated" not in full


def test_dead_code_not_masked_by_homonym_callers():
    files = {"a.py": "def helper():\n    return 1\n", "b.py": "def helper():\n    return 2\n\ndef use():\n    return helper()\n"}
    res = app_mod.run_analysis(files)
    dead = {i["name"] for i in res["dead_code"]["items"]["a.py"]}
    assert "helper" in dead                                                                  # a.helper nadie lo llama
    assert "helper" not in {i["name"] for i in res["dead_code"]["items"].get("b.py", []) if i["score"] >= 0.7}


def test_engine_falls_back_to_legacy_on_internal_error(monkeypatch):
    monkeypatch.setattr(app_mod, "_run_analysis_unified", lambda files: (_ for _ in ()).throw(RuntimeError("boom")))
    out = app_mod.run_analysis({"m.py": "def f(): pass\n"})
    assert out["engine"] == "legacy-fallback" and out["structure"]["m.py"]["functions"][0]["name"] == "f"


def test_legacy_engine_switch(monkeypatch):
    monkeypatch.setenv("FI_ENGINE", "legacy")
    assert "engine" not in app_mod.run_analysis({"m.py": "def f(): pass\n"})


# ───────────── definiciones condicionales ─────────────
CONDITIONAL = (
    "import sys\n"
    "if sys.platform == 'win32':\n    def helper():\n        return 1\nelse:\n    def helper():\n        return 2\n\n"
    "def use():\n    return helper()\n")


def test_conditional_redefinitions_emit_all_alternatives_as_ambiguous():
    _, g = build({"m.py": CONDITIONAL})
    es = [e for e in g.edges if e.relation == "CALLS" and e.src == "py:m.py::use"]
    assert {e.dst for e in es} == {"py:m.py::helper", "py:m.py::helper#2"}
    assert all(e.ambiguous and e.confidence != "high" for e in es)
    assert {e.resolved_by for e in es} == {"lexical", "conditional-def"}


@needs_ts
def test_tree_sitter_flags_conditional_symbols_like_ast():
    from Backend.graph.py_ast import AstExtractor
    a = AstExtractor().extract("m.py", CONDITIONAL, "m", False)
    t = py_ts.TreeSitterExtractor().extract("m.py", CONDITIONAL, "m", False)
    assert sorted((s.uid, s.conditional) for s in a.symbols) == sorted((s.uid, s.conditional) for s in t.symbols)
    assert [s.conditional for s in a.symbols if s.name == "helper"] == [True, True]
    assert [s.conditional for s in a.symbols if s.name == "use"] == [False]


def test_sequential_redefinition_still_picks_last_only():
    _, g = build({"m.py": "def f():\n    return 1\n\ndef f():\n    return 2\n\ndef g():\n    return f()\n"})
    es = [e for e in g.edges if e.relation == "CALLS" and e.src == "py:m.py::g"]
    assert [e.dst for e in es] == ["py:m.py::f#2"] and not es[0].ambiguous


# ───────────── determinismo ─────────────
def test_output_is_deterministic():
    import json
    a = json.dumps(build(COLLIDE)[1].to_dict(), sort_keys=False)
    b = json.dumps(build(dict(reversed(list(COLLIDE.items()))))[1].to_dict(), sort_keys=False)
    assert a == b                                    # mismo grafo byte a byte, sin importar el orden de entrada
