# Unified symbol graph (Flow Inspector 3.1)

The Python analysis now builds a single graph of **symbols with file-qualified identities**, and the
existing UI/API payload (`structure`, `dependencies`, `call_graph`, `graph`) is projected from it.
The analyzed repository is **never executed or imported**: only `ast.parse`, tree-sitter and (optionally)
`scip-python` over a sanitized copy of the sources.

## Layout

```
Backend/graph/
  model.py         Symbol / Edge / FileFacts, uid scheme, confidence levels
  positions.py     UTF-8 byte <-> UTF-16 column conversion (needed to join backends exactly)
  py_ast.py        ast extractor with real scopes (qualname, innermost caller, conditional defs)
  py_ts.py         tree-sitter extractor (optional) - same FileFacts, tolerant to syntax errors
  modules.py       module index + import resolution (relative, package roots, siblings, stdlib guard)
  resolver.py      lexical lookup, re-exports, MRO / super(), local & attribute type hints, calls
  unified.py       builder, legacy projections (ids, structure, dependencies, call_graph, graph)
  scip_reader.py   minimal SCIP protobuf decoder
  scip_enricher.py safe scip-python runner + edge confirmation/correction (optional)
```

## Identity and traceability

* `uid = py:<file>::<qualname>` (`#2`, `#3` for redefinitions in the same scope); modules are `py:<file>::<module>`.
* Every symbol has `file`, `line`, `end_line`; every `CALLS` / `IMPORTS` edge has `file`, `line`, `col`.
* Every edge has `confidence` (`exact` > `high` > `medium` > `low`), `resolved_by`, `ambiguous`, `external`.
* Legacy node ids (`function:x`, `method:C.m`, `class:C`) are **unchanged when unique** and become
  `function:x@path/to/file.py` only on collision; colliding labels get ` (file.py)` appended.
* Conditional definitions (`if/else`, `try/except`) emit an edge to **every** alternative, marked ambiguous.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `FI_ENGINE` | `unified` | `legacy` restores the previous analyzer exactly. Any internal error also falls back to it (`engine: "legacy-fallback"`) |
| `FI_TREE_SITTER` | `1` | `0` disables the tree-sitter fallback |
| `FI_SCIP` | off | `1` enables SCIP confirmation (needs Node >= 16 and `scip-python`, or `FI_SCIP_BIN`) |
| `FI_SCIP_TIMEOUT` / `FI_SCIP_MAX_FILES` / `FI_SCIP_MAX_BYTES` | 90 s / 5000 / 25 MB | Hard limits |
| `FI_UNIFIED_MAX_EDGES` | 20000 | Above this the analysis payload carries only stats; `POST /graph/unified` returns the full graph |

`GET /health` reports which backends are active. New endpoint: `POST /graph/unified` (zip of `.py`).

## SCIP safety model

Run on a *copy*: only `.py` files whose paths pass `safe_relpath` (no absolute paths, `..`, NUL, drive letters),
our own `scip-pyrightconfig.json` (the project's `pyrightconfig.json` / `pyproject.toml` are never copied),
empty environment (`PYTHONSAFEPATH=1`, `PYTHONNOUSERSITE=1`, isolated `HOME`), `--environment` pointing to an empty
list so `pip` is never invoked, temp working directory, hard timeout. Verified with a booby-trapped repo
(`sitecustomize.py`, `site.py`, `conftest.py`, `setup.py` and a `pyrightconfig.json` pointing `pythonPath` at a script):
no payload ran, and `../` / absolute entries were not written.

## Validation (measured)

| Check | Result |
|---|---|
| Parity `ast` vs tree-sitter (140 files, 60.7k lines: stdlib + this repo) | 0 differences in symbols, name positions, calls and imports |
| Resolver vs SCIP on 2,764 internal call sites (asyncio, json, logging, email, http, ... 105 files) | 95.7 % overall; 99.5 % on `high`, 99.4 % on `medium`, 100 % on `low`/ambiguous; 12 residual disagreements are duck-typing/inheritance cases SCIP types better |
| Recall gap | 106 sites SCIP resolves via parameter types that the offline resolver leaves unresolved (SCIP corrects them when enabled) |
| Cross-check with codemap `--deep` on the collision fixture | identical 8 call edges in its scope (codemap's fast tier misses `super()` and local-type calls) |
| Performance, 278k lines / 534 files (full stdlib) | legacy 5.33 s, unified 5.26 s, same peak RSS (~375 MB) |
| Performance of SCIP | 25.7 s for 46k lines (vs 0.65 s own engine): opt-in only |
| Determinism | byte-identical output regardless of input order |
| Tests | `pytest -q`: 45 tests (39 run without optional deps) |

## Behavior changes vs 3.0 (all intentional)

* Same-name symbols in different files are no longer merged; calls resolve to the right definition.
* `from .x import y`, `from . import m`, `from ..pkg import z`, package `__init__` re-exports and `import a.b.c` now resolve internally;
  a project `logging.py` no longer hides stdlib `logging` unless it is at the project root.
* Calls are attributed to the innermost function; module-level calls appear under `<module>`.
* Classes/functions defined inside module-level `try:`/`if:` are now seen.
* Dead-code callers are counted per symbol instead of per bare name, so a homonym's callers no longer hide an unused function
  (and `time.ctime()` no longer counts as a call to `date.ctime`). Unresolved attribute calls still count toward every
  same-named method, to avoid false positives. On the full stdlib corpus `dead_high` moved 923 -> 1,078:
  109 of the 140 newly flagged pre-existing items were hidden by a homonym; sampled non-collisions were confirmed by hand.

## Known limits

* tree-sitter-python parses `type(x).attr = v` as a `type` alias statement; handled specially in `py_ts.py`.
* Dynamic dispatch, `getattr`, decorators that rewrite callables and runtime-built classes are not resolved without SCIP's type inference.
* The unified graph is Python-only; the HTML/CSS/JS analyzers are unchanged.
* The UI file list shows only base names, so two `util.py` still look alike there (the path is in the tooltip).

## Informes automáticos (3.1)

`Backend/report/` genera un informe **determinista** (hechos con `archivo:línea`) y, opcionalmente, una narrativa IA encima.

| Pieza | Qué hace |
|---|---|
| `builder.py` | Hallazgos con severidad y evidencia: ciclos de imports (Tarjan), código muerto probable, colisiones de nombres, funciones largas, acoplamiento (fan-in/out), símbolos más llamados, calidad de resolución de llamadas |
| `diff.py` | Snapshot compacto por uid y diff entre corridas (símbolos añadidos/quitados/movidos, aristas, código muerto y ciclos nuevos/resueltos) |
| `narrative.py` | Groq con reintentos (429/5xx), fallback entre modelos (404/retirado), reintento sin `response_format`, parser que quita `<think>`/fences y **descarta acciones que citen archivos inexistentes**. Si todo falla, el informe sale sin narrativa |
| `config.py` | Modelos configurables: `FI_MODELS` (default `qwen/qwen3.8-27b,openai/gpt-oss-120b,openai/gpt-oss-20b`), `FI_MODEL_REPORT`, `FI_MODEL_CHAT`, `FI_MODEL_FAST` |
| `__main__.py` | CLI para CI/cron |

```
python -m Backend.report REPO_O_ZIP --out informe.md [--format md|html|json] [--ai] [--model ID]
       [--baseline snap.json] [--save-snapshot snap.json] [--fail-on medium]   # exit 2 si hay hallazgos >= nivel
```

API: `GET /models`, `POST /report` (zip; `?ai=true`; clave en header `x-groq-key` o `GROQ_API_KEY`), `POST /report/analysis` (JSON `{analysis, ai, api_key, model, baseline}`).
UI: botón **▤ Informe** (descarga Markdown; guarda el snapshot en el navegador para mostrar cambios en la próxima descarga) y selector de modelos poblado desde `/models`.
Automatización: `.github/workflows/flowinspector-report.yml` (semanal + en PRs, resumen en la pestaña del job, línea base por caché). `GROQ_API_KEY` es un secret opcional.

## Gráfico (3.1)

Layout con repulsión Barnes-Hut y enfriamiento (se detiene solo), halos por archivo, HiDPI, etiquetas por nivel de detalle sin solapes,
aristas por confianza (punteadas = ambiguas/baja), anillos de código muerto, foco por vecindad (`F`: 1→2→todo), búsqueda (`/`, Enter siguiente),
minimapa, pinch-zoom, exportar PNG. Misma API pública (`Graph.init`, `setView`, `highlightFile`, ...).
