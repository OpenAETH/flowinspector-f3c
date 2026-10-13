"""Render de informes: Markdown (para CI/PR/mail) y HTML autocontenido."""
from __future__ import annotations
import html
from typing import Optional

_SEV = {"high": "🔴 alta", "medium": "🟠 media", "low": "🟡 baja", "info": "🔵 info"}


def _loc(e: dict) -> str:
    s = e.get("file", "")
    if e.get("line"):
        s += f":{e['line']}"
    return f"`{s}`" + (f" · `{e['symbol']}`" if e.get("symbol") else "")


def to_markdown(report: dict, narrative: Optional[dict] = None, diff: Optional[dict] = None) -> str:
    o = report["overview"]
    L = [f"# Informe de análisis{' — ' + report['project'] if report.get('project') else ''}", ""]
    L.append(f"{o['files']} archivos · {o.get('classes')} clases · {o.get('functions')} funciones · motor `{o.get('engine')}` · huella `{report['digest']}`")
    L.append("")
    if narrative:
        L += ["## Resumen ejecutivo", "", narrative.get("resumen", ""), ""]
        if narrative.get("acciones"):
            L += ["### Acciones recomendadas", ""] + [f"{i}. {a}" for i, a in enumerate(narrative["acciones"], 1)] + [""]
        L.append(f"_Narrativa generada por `{narrative.get('model')}`; los hechos de abajo son deterministas._")
        L.append("")
    elif narrative is None:
        pass
    if diff and diff.get("comparable"):
        L += ["## Cambios desde la corrida anterior", ""]
        s, e = diff["symbols"], diff["edges"]
        L.append(f"- Símbolos: +{s['added']['count']} / −{s['removed']['count']} · redimensionados {s['resized']['count']} · movidos {s['moved']['count']}")
        L.append(f"- Aristas: +{e['added']['count']} / −{e['removed']['count']}")
        L.append(f"- Código muerto nuevo: {diff['dead_code']['new']['count']} · resuelto: {diff['dead_code']['resolved']['count']}")
        L.append(f"- Ciclos nuevos: {diff['cycles']['new']['count']} · resueltos: {diff['cycles']['resolved']['count']}")
        if diff.get("limited"):
            L.append("- ⚠ Comparación parcial (payload recortado o motor legacy).")
        L.append("")
    L += ["## Hallazgos", ""]
    if not report["findings"]:
        L.append("Sin hallazgos relevantes.")
    for f in report["findings"]:
        L.append(f"- **{_SEV[f['severity']]}** — {f['title']}")
        for ev in f["evidence"]:
            L.append(f"  - {_loc(ev)}")
    L.append("")
    r = report.get("resolution")
    if r:
        L += ["## Calidad de resolución de llamadas", "",
              f"{r['calls_total']} llamadas · confianza {r['by_confidence']} · ambiguas {r['ambiguous']} · externas {r['external']} · resueltas sin ambigüedad {r['internal_resolved_pct']}%", ""]
    if report["hotspots"]:
        L += ["## Archivos más acoplados", "", "| Archivo | Fan-in | Fan-out | Líneas |", "|---|---:|---:|---:|"]
        L += [f"| `{h['file']}` | {h['fan_in']} | {h['fan_out']} | {h['lines']} |" for h in report["hotspots"]]
        L.append("")
    if report["most_called"]:
        L += ["## Símbolos más llamados", "", "| Símbolo | Ubicación | Callers |", "|---|---|---:|"]
        L += [f"| `{m['name']}` | `{m['file']}:{m['line']}` | {m['callers']} |" for m in report["most_called"]]
        L.append("")
    if report["dead_code_high"]:
        L += ["## Código muerto probable (top)", ""]
        L += [f"- `{d['file']}{':' + str(d['line']) if d['line'] else ''}` · `{d['name']}` ({d['score']})" for d in report["dead_code_high"][:15]]
        L.append("")
    return "\n".join(L)


def to_html(report: dict, narrative: Optional[dict] = None, diff: Optional[dict] = None) -> str:
    md = to_markdown(report, narrative, diff)
    return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Informe FlowInspector</title><style>body{font:14px/1.5 system-ui;max-width:880px;margin:2rem auto;padding:0 1rem;"
            "background:#0d0f14;color:#d4d8e8}pre{white-space:pre-wrap;font:13px/1.55 ui-monospace,monospace}</style>"
            f"<pre>{html.escape(md)}</pre>")
