"""
CLI: `python -m Backend.report REPO_DIR_O_ZIP [--out informe.md] [--format md|html|json] [--ai]
        [--baseline snapshot.json] [--save-snapshot snapshot.json] [--fail-on high]`

Analiza SIN ejecutar el código (solo ast/tree-sitter). Pensado para CI / cron.
Código de salida: 0 ok; 2 si hay hallazgos >= --fail-on.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import zipfile

_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}
SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "build", "dist"}


def load_files(path: str, max_bytes: int = 5_000_000):
    files = {}
    if os.path.isfile(path) and path.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for n in zf.namelist():
                if n.endswith(".py") and not n.startswith("__MACOSX"):
                    files[n.replace("\\", "/")] = zf.read(n).decode("utf-8", "replace")
        return files
    for root, dirs, names in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith("."))
        for n in sorted(names):
            fp = os.path.join(root, n)
            if n.endswith(".py") and not os.path.islink(fp) and os.path.getsize(fp) <= max_bytes:
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    files[os.path.relpath(fp, path).replace(os.sep, "/")] = fh.read()
    return files


def run(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m Backend.report")
    ap.add_argument("path"); ap.add_argument("--out"); ap.add_argument("--format", choices=["md", "html", "json"], default="md")
    ap.add_argument("--ai", action="store_true"); ap.add_argument("--model", default="")
    ap.add_argument("--baseline"); ap.add_argument("--save-snapshot"); ap.add_argument("--project", default="")
    ap.add_argument("--fail-on", choices=list(_SEV), default="")
    a = ap.parse_args(argv)
    try:
        from .. import app as appmod
    except ImportError:
        import app as appmod   # noqa
    from . import build_report, make_snapshot, diff_snapshots, to_markdown, to_html, generate_narrative
    files = load_files(a.path)
    if not files:
        print("sin archivos .py", file=sys.stderr); return 1
    analysis = appmod.run_analysis(files)
    report = build_report(analysis, a.project or os.path.basename(os.path.abspath(a.path)).replace(".zip", ""))
    snap = make_snapshot(analysis, report)
    diff = None
    if a.baseline and os.path.isfile(a.baseline):
        with open(a.baseline) as fh:
            diff = diff_snapshots(json.load(fh), snap)
    narr = None
    if a.ai:
        res = generate_narrative(report, preferred=a.model)
        narr = res["narrative"]
        if not narr:
            print(f"[aviso] sin narrativa IA: {res['attempts']}", file=sys.stderr)
    if a.save_snapshot:
        with open(a.save_snapshot, "w") as fh:
            json.dump(snap, fh, separators=(",", ":"))
    out = (json.dumps({"report": report, "narrative": narr, "diff": diff}, ensure_ascii=False, indent=1) if a.format == "json"
           else to_html(report, narr, diff) if a.format == "html" else to_markdown(report, narr, diff))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        print(out)
    if a.fail_on:
        return 2 if any(_SEV[f["severity"]] >= _SEV[a.fail_on] for f in report["findings"]) else 0
    return 0


if __name__ == "__main__":
    sys.exit(run())
