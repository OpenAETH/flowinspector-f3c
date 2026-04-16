"""
Flow Inspector — FastAPI Backend  v3.0  (Cloud / Render.com)
=============================================================
API REST para analizar repositorios Python Y proyectos web (HTML/CSS/JS).
Autoshutdown REMOVIDO — versión cloud (Render.com).
Login via ACCESS_KEY en variables de entorno.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from collections import defaultdict
from typing import Dict, List, Optional
import ast, os, re, json, zipfile, io, secrets, pathlib

app = FastAPI(title="Flow Inspector API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── AUTH ────────────────────────────────────────────────
ACCESS_KEY = os.environ.get("ACCESS_KEY", "")

def _check_key(provided: str) -> bool:
    if not ACCESS_KEY:
        return True
    return secrets.compare_digest(provided.strip(), ACCESS_KEY.strip())

class LoginPayload(BaseModel):
    key: str

@app.post("/api/login")
async def login(payload: LoginPayload):
    if not _check_key(payload.key):
        raise HTTPException(401, "Clave de acceso incorrecta.")
    return {"ok": True}

@app.get("/api/auth-required")
async def auth_required():
    return {"required": bool(ACCESS_KEY)}

def require_auth(request: Request):
    if not ACCESS_KEY:
        return True
    key = request.headers.get("x-access-key", "")
    if not _check_key(key):
        raise HTTPException(401, "No autorizado.")
    return True

# ═══════════════════════════════════════════════════════════
# PYTHON ANALYSIS CORE
# ═══════════════════════════════════════════════════════════

class RepositoryLoader:
    def load_from_dump(self, content):
        if re.search(r"^={10,}\s*\nINICIO ARCHIVO:", content, re.MULTILINE):
            return self._machete(content)
        return self._legacy(content)

    def _machete(self, content):
        files = {}
        pat = re.compile(r"={10,}\s*\nINICIO ARCHIVO:\s*(.+?)\s*\n={10,}\s*\n(.*?)\n={10,}\s*\nFIN ARCHIVO:\s*.+?\s*\n={10,}", re.DOTALL)
        for m in pat.finditer(content):
            path = m.group(1).strip().replace("\\", "/")
            if path.endswith(".py"):
                files[path] = m.group(2).lstrip("\n")
        return files

    def _legacy(self, content):
        files = {}
        pat = re.compile(r"^###\s+(.+?)\s+###\s*$", re.MULTILINE)
        matches = list(pat.finditer(content))
        for i, m in enumerate(matches):
            fp = m.group(1).strip()
            start, end = m.end(), (matches[i+1].start() if i+1 < len(matches) else len(content))
            if fp.endswith(".py"):
                files[fp] = content[start:end].strip()
        return files


class ASTParser:
    def parse(self, files):
        result = {}
        for fp, src in files.items():
            try:    result[fp] = ast.parse(src, filename=fp)
            except: result[fp] = None
        return result


class FileDependencyAnalyzer:
    def analyze(self, parsed, known_files=None):
        known = known_files or set(parsed.keys())
        base_map = {os.path.basename(fp).replace(".py", ""): fp for fp in known}
        result = {}
        for fp, tree in parsed.items():
            if tree is None:
                result[fp] = {"all": [], "internal": [], "external": [], "internal_map": {}, "symbols_used": {}}
                continue
            raw, symbols = self._imports(tree)
            internal, external, imap, sym_used = [], [], {}, {}
            for mod in raw:
                resolved = base_map.get(mod) or base_map.get(mod.split(".")[-1])
                if resolved:
                    internal.append(mod); imap[mod] = resolved; sym_used[resolved] = symbols.get(mod, [])
                else:
                    external.append(mod)
            result[fp] = {"all": raw, "internal": internal, "external": external, "internal_map": imap, "symbols_used": sym_used}
        return result

    def _imports(self, tree):
        mods, symbols = [], {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    mods.append(a.name); symbols.setdefault(a.name, [])
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.append(node.module)
                symbols.setdefault(node.module, []).extend([a.name for a in node.names if a.name != "*"])
        return mods, symbols


class StructureAnalyzer:
    def analyze(self, parsed):
        return {fp: (self._extract(tree) if tree else {"classes": {}, "functions": []}) for fp, tree in parsed.items()}

    def _extract(self, tree):
        classes, functions = {}, []
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes[node.name] = {"methods": self._methods(node), "inherits": self._bases(node), "decorators": self._decs(node)}
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append({"name": node.name, "decorators": self._decs(node)})
        return {"classes": classes, "functions": functions}

    def _methods(self, cls):
        return [{"name": n.name, "decorators": self._decs(n)} for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def _decs(self, node):
        out = []
        for d in getattr(node, "decorator_list", []):
            if isinstance(d, ast.Name): out.append(d.id)
            elif isinstance(d, ast.Attribute): out.append(self._attr(d))
            elif isinstance(d, ast.Call):
                f = d.func
                if isinstance(f, ast.Name): out.append(f.id)
                elif isinstance(f, ast.Attribute): out.append(self._attr(f))
        return out

    def _bases(self, cls):
        out = []
        for b in cls.bases:
            if isinstance(b, ast.Name): out.append(b.id)
            elif isinstance(b, ast.Attribute): out.append(self._attr(b))
        return out

    def _attr(self, node):
        v = node.value
        if isinstance(v, ast.Name): return f"{v.id}.{node.attr}"
        elif isinstance(v, ast.Attribute): return f"{self._attr(v)}.{node.attr}"
        return node.attr


class CallGraphAnalyzer:
    def analyze(self, parsed):
        return {fp: (self._extract(tree) if tree else {}) for fp, tree in parsed.items()}

    def _extract(self, tree):
        cg = defaultdict(list)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                calls = self._calls(node)
                if calls: cg[node.name].extend(calls)
        return dict(cg)

    def _calls(self, fn):
        out = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                name = self._target(node.func)
                if name: out.append({"name": name, "line": getattr(node, "lineno", 0)})
        return out

    def _target(self, node):
        if isinstance(node, ast.Name): return node.id
        elif isinstance(node, ast.Attribute):
            p = self._target(node.value)
            return f"{p}.{node.attr}" if p else node.attr
        return None


class DependencyGraphBuilder:
    def __init__(self):
        self.nodes = {}; self.edges = []; self._idx = defaultdict(list)

    def build(self, dependencies, structure, call_graph):
        self._file_nodes(dependencies); self._import_edges(dependencies)
        self._file_use_edges(dependencies); self._struct_nodes(structure)
        self._call_edges(call_graph, structure)

    def _reg(self, nid, data):
        self.nodes[nid] = data
        lbl = data.get("label", "")
        if lbl:
            self._idx[lbl].append(nid)
            short = lbl.split(".")[-1]
            if short != lbl: self._idx[short].append(nid)

    def _fid(self, fp): return f"file:{fp}"

    def _file_nodes(self, deps):
        for fp in deps:
            self._reg(self._fid(fp), {"type": "file", "label": os.path.basename(fp), "path": fp})

    def _import_edges(self, deps):
        for fp, d in deps.items():
            src = self._fid(fp); mods = d.get("all", []); imap = d.get("internal_map", {})
            for mod in mods:
                mid = f"module:{mod}"
                if mid not in self.nodes: self._reg(mid, {"type": "module", "label": mod})
                self.edges.append({"from": src, "to": mid, "relation": "IMPORTS", "is_internal": mod in imap})

    def _file_use_edges(self, deps):
        for fp, d in deps.items():
            src = self._fid(fp); sym_used = d.get("symbols_used", {}); imap = d.get("internal_map", {})
            for mod, resolved_fp in imap.items():
                self.edges.append({"from": src, "to": self._fid(resolved_fp), "relation": "FILE_USES",
                                   "symbols": sym_used.get(resolved_fp, []), "module": mod})

    def _struct_nodes(self, structure):
        for fp, data in structure.items():
            fid = self._fid(fp)
            if not isinstance(data, dict): continue
            for cname, cdata in data.get("classes", {}).items():
                if not isinstance(cdata, dict): continue
                cid = f"class:{cname}"
                self._reg(cid, {"type": "class", "label": cname, "decorators": cdata.get("decorators", []), "inherits": cdata.get("inherits", [])})
                self.edges.append({"from": fid, "to": cid, "relation": "DEFINES"})
                for m in cdata.get("methods", []):
                    mn, md = (m["name"], m.get("decorators", [])) if isinstance(m, dict) else (m, [])
                    mid = f"method:{cname}.{mn}"
                    self._reg(mid, {"type": "function", "label": f"{cname}.{mn}", "short_name": mn, "class": cname, "decorators": md})
                    self.edges.append({"from": cid, "to": mid, "relation": "DEFINES"})
            for f in data.get("functions", []):
                fn, fd = (f["name"], f.get("decorators", [])) if isinstance(f, dict) else (f, [])
                fid2 = f"function:{fn}"
                self._reg(fid2, {"type": "function", "label": fn, "decorators": fd})
                self.edges.append({"from": fid, "to": fid2, "relation": "DEFINES"})

    def _call_edges(self, call_graph, structure):
        caller_cls = {}
        for data in structure.values():
            for cname, cdata in data["classes"].items():
                for m in cdata["methods"]:
                    caller_cls[m["name"] if isinstance(m, dict) else m] = cname
        for fp, calls in call_graph.items():
            for caller, callees in calls.items():
                cid = self._resolve_caller(caller, caller_cls)
                for entry in callees:
                    cn = entry["name"] if isinstance(entry, dict) else entry
                    line = entry.get("line", 0) if isinstance(entry, dict) else 0
                    tid = self._resolve_callee(cn, caller, caller_cls)
                    if tid not in self.nodes: self._reg(tid, {"type": "external", "label": cn})
                    self.edges.append({"from": cid, "to": tid, "relation": "CALLS", "line": line})

    def _resolve_caller(self, name, caller_cls):
        if name in caller_cls:
            cid = f"method:{caller_cls[name]}.{name}"
            if cid in self.nodes: return cid
        fid = f"function:{name}"
        return fid if fid in self.nodes else f"unknown:{name}"

    def _resolve_callee(self, name, caller, caller_cls):
        if "." in name:
            prefix, method = name.split(".", 1)
            if prefix in ("self", "cls") and caller in caller_cls:
                cid = f"method:{caller_cls[caller]}.{method}"
                if cid in self.nodes: return cid
            cid = f"method:{prefix}.{method}"
            if cid in self.nodes: return cid
            return self._by_short(method, caller, caller_cls)
        return self._by_short(name, caller, caller_cls)

    def _by_short(self, name, caller, caller_cls):
        candidates = self._idx.get(name, [])
        if not candidates:
            fid = f"function:{name}"
            return fid if fid in self.nodes else f"unknown:{name}"
        if len(candidates) == 1: return candidates[0]
        if caller in caller_cls:
            pref = f"method:{caller_cls[caller]}.{name}"
            if pref in candidates: return pref
        gid = f"function:{name}"
        return gid if gid in candidates else candidates[0]

    def to_dict(self): return {"nodes": self.nodes, "edges": self.edges}


EXCL_NAMES    = {"main","run","start","stop","execute","launch","setup","teardown","setUp","tearDown","setUpClass","tearDownClass","configure","initialize","init_app","create_app","ready","shutdown","cleanup","handle","dispatch","process","on_event"}
EXCL_PREFIXES = ("__", "test_", "Test")
EXCL_SUFFIXES = ("_handler","_callback","_listener","_hook","_middleware","_signal")
FRAMEWORK_DECS = {"property","staticmethod","classmethod","abstractmethod","cached_property","pytest.fixture","fixture","patch","login_required","app.route","blueprint.route","router.get","router.post","router.put","router.delete","app.get","app.post","app.put","app.delete","shared_task","task","command","group","override","contextmanager","dataclass"}

class DeadCodeAnalyzer:
    def __init__(self, data, exclusions=None):
        self.data = data; self.extra = exclusions or set()
        self._callers = {}; self._result = None

    def analyze(self, force=False):
        if self._result and not force: return self._result
        self._build_callers(); self._result = self._run(); return self._result

    def _build_callers(self):
        counts = defaultdict(int)
        for calls in self.data.get("call_graph", {}).values():
            for callees in calls.values():
                for e in callees:
                    name = e["name"] if isinstance(e, dict) else e; short = name.split(".")[-1]
                    counts[name] += 1
                    if short != name: counts[short] += 1
        self._callers = dict(counts)

    def _run(self):
        structure = self.data.get("structure", {}); scores, items = {}, {}
        summary = {"total_elements": 0, "dead_high": 0, "dead_medium": 0, "dead_low": 0, "excluded": 0}
        for fp, data in structure.items():
            fp_scores, fp_items = {}, []
            for cname, cdata in data["classes"].items():
                has_inh = bool(cdata.get("inherits"))
                for m in cdata["methods"]:
                    mn = m["name"] if isinstance(m, dict) else m; mdec = m.get("decorators", []) if isinstance(m, dict) else []
                    s = self._score(mn, mdec, self._callers.get(mn, 0), has_inh); key = f"{cname}.{mn}"
                    fp_scores[key] = s; summary["total_elements"] += 1; self._tally(summary, s)
                    if s > 0: fp_items.append({"name": key, "kind": "method", "class": cname, "score": s, "label": self._lbl(s)})
            for func in data["functions"]:
                fn = func["name"] if isinstance(func, dict) else func; fdec = func.get("decorators", []) if isinstance(func, dict) else []
                s = self._score(fn, fdec, self._callers.get(fn, 0), False)
                fp_scores[fn] = s; summary["total_elements"] += 1; self._tally(summary, s)
                if s > 0: fp_items.append({"name": fn, "kind": "function", "class": None, "score": s, "label": self._lbl(s)})
            scores[fp] = fp_scores; items[fp] = sorted(fp_items, key=lambda x: -x["score"])
        return {"scores": scores, "items": items, "summary": summary}

    def _score(self, name, decs, n_callers, inheriting):
        dec_set = {d.split(".")[-1] for d in decs}
        if dec_set & FRAMEWORK_DECS or set(decs) & FRAMEWORK_DECS: return 0.0
        if name in EXCL_NAMES or name in self.extra: return 0.0
        if name.startswith(EXCL_PREFIXES): return 0.0
        if name.endswith(EXCL_SUFFIXES): return 0.0
        if inheriting and not name.startswith("_"): return 0.0
        if n_callers >= 3: return 0.0
        if n_callers == 0:
            s = 0.60
            if not name.startswith("_"): s += 0.20
            if name.startswith("_") and not name.startswith("__"): s -= 0.15
            return min(s, 1.0)
        return 0.30 if n_callers == 1 else 0.15

    def _lbl(self, s):
        if s >= 0.90: return "dead"
        if s >= 0.70: return "probable"
        if s >= 0.40: return "sospechoso"
        return "bajo"

    def _tally(self, summary, s):
        if s == 0.0: summary["excluded"] += 1
        elif s >= 0.70: summary["dead_high"] += 1
        elif s >= 0.40: summary["dead_medium"] += 1
        else: summary["dead_low"] += 1


class TraceabilityAnalyzer:
    def __init__(self, data): self.data = data

    def get_traceability(self, filepath):
        deps = self.data.get("dependencies", {}); struc = self.data.get("structure", {})
        fd = deps.get(filepath, {}); mods = fd.get("all", []); imap = fd.get("internal_map", {}); sym_used = fd.get("symbols_used", {})
        imports = []
        for m in mods:
            resolved = imap.get(m); symbols = sym_used.get(resolved, []) if resolved else []
            used_classes, used_fns = [], []
            if resolved:
                ts = struc.get(resolved, {"classes": {}, "functions": []})
                cls_names = set(ts["classes"].keys()); fn_names = {(f["name"] if isinstance(f, dict) else f) for f in ts["functions"]}
                for s in symbols:
                    if s in cls_names: used_classes.append(s)
                    elif s in fn_names: used_fns.append(s)
                    else: used_classes.append(s)
            imports.append({"module": m, "is_internal": m in imap, "resolved_path": resolved, "symbols": symbols, "used_classes": used_classes, "used_functions": used_fns})
        imported_by = []
        for ofp, od in deps.items():
            if ofp == filepath: continue
            oimap = od.get("internal_map", {}); osym_used = od.get("symbols_used", {})
            if filepath in oimap.values():
                symbols = osym_used.get(filepath, [])
                ms = struc.get(filepath, {"classes": {}, "functions": []})
                cls_names = set(ms["classes"].keys()); fn_names = {(f["name"] if isinstance(f, dict) else f) for f in ms["functions"]}
                used_cls, used_fns = [], []
                for s in symbols:
                    if s in cls_names: used_cls.append(s)
                    elif s in fn_names: used_fns.append(s)
                    else: used_cls.append(s)
                imported_by.append({"file": ofp, "symbols": symbols, "used_classes": used_cls, "used_functions": used_fns})
        fstruct = struc.get(filepath, {"classes": {}, "functions": []})
        cls_list = [{"name": c, "methods": [m["name"] if isinstance(m, dict) else m for m in d["methods"]], "inherits": d.get("inherits", [])} for c, d in fstruct["classes"].items()]
        fn_list = [f["name"] if isinstance(f, dict) else f for f in fstruct["functions"]]
        return {"filepath": filepath, "filename": os.path.basename(filepath), "downstream": imports, "upstream": imported_by, "imports": imports, "imported_by": imported_by, "classes": cls_list, "functions": fn_list, "impact_direct": len(imported_by), "impact_count": len(imported_by), "transitive_depth": 1 if imported_by else 0}


# ═══════════════════════════════════════════════════════════
# WEB ANALYSIS CORE (HTML / CSS / JS)
# ═══════════════════════════════════════════════════════════

class WebFileParser:
    def parse_html(self, filepath, content):
        r = {"type": "html", "title": "", "scripts": [], "stylesheets": [], "ids": [], "classes": [], "inline_scripts": [], "inline_styles": [], "links": [], "images": [], "custom_elements": [], "forms": []}
        tm = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE|re.DOTALL)
        if tm: r["title"] = re.sub(r"<[^>]+>", "", tm.group(1)).strip()
        r["scripts"] = re.findall(r'<script[^>]+src=[\'"]([^\'"]+)[\'"]', content, re.IGNORECASE)
        ss = re.findall(r'<link[^>]+rel=[\'"]stylesheet[\'"][^>]*href=[\'"]([^\'"]+)[\'"]|<link[^>]+href=[\'"]([^\'"]+)[\'"][^>]*rel=[\'"]stylesheet[\'"]', content, re.IGNORECASE)
        r["stylesheets"] = [s[0] or s[1] for s in ss if s[0] or s[1]]
        r["ids"] = list(set(re.findall(r'\bid=["\']([^"\']+)["\']', content)))
        all_cls = []
        for m in re.finditer(r'\bclass=["\']([^"\']+)["\']', content): all_cls.extend(m.group(1).split())
        r["classes"] = list(set(all_cls))
        hrefs = re.findall(r'<a[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE)
        r["links"] = [h for h in hrefs if not h.startswith(("#", "javascript:", "mailto:"))]
        r["images"] = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
        r["custom_elements"] = list(set(re.findall(r"<([a-z][a-z0-9]*-[a-z0-9-]+)", content, re.IGNORECASE)))
        ijs = re.findall(r"<script(?![^>]+src)[^>]*>(.*?)</script>", content, re.IGNORECASE|re.DOTALL)
        r["inline_scripts"] = [s.strip()[:500] for s in ijs if s.strip()]
        ics = re.findall(r"<style[^>]*>(.*?)</style>", content, re.IGNORECASE|re.DOTALL)
        r["inline_styles"] = [s.strip()[:500] for s in ics if s.strip()]
        for m in re.finditer(r"<form([^>]*)>", content, re.IGNORECASE):
            attrs = m.group(1)
            fid = re.search(r'id=["\']([^"\']+)["\']', attrs); fact = re.search(r'action=["\']([^"\']+)["\']', attrs)
            r["forms"].append({"id": fid.group(1) if fid else None, "action": fact.group(1) if fact else None})
        return r

    def parse_css(self, filepath, content):
        r = {"type": "css", "selectors": [], "id_selectors": [], "class_selectors": [], "element_selectors": [], "variables": [], "imports": [], "media_queries": [], "keyframes": [], "rule_count": 0}
        r["imports"] = re.findall(r'@import\s+["\']([^"\']+)["\']', content)
        r["variables"] = list(set(re.findall(r'(--[a-zA-Z][a-zA-Z0-9-]*)\s*:', content)))
        r["media_queries"] = [m.strip() for m in re.findall(r'@media\s+([^{]+)\{', content)]
        r["keyframes"] = re.findall(r'@keyframes\s+([a-zA-Z0-9_-]+)', content)
        selectors = []
        clean = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        clean = re.sub(r'@[a-z-]+[^{]*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', '', clean)
        for m in re.finditer(r'([^{};@][^{};]*)\{', clean):
            for s in m.group(1).strip().split(","):
                s = s.strip()
                if s and not s.startswith("@"): selectors.append(s)
        r["selectors"] = list(set(selectors))[:100]; r["rule_count"] = len(selectors)
        r["id_selectors"] = [s for s in selectors if "#" in s][:50]
        r["class_selectors"] = [s for s in selectors if "." in s and "#" not in s][:50]
        r["element_selectors"] = [s for s in selectors if not s.startswith((".", "#", "["))][:50]
        return r

    def parse_js(self, filepath, content):
        r = {"type": "js", "functions": [], "classes": [], "exports": [], "imports": [], "event_listeners": [], "dom_queries": [], "variables": [], "fetch_calls": [], "api_endpoints": []}
        es_imps = re.findall(r'import\s+.*?\s+from\s+["\']([^"\']+)["\']', content)
        req_imps = re.findall(r'require\s*\(\s*["\']([^"\']+)["\']\s*\)', content)
        r["imports"] = list(set(es_imps + req_imps))
        r["exports"] = re.findall(r'export\s+(?:default\s+)?(?:class|function|const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', content)
        fns = re.findall(r'(?:function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(|(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))', content)
        r["functions"] = list(set([f[0] or f[1] for f in fns if f[0] or f[1]]))[:60]
        r["classes"] = re.findall(r'class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', content)
        r["variables"] = re.findall(r'^(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)', content, re.MULTILINE)[:40]
        r["event_listeners"] = list(set(re.findall(r'addEventListener\s*\(\s*["\']([^"\']+)["\']', content)))
        found_dom = []
        for pat in ["getElementById","getElementsByClassName","querySelector","querySelectorAll","closest"]:
            for h in re.findall(rf'{pat}\s*\(\s*["\']([^"\']+)["\']', content)[:5]:
                found_dom.append({"method": pat, "selector": h})
        r["dom_queries"] = found_dom[:30]
        r["fetch_calls"] = re.findall(r'fetch\s*\(\s*["\']([^"\']+)["\']', content)[:20]
        r["api_endpoints"] = list(set(re.findall(r'["\'](\/?(?:api|v\d+|graphql)[^"\']{0,80})["\']', content)))[:20]
        return r


class WebDependencyGraphBuilder:
    def __init__(self): self.nodes = {}; self.edges = []

    def build(self, parsed_files):
        for fp, pdata in parsed_files.items():
            ftype = pdata.get("type", "unknown")
            self.nodes[f"file:{fp}"] = {"type": "file", "subtype": ftype, "label": os.path.basename(fp), "path": fp, "icon": {"html": "🌐", "css": "🎨", "js": "⚡"}.get(ftype, "📄")}
        all_bn = {os.path.basename(fp): fp for fp in parsed_files}
        for fp, pdata in parsed_files.items():
            ftype = pdata.get("type", "unknown"); src = f"file:{fp}"
            if ftype == "html":
                for s in pdata.get("scripts", []):
                    t = all_bn.get(os.path.basename(s))
                    if t: self.edges.append({"from": src, "to": f"file:{t}", "relation": "USES_SCRIPT", "label": os.path.basename(s)})
                for c in pdata.get("stylesheets", []):
                    t = all_bn.get(os.path.basename(c))
                    if t: self.edges.append({"from": src, "to": f"file:{t}", "relation": "USES_STYLE", "label": os.path.basename(c)})
                for h in pdata.get("links", []):
                    t = all_bn.get(os.path.basename(h.split("?")[0]))
                    if t: self.edges.append({"from": src, "to": f"file:{t}", "relation": "LINKS_TO", "label": os.path.basename(h)})
            elif ftype == "js":
                for imp in pdata.get("imports", []):
                    bn = os.path.basename(imp)
                    if not bn.endswith((".js", ".mjs", ".ts")): bn += ".js"
                    t = all_bn.get(bn)
                    if t: self.edges.append({"from": src, "to": f"file:{t}", "relation": "IMPORTS", "label": bn})
                for fn in pdata.get("functions", [])[:30]:
                    nid = f"js_fn:{fp}:{fn}"; self.nodes[nid] = {"type": "function", "subtype": "js", "label": fn, "file": fp}
                    self.edges.append({"from": src, "to": nid, "relation": "DEFINES"})
                for cls in pdata.get("classes", [])[:15]:
                    nid = f"js_cls:{fp}:{cls}"; self.nodes[nid] = {"type": "class", "subtype": "js", "label": cls, "file": fp}
                    self.edges.append({"from": src, "to": nid, "relation": "DEFINES"})
            elif ftype == "css":
                for imp in pdata.get("imports", []):
                    t = all_bn.get(os.path.basename(imp))
                    if t: self.edges.append({"from": src, "to": f"file:{t}", "relation": "CSS_IMPORT", "label": os.path.basename(imp)})
                css_cls = {s.lstrip(".") for s in pdata.get("class_selectors", []) if s.startswith(".")}
                css_ids = {s.lstrip("#") for s in pdata.get("id_selectors", []) if s.startswith("#")}
                for ofp, opdata in parsed_files.items():
                    if opdata.get("type") != "html": continue
                    shared_cls = css_cls & set(opdata.get("classes", []))
                    shared_ids = css_ids & set(opdata.get("ids", []))
                    if shared_cls or shared_ids:
                        self.edges.append({"from": src, "to": f"file:{ofp}", "relation": "STYLES", "shared_classes": list(shared_cls)[:10], "shared_ids": list(shared_ids)[:10]})
                for sel in pdata.get("selectors", [])[:20]:
                    nid = f"css_sel:{fp}:{sel}"; self.nodes[nid] = {"type": "selector", "subtype": "css", "label": sel, "file": fp}
                    self.edges.append({"from": src, "to": nid, "relation": "DEFINES"})

    def to_dict(self): return {"nodes": self.nodes, "edges": self.edges}


def run_web_analysis(files):
    parser = WebFileParser(); parsed = {}
    for fp, content in files.items():
        ext = fp.rsplit(".", 1)[-1].lower() if "." in fp else ""
        if ext in ("html", "htm"): parsed[fp] = parser.parse_html(fp, content)
        elif ext == "css": parsed[fp] = parser.parse_css(fp, content)
        elif ext in ("js", "mjs", "ts", "jsx", "tsx"): parsed[fp] = parser.parse_js(fp, content)
    if not parsed: return {"files": [], "parsed": {}, "graph": {"nodes": {}, "edges": []}, "summary": {"total_files": 0, "project_type": "web"}, "project_type": "web"}
    gb = WebDependencyGraphBuilder(); gb.build(parsed); graph = gb.to_dict()
    file_list = []
    for fp in sorted(parsed.keys()):
        pdata = parsed[fp]; ftype = pdata.get("type", "unknown"); base = {"path": fp, "name": os.path.basename(fp), "type": ftype}
        if ftype == "html":
            file_list.append({**base, "title": pdata.get("title",""), "scripts": len(pdata.get("scripts",[])), "stylesheets": len(pdata.get("stylesheets",[])), "ids": len(pdata.get("ids",[])), "classes_count": len(pdata.get("classes",[])), "custom_elements": pdata.get("custom_elements",[]), "forms": len(pdata.get("forms",[])), "links": len(pdata.get("links",[]))})
        elif ftype == "css":
            file_list.append({**base, "rule_count": pdata.get("rule_count",0), "variables": len(pdata.get("variables",[])), "imports": pdata.get("imports",[]), "media_queries": len(pdata.get("media_queries",[])), "keyframes": pdata.get("keyframes",[])})
        elif ftype == "js":
            file_list.append({**base, "functions": pdata.get("functions",[]), "classes": pdata.get("classes",[]), "imports": pdata.get("imports",[]), "exports": pdata.get("exports",[]), "event_listeners": pdata.get("event_listeners",[]), "fetch_calls": pdata.get("fetch_calls",[]), "api_endpoints": pdata.get("api_endpoints",[])})
    return {"files": file_list, "parsed": parsed, "graph": graph, "summary": {"total_files": len(files), "html_files": sum(1 for p in parsed.values() if p.get("type")=="html"), "css_files": sum(1 for p in parsed.values() if p.get("type")=="css"), "js_files": sum(1 for p in parsed.values() if p.get("type")=="js"), "total_nodes": len(graph["nodes"]), "total_edges": len(graph["edges"]), "project_type": "web"}, "project_type": "web"}


# ═══════════════════════════════════════════════════════════
# PYTHON ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

def run_analysis(files):
    parser = ASTParser(); dep_a = FileDependencyAnalyzer(); struct_a = StructureAnalyzer()
    call_a = CallGraphAnalyzer(); gb = DependencyGraphBuilder()
    parsed = parser.parse(files); deps = dep_a.analyze(parsed, known_files=set(files.keys()))
    struct = struct_a.analyze(parsed); calls = call_a.analyze(parsed)
    gb.build(deps, struct, calls); graph = gb.to_dict()
    analysis = {"files": files, "dependencies": deps, "structure": struct, "call_graph": calls, "graph": graph}
    dc = DeadCodeAnalyzer(analysis).analyze()
    file_list = []
    for fp in sorted(files.keys()):
        fs = struct.get(fp, {"classes": {}, "functions": []}); fd = deps.get(fp, {})
        aimps = fd.get("all", []); ints = fd.get("internal", []); exts = fd.get("external", [])
        di = dc["items"].get(fp, [])
        file_list.append({"path": fp, "name": os.path.basename(fp), "type": "python", "classes": list(fs["classes"].keys()), "functions": [f["name"] if isinstance(f, dict) else f for f in fs["functions"]], "imports_total": len(aimps), "imports_internal": len(ints), "imports_external": len(exts), "dead_code_count": len(di), "dead_code_high": sum(1 for d in di if d["score"] >= 0.70)})
    norm_deps = {fp: ({"all": d.get("all",[]), "internal": d.get("internal",[]), "external": d.get("external",[]), "internal_map": d.get("internal_map",{}), "symbols_used": d.get("symbols_used",{})} if isinstance(d, dict) else {"all": d, "internal": [], "external": [], "internal_map": {}, "symbols_used": {}}) for fp, d in deps.items()}
    return {"files": file_list, "structure": struct, "dependencies": norm_deps, "call_graph": calls, "graph": graph, "dead_code": dc, "project_type": "python", "summary": {"total_files": len(files), "total_classes": sum(len(s["classes"]) for s in struct.values()), "total_functions": sum(len(s["functions"]) for s in struct.values()), "total_nodes": len(graph["nodes"]), "total_edges": len(graph["edges"]), "dead_code_summary": dc["summary"], "project_type": "python"}}


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.get("/health")
def health(): return {"status": "healthy", "version": "3.0.0"}

class DumpPayload(BaseModel): content: str

@app.post("/analyze/dump")
async def analyze_dump(payload: DumpPayload, _auth=Depends(require_auth)):
    try:
        files = RepositoryLoader().load_from_dump(payload.content)
        if not files: raise HTTPException(400, "No se encontraron archivos .py en el dump.")
        return JSONResponse(content=run_analysis(files))
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, str(e))

@app.post("/analyze/upload")
async def analyze_upload(files: List[UploadFile] = File(...), _auth=Depends(require_auth)):
    try:
        fd = {}
        for uf in files:
            if uf.filename.endswith(".py"):
                fd[uf.filename.replace("\\", "/")] = (await uf.read()).decode("utf-8", errors="replace")
        if not fd: raise HTTPException(400, "No se encontraron archivos .py validos.")
        return JSONResponse(content=run_analysis(fd))
    except HTTPException: raise
    except Exception as e:
        import traceback as _tb; raise HTTPException(500, f"{type(e).__name__}: {e}\n{_tb.format_exc()}")

@app.post("/analyze/zip")
async def analyze_zip(file: UploadFile = File(...), _auth=Depends(require_auth)):
    try:
        fd = {}
        with zipfile.ZipFile(io.BytesIO(await file.read())) as zf:
            for name in zf.namelist():
                if name.endswith(".py") and not name.startswith("__"):
                    fd[name] = zf.read(name).decode("utf-8", errors="replace")
        if not fd: raise HTTPException(400, "El ZIP no contiene archivos .py.")
        return JSONResponse(content=run_analysis(fd))
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, str(e))

class TraceReq(BaseModel): filepath: str; analysis: dict

@app.post("/traceability")
async def get_traceability(req: TraceReq, _auth=Depends(require_auth)):
    try: return JSONResponse(content=TraceabilityAnalyzer(req.analysis).get_traceability(req.filepath))
    except Exception as e: raise HTTPException(500, str(e))

WEB_EXT = {".html", ".htm", ".css", ".js", ".mjs", ".ts", ".jsx", ".tsx"}

@app.post("/analyze/web-upload")
async def analyze_web_upload(files: List[UploadFile] = File(...), _auth=Depends(require_auth)):
    try:
        fd = {}
        for uf in files:
            ext = "." + uf.filename.rsplit(".", 1)[-1].lower() if "." in uf.filename else ""
            if ext in WEB_EXT:
                fd[uf.filename.replace("\\", "/")] = (await uf.read()).decode("utf-8", errors="replace")
        if not fd: raise HTTPException(400, "No se encontraron archivos web (.html, .css, .js).")
        return JSONResponse(content=run_web_analysis(fd))
    except HTTPException: raise
    except Exception as e:
        import traceback as _tb; raise HTTPException(500, f"{type(e).__name__}: {e}\n{_tb.format_exc()}")

@app.post("/analyze/web-zip")
async def analyze_web_zip(file: UploadFile = File(...), _auth=Depends(require_auth)):
    try:
        fd = {}
        with zipfile.ZipFile(io.BytesIO(await file.read())) as zf:
            for name in zf.namelist():
                if name.startswith(("__MACOSX", ".")): continue
                ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext in WEB_EXT:
                    try: fd[name] = zf.read(name).decode("utf-8", errors="replace")
                    except: pass
        if not fd: raise HTTPException(400, "El ZIP no contiene archivos web.")
        return JSONResponse(content=run_web_analysis(fd))
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, str(e))

@app.post("/analyze/web-dump")
async def analyze_web_dump(payload: DumpPayload, _auth=Depends(require_auth)):
    try:
        files = {}
        pat = re.compile(r"={10,}\s*\nINICIO ARCHIVO:\s*(.+?)\s*\n={10,}\s*\n(.*?)\n={10,}\s*\nFIN ARCHIVO:\s*.+?\s*\n={10,}", re.DOTALL)
        for m in pat.finditer(payload.content):
            path = m.group(1).strip().replace("\\", "/")
            ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in WEB_EXT: files[path] = m.group(2).lstrip("\n")
        if not files: raise HTTPException(400, "No se encontraron archivos web en el dump.")
        return JSONResponse(content=run_web_analysis(files))
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, str(e))

class GroqProxyReq(BaseModel):
    api_key: str; model: str; messages: list; max_tokens: int = 2048; temperature: float = 0.1

@app.post("/api/groq")
async def groq_proxy(req: GroqProxyReq, _auth=Depends(require_auth)):
    import urllib.request, urllib.error, json as _json
    body = {"model": req.model, "messages": req.messages, "max_tokens": req.max_tokens, "temperature": req.temperature, "response_format": {"type": "json_object"}}
    payload = _json.dumps(body).encode("utf-8")
    http_req = urllib.request.Request("https://api.groq.com/openai/v1/chat/completions", data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {req.api_key.strip()}", "Accept": "application/json", "User-Agent": "groq-python/0.13.0"}, method="POST")
    try:
        with urllib.request.urlopen(http_req, timeout=45) as resp:
            return JSONResponse(content=_json.loads(resp.read()))
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        try: msg = _json.loads(body_bytes).get("error", {}).get("message", body_bytes.decode("utf-8", errors="replace"))
        except: msg = body_bytes.decode("utf-8", errors="replace")
        raise HTTPException(e.code, detail=msg)
    except urllib.error.URLError as e: raise HTTPException(502, detail=f"No se pudo contactar Groq: {e.reason}")
    except Exception as e: raise HTTPException(502, detail=str(e))

# ═══════════════════════════════════════════════════════════
# RUNTIME — v4  (Observabilidad cognitiva)
# ═══════════════════════════════════════════════════════════

try:
    from runtime.store          import store      as _store
    from runtime.correlator     import get_correlator, invalidate_correlator
    from runtime.replay         import ReplayEngine, HotPathAnalyzer, CoverageReport, SessionDiff
    from runtime.audit          import AuditBuilder, build_multi_audit
    from runtime.session_export import SessionExporter
    from runtime.models         import (
        FlowEvent as _FlowEvent, ActionType as _ActionType,
        FlowEventIngest as _FlowEventIngest, FlowEventBatch as _FlowEventBatch,
    )
    _RUNTIME_OK = True
except ImportError:
    _RUNTIME_OK = False


# ── Ingest ───────────────────────────────────────────────

class _EventIn(BaseModel):
    flow_id:     str
    node_id:     str
    action:      str
    timestamp_ms: Optional[int] = None
    payload:     dict = {}
    source:      str = "python"

class _BatchIn(BaseModel):
    events: List[_EventIn]


def _ingest_event(ev: _EventIn) -> dict:
    """Procesa y correlaciona un evento entrante."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    try:
        action = _ActionType(ev.action)
    except ValueError:
        action = _ActionType.CUSTOM

    import time as _time
    event = _FlowEvent.create(
        flow_id    = ev.flow_id,
        node_id    = ev.node_id,
        action     = action,
        payload    = ev.payload,
    )
    if ev.timestamp_ms:
        event.timestamp_ms = ev.timestamp_ms

    flow       = _store.get_or_create_flow(ev.flow_id)
    correlator = get_correlator(flow)
    correlator.correlate(event)

    _store.append_event(event)
    return event.to_dict()


@app.post("/flow-events")
async def ingest_event(ev: _EventIn, _auth=Depends(require_auth)):
    """Ingesta de un evento runtime individual."""
    try:
        return JSONResponse(content=_ingest_event(ev))
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, str(e))


@app.post("/flow-events/batch")
async def ingest_batch(batch: _BatchIn, _auth=Depends(require_auth)):
    """Ingesta en batch (usado por el tracker Python y el proxy JS)."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    accepted = 0
    for ev in batch.events[:200]:   # max 200 eventos por batch
        try:
            _ingest_event(ev)
            accepted += 1
        except Exception:
            pass
    return {"accepted": accepted, "total": len(batch.events)}


# ── Flow queries ─────────────────────────────────────────

@app.get("/flows")
async def list_flows(_auth=Depends(require_auth)):
    """Lista todos los flows conocidos."""
    if not _RUNTIME_OK:
        return JSONResponse(content={"flows": [], "runtime": False})
    return JSONResponse(content={"flows": _store.list_flows(), "runtime": True})


@app.get("/flows/{flow_id}")
async def get_flow(flow_id: str, _auth=Depends(require_auth)):
    """
    Devuelve la estructura del flow: grafo estático enriquecido con
    datos de runtime (call_count, error_count, origin, etc.)
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")
    return JSONResponse(content={
        "summary": flow.summary(),
        "nodes":   {nid: n.to_dict() for nid, n in flow.nodes.items()},
        "edges":   [e.to_dict() for e in flow.edges],
        "static_graph": flow.static_graph,
    })


@app.get("/flows/{flow_id}/timeline")
async def get_timeline(
    flow_id:  str,
    from_ms:  Optional[int] = None,
    to_ms:    Optional[int] = None,
    node_ids: Optional[str] = None,   # comma-separated
    actions:  Optional[str] = None,   # comma-separated
    limit:    int = 500,
    _auth = Depends(require_auth),
):
    """
    Devuelve eventos ordenados por timestamp.
    Filtrable por ventana temporal, nodos y tipos de acción.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")

    nids    = node_ids.split(",") if node_ids else None
    acts    = actions.split(",")  if actions  else None
    events  = _store.get_timeline(flow_id, from_ms, to_ms, nids, acts, min(limit, 2000))
    return JSONResponse(content={"flow_id": flow_id, "events": events, "count": len(events)})


@app.get("/flows/{flow_id}/replay")
async def get_replay(
    flow_id:  str,
    from_ms:  Optional[int] = None,
    to_ms:    Optional[int] = None,
    window_ms: int = 3000,
    _auth = Depends(require_auth),
):
    """
    Reconstruye la ejecución paso a paso.
    Devuelve lista de frames {active_nodes, active_edges, event, payload_preview}.
    El frontend usa esto para el slider de timeline y el modo replay.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")

    engine = ReplayEngine(window_ms=window_ms, max_frames=2000)
    frames = engine.build(flow, from_ms=from_ms, to_ms=to_ms)
    return JSONResponse(content={
        "flow_id":    flow_id,
        "frame_count":len(frames),
        "frames":     [f.to_dict() for f in frames],
    })


@app.get("/flows/{flow_id}/live")
async def get_live(flow_id: str, window_ms: int = 5000, _auth=Depends(require_auth)):
    """
    Snapshot del estado live: qué nodos están activos AHORA.
    El frontend hace polling a 1-2s para el modo live.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    import time as _time
    now_ms  = int(_time.time() * 1000)
    active  = _store.get_active_nodes_at(flow_id, now_ms, window_ms)
    return JSONResponse(content={
        "flow_id":     flow_id,
        "now_ms":      now_ms,
        "window_ms":   window_ms,
        "active_nodes":active,
    })


# ── Attach static analysis to a flow ─────────────────────

class _AttachReq(BaseModel):
    flow_id: str
    name:    str = ""

@app.post("/flows/{flow_id}/attach-analysis")
async def attach_analysis(flow_id: str, req: _AttachReq, _auth=Depends(require_auth)):
    """
    Vincula el resultado del análisis estático v3 a un flow runtime.
    Llamar después de /analyze/* para habilitar la correlación.
    Body: el JSON completo devuelto por /analyze/*.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    # El body real viene en el request — aceptamos dict libre
    return JSONResponse(content={"ok": True, "flow_id": flow_id,
                                  "message": "Use POST con el analysis JSON como body."})

@app.post("/flows/{flow_id}/attach")
async def attach_analysis_body(flow_id: str, analysis: dict, _auth=Depends(require_auth)):
    """
    POST /flows/my-project/attach  +  body = resultado de /analyze/*
    Inicializa FlowNodes desde el grafo estático.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.attach_static_analysis(flow_id, analysis)
    invalidate_correlator(flow_id)
    return JSONResponse(content={
        "ok":           True,
        "flow_id":      flow_id,
        "static_nodes": sum(1 for n in flow.nodes.values() if n.origin == "static"),
    })



# ═══════════════════════════════════════════════════════════
# RUNTIME — Fase 2  (replay enriquecido, coverage, export)
# ═══════════════════════════════════════════════════════════

@app.get("/flows/{flow_id}/coverage")
async def get_coverage(flow_id: str, _auth=Depends(require_auth)):
    """
    Reporte de cobertura: qué % del grafo estático fue ejercitado.
    Incluye hot_nodes (top 20 por call_count) y nodos con errores.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")
    report = CoverageReport.build(flow)
    return JSONResponse(content=report.to_dict())


@app.get("/flows/{flow_id}/hot-paths")
async def get_hot_paths(
    flow_id:  str,
    path_len: int = 3,
    top_n:    int = 10,
    window_ms: int = 3000,
    _auth = Depends(require_auth),
):
    """
    Secuencias de nodos más frecuentemente ejecutadas.
    Útil para encontrar el hot path real vs el esperado.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")
    engine   = ReplayEngine(window_ms=window_ms)
    frames   = engine.build(flow)
    analyzer = HotPathAnalyzer(path_len=min(path_len, 5), top_n=min(top_n, 20))
    paths    = analyzer.analyze(frames)
    return JSONResponse(content={"flow_id": flow_id, "hot_paths": paths})


@app.get("/flows/{flow_id}/export")
async def export_session(
    flow_id:       str,
    include_events: bool = True,
    include_frames: bool = True,
    compress:       bool = False,
    _auth = Depends(require_auth),
):
    """
    Exporta la sesión completa como bundle JSON reproducible.
    compress=true → responde con application/gzip (más liviano).
    El bundle incluye grafo estático, eventos, frames, coverage y resumen ejecutivo.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")

    exporter = SessionExporter()
    bundle   = exporter.export(
        flow,
        include_raw_events = include_events,
        include_frames     = include_frames,
    )

    if compress:
        from fastapi.responses import Response
        gz = exporter.to_json_gz(bundle)
        return Response(
            content      = gz,
            media_type   = "application/gzip",
            headers      = {
                "Content-Disposition": f'attachment; filename="{flow_id}_session.json.gz"',
                "Content-Length":      str(len(gz)),
            }
        )
    from fastapi.responses import Response
    json_str = exporter.to_json(bundle)
    return Response(
        content    = json_str,
        media_type = "application/json",
        headers    = {"Content-Disposition": f'attachment; filename="{flow_id}_session.json"'})


@app.get("/flows/{flow_id}/export/jsonl")
async def export_session_jsonl(flow_id: str, _auth=Depends(require_auth)):
    """
    Exporta los eventos como JSONL (una línea por evento).
    Formato eficiente para ingestión en sistemas externos (BigQuery, S3, etc.)
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")
    from fastapi.responses import Response
    exporter = SessionExporter()
    return Response(
        content    = exporter.to_jsonl(flow),
        media_type = "application/x-ndjson",
        headers    = {"Content-Disposition": f'attachment; filename="{flow_id}_events.jsonl"'},
    )


@app.get("/flows/compare/{flow_id_a}/{flow_id_b}")
async def compare_sessions(flow_id_a: str, flow_id_b: str, _auth=Depends(require_auth)):
    """
    Compara dos sesiones del mismo proyecto.
    Devuelve: nodos de nueva cobertura, cobertura perdida, errores nuevos/resueltos.
    Clave para auditorías CAE/DAE ("¿qué cambió?").
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow_a = _store.get_flow(flow_id_a)
    flow_b = _store.get_flow(flow_id_b)
    if not flow_a:
        raise HTTPException(404, f"Flow '{flow_id_a}' no encontrado.")
    if not flow_b:
        raise HTTPException(404, f"Flow '{flow_id_b}' no encontrado.")
    diff = SessionDiff.compare(flow_a, flow_b)
    return JSONResponse(content=diff.to_dict())


@app.post("/flows/import")
async def import_session(bundle: dict, _auth=Depends(require_auth)):
    """
    Importa un bundle exportado previamente.
    Permite reproducir sesiones históricas o de otros entornos.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    try:
        exporter = SessionExporter()
        flow     = SessionExporter.from_bundle(bundle, _store)
        return JSONResponse(content={
            "ok":           True,
            "flow_id":      flow.id,
            "imported_events": len(flow.events),
        })
    except Exception as e:
        raise HTTPException(400, f"Bundle inválido: {e}")


# ═══════════════════════════════════════════════════════════
# AUDIT — Fase 3  (CAE / DAE)
# ═══════════════════════════════════════════════════════════

# ── Projects ─────────────────────────────────────────────

@app.get("/projects")
async def list_projects(_auth=Depends(require_auth)):
    """Lista todos los proyectos con metricas basicas."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    return JSONResponse(content={"projects": _store.list_projects()})


@app.get("/projects/{project_id}/flows")
async def get_project_flows(project_id: str, _auth=Depends(require_auth)):
    """Todos los flows de un proyecto."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flows = _store.get_flows_by_project(project_id)
    return JSONResponse(content={"project_id": project_id, "flows": [f.summary() for f in flows]})


# ── Audit report generation ──────────────────────────────

class _AuditReq(BaseModel):
    audit_type:       str = "CAE"        # "CAE" | "DAE"
    baseline_flow_id: Optional[str] = None
    period_from_ms:   Optional[int] = None
    period_to_ms:     Optional[int] = None

@app.post("/flows/{flow_id}/audit")
async def generate_audit(flow_id: str, req: _AuditReq, _auth=Depends(require_auth)):
    """
    Genera un reporte de auditoria CAE o DAE para un flow.
    CAE — rapido, estatico + coverage basico.
    DAE — profundo, replay completo + comparacion + regresiones.
    Devuelve AuditReport con findings, risk score y evidencia.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")

    audit_type = req.audit_type.upper()
    if audit_type not in ("CAE", "DAE"):
        raise HTTPException(400, "audit_type debe ser CAE o DAE.")

    baseline = None
    if req.baseline_flow_id:
        baseline = _store.get_flow(req.baseline_flow_id)
        if not baseline:
            raise HTTPException(404, f"Flow baseline '{req.baseline_flow_id}' no encontrado.")

    try:
        builder = AuditBuilder()
        report  = builder.build(
            flow,
            audit_type     = audit_type,
            baseline_flow  = baseline,
            period_from_ms = req.period_from_ms,
            period_to_ms   = req.period_to_ms,
        )
        return JSONResponse(content=report.to_dict())
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/audit/multi")
async def multi_audit(
    audit_type:     str = "CAE",
    project_filter: Optional[str] = None,
    from_ms:        Optional[int] = None,
    to_ms:          Optional[int] = None,
    _auth = Depends(require_auth),
):
    """
    Auditoria agregada sobre multiples flows / proyectos.
    Devuelve un reporte consolidado con todos los findings.
    """
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flows = (
        _store.get_flows_by_project(project_filter)
        if project_filter
        else list(_store._flows.values())
    )
    if from_ms or to_ms:
        flows = _store.get_flows_in_window(from_ms or 0, to_ms or int(9e15))
    try:
        result = build_multi_audit(
            flows,
            audit_type     = audit_type.upper(),
            project_filter = project_filter,
            from_ms        = from_ms,
            to_ms          = to_ms,
        )
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(500, str(e))


# ── Audit queries ─────────────────────────────────────────

@app.get("/flows/{flow_id}/errors")
async def get_error_clusters(flow_id: str, _auth=Depends(require_auth)):
    """Agrupa las excepciones por tipo y nodo. Panel de errores de auditoria."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    flow = _store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, f"Flow '{flow_id}' no encontrado.")
    clusters = _store.get_error_clusters(flow_id)
    return JSONResponse(content={"flow_id": flow_id, "clusters": clusters})


@app.get("/flows/{flow_id}/nodes/{node_id}/timeline")
async def get_node_timeline(
    flow_id: str, node_id: str, limit: int = 100, _auth=Depends(require_auth),
):
    """Timeline de eventos de un nodo especifico (calls, returns, exceptions)."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    events = _store.get_node_timeline(flow_id, node_id, limit=limit)
    return JSONResponse(content={"flow_id": flow_id, "node_id": node_id, "events": events})


@app.get("/search/events")
async def search_events(
    q:          str,
    project_id: Optional[str] = None,
    from_ms:    Optional[int] = None,
    to_ms:      Optional[int] = None,
    severity:   Optional[str] = None,
    limit:      int = 100,
    _auth = Depends(require_auth),
):
    """Busqueda full-text en payloads de eventos. severity='error' para solo excepciones."""
    if not _RUNTIME_OK:
        raise HTTPException(501, "Runtime module not available.")
    results = _store.search_events(q, project_id=project_id, from_ms=from_ms,
                                   to_ms=to_ms, severity=severity, limit=min(limit, 500))
    return JSONResponse(content={"query": q, "count": len(results), "results": results})


# ─── SERVE FRONTEND (cloud mode) ─────────────────────────
FRONTEND_DIR = pathlib.Path(__file__).parent.parent / "Frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
