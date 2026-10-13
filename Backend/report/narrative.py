"""
Narrativa IA del informe (Groq, API compatible OpenAI) con reintentos, fallback entre modelos y validación.

Principio: la IA solo redacta sobre hechos ya calculados. Se le entrega un resumen compacto del informe
determinista y se descarta cualquier acción/hallazgo que cite archivos que no existan en él. Si todos los
modelos fallan, el informe sale igual (sin narrativa) — nunca bloquea la automatización.
"""
from __future__ import annotations
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from .config import model_chain

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SYSTEM = ("Sos un revisor técnico senior. Recibís métricas YA calculadas de un repositorio y redactás en español, de forma concisa y accionable. "
          "No inventes archivos, símbolos ni números: usá solo lo que está en los datos. Respondé SOLO un objeto JSON con las claves "
          '"resumen" (string, máx. 120 palabras) y "acciones" (lista de 3 a 6 strings; cada una debe nombrar al menos un archivo de los datos).')


def _compact(report: dict) -> dict:
    return {
        "overview": report["overview"], "resolution": report.get("resolution"),
        "hallazgos": [{"sev": f["severity"], "titulo": f["title"], "archivos": [e.get("file") for e in f["evidence"]]} for f in report["findings"][:12]],
        "acoplamiento": report["hotspots"][:6], "mas_llamados": [{k: m[k] for k in ("name", "file", "callers")} for m in report["most_called"][:6]],
        "ciclos": report["import_cycles"][:3],
    }


def _known_files(report: dict) -> set:
    out = set()
    for h in report["hotspots"]:
        out.add(h["file"])
    for f in report["findings"]:
        out.update(e.get("file") for e in f["evidence"] if e.get("file"))
    for m in report["most_called"]:
        out.add(m["file"])
    for c in report["import_cycles"]:
        out.update(c)
    return out


def _strip(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text).strip()
    if not text.startswith("{"):
        i, j = text.find("{"), text.rfind("}")
        if i >= 0 and j > i:
            text = text[i:j + 1]
    return text


def validate(raw: str, report: dict) -> Optional[dict]:
    try:
        data = json.loads(_strip(raw))
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("resumen"), str) or not data["resumen"].strip():
        return None
    acts = [a for a in (data.get("acciones") or []) if isinstance(a, str) and a.strip()]
    known = _known_files(report)
    mentioned = lambda a: [k for k in known if k in a]
    # una acción es válida si cita un archivo conocido; si cita algo con forma de ruta .py desconocido, se descarta
    good = []
    for a in acts:
        paths = re.findall(r"[\w./-]+\.py", a)
        if paths and any(p not in known and not any(p.endswith("/" + k) or k.endswith("/" + p) for k in known) for p in paths):
            continue
        if mentioned(a) or not known:
            good.append(a.strip())
    if not good:
        return None
    return {"resumen": data["resumen"].strip()[:1500], "acciones": good[:6]}


def _post(api_key: str, body: dict, timeout: int):
    req = urllib.request.Request(GROQ_URL, data=json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {api_key.strip()}", "Accept": "application/json",
        "User-Agent": "flowinspector-report/3.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def generate_narrative(report: dict, api_key: str = "", preferred: str = "", *, retries: int = 2, timeout: int = 60,
                       post: Callable = _post, sleep: Callable = time.sleep) -> dict:
    """Devuelve {"narrative": dict|None, "attempts": [...]} (nunca lanza)."""
    api_key = api_key or os.environ.get("GROQ_API_KEY", "")
    attempts = []
    if not api_key:
        return {"narrative": None, "attempts": [{"error": "sin GROQ_API_KEY"}]}
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": json.dumps(_compact(report), ensure_ascii=False)}]
    for model in model_chain(preferred, "report"):
        use_json = True
        for n in range(retries + 1):
            body = {"model": model, "messages": msgs, "temperature": 0.1, "max_tokens": 4096}
            if use_json:
                body["response_format"] = {"type": "json_object"}
            try:
                resp = post(api_key, body, timeout)
                narr = validate(resp["choices"][0]["message"]["content"], report)
                if narr:
                    narr["model"] = model
                    attempts.append({"model": model, "ok": True})
                    return {"narrative": narr, "attempts": attempts}
                attempts.append({"model": model, "error": "respuesta inválida o con datos no verificables"})
                break                                 # mismo modelo no mejora: pasar al siguiente
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")[:200]
                except Exception:
                    pass
                attempts.append({"model": model, "error": f"HTTP {e.code}", "detail": detail})
                if e.code == 400 and use_json:
                    use_json = False; continue        # el modelo no admite response_format
                if e.code in (401, 403):
                    return {"narrative": None, "attempts": attempts}   # clave inválida: no insistir
                if e.code in (429, 500, 502, 503, 504) and n < retries:
                    sleep(min(20, 2 ** (n + 1))); continue
                break                                  # 404 (modelo retirado) u otros: siguiente modelo
            except Exception as e:
                attempts.append({"model": model, "error": f"{type(e).__name__}: {e}"[:200]})
                if n < retries:
                    sleep(2 ** n); continue
                break
    return {"narrative": None, "attempts": attempts}
