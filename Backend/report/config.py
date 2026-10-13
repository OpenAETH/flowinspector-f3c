"""
Modelos de IA configurables (Groq).

  FI_MODELS         lista separada por comas (default: los tres modelos vigentes)
  FI_MODEL_REPORT   modelo preferido para informes (narrativa larga)   default: openai/gpt-oss-120b
  FI_MODEL_CHAT     modelo preferido para el análisis de impacto (UI)  default: qwen/qwen3.8-27b
  FI_MODEL_FAST     modelo preferido para tareas cortas                default: openai/gpt-oss-20b

Un id que no esté en FI_MODELS se ignora, así un modelo retirado nunca rompe el servicio:
la cadena de fallback usa solo lo configurado.
"""
from __future__ import annotations
import os
from typing import List

DEFAULT_MODELS = ["qwen/qwen3.8-27b", "openai/gpt-oss-120b", "openai/gpt-oss-20b"]
_ROLE_DEFAULTS = {"report": "openai/gpt-oss-120b", "chat": "qwen/qwen3.8-27b", "fast": "openai/gpt-oss-20b"}


def get_models() -> List[str]:
    raw = os.environ.get("FI_MODELS", "")
    items = [m.strip() for m in raw.split(",") if m.strip()]
    seen, out = set(), []
    for m in items or DEFAULT_MODELS:
        if m not in seen:
            seen.add(m); out.append(m)
    return out


def role_model(role: str) -> str:
    models = get_models()
    want = os.environ.get(f"FI_MODEL_{role.upper()}", "").strip() or _ROLE_DEFAULTS.get(role, "")
    return want if want in models else models[0]


def model_chain(preferred: str = "", role: str = "report") -> List[str]:
    """Orden de intento: el pedido (si está permitido) o el del rol, y luego el resto."""
    models = get_models()
    first = preferred if preferred in models else role_model(role)
    return [first] + [m for m in models if m != first]


def describe() -> dict:
    return {
        "models": [{"id": m, "label": m.split("/")[-1]} for m in get_models()],
        "roles": {r: role_model(r) for r in _ROLE_DEFAULTS},
    }
