"""Informes automáticos de Flow Inspector (deterministas + narrativa IA opcional)."""
from .config import get_models, model_chain, DEFAULT_MODELS
from .builder import build_report
from .diff import make_snapshot, diff_snapshots
from .render import to_markdown, to_html
from .narrative import generate_narrative

__all__ = ["get_models", "model_chain", "DEFAULT_MODELS", "build_report", "make_snapshot",
           "diff_snapshots", "to_markdown", "to_html", "generate_narrative"]
