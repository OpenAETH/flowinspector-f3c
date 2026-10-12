"""
Flow Inspector — grafo unificado de símbolos (v3.1).

    from graph import analyze_python
    result = analyze_python({"pkg/a.py": "...", ...})
"""

from .unified import UnifiedGraphBuilder, UnifiedGraph, SCHEMA_VERSION  # noqa: F401
from .model import Symbol, Edge, FileFacts  # noqa: F401
