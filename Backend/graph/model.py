"""
Flow Inspector — modelo del grafo unificado
===========================================
Estructuras neutrales respecto del backend de parseo (ast, tree-sitter, SCIP).
Todos los backends producen `FileFacts`; el resolver las convierte en `Edge`
con identidades de símbolo calificadas por archivo (`uid`).

Formato de `uid` (estable y sin colisiones entre archivos):

    py:<archivo>::<qualname>         clase / función / método
    py:<archivo>::<qualname>#2       redefinición en el mismo scope
    py:<archivo>::<module>           símbolo-módulo (un archivo = un módulo)
    ext:<dotted>                     símbolo externo / no resuelto
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

KIND_MODULE = "module"
KIND_CLASS = "class"
KIND_FUNCTION = "function"
KIND_METHOD = "method"

# Confianza de una arista, de mayor a menor.
CONF_EXACT = "exact"     # confirmada por un resolvedor semántico (SCIP)
CONF_HIGH = "high"       # binding léxico / import resuelto sin ambigüedad
CONF_MEDIUM = "medium"   # inferencia (tipo local, MRO, sufijo de path)
CONF_LOW = "low"         # solo por nombre
CONF_ORDER = {CONF_EXACT: 3, CONF_HIGH: 2, CONF_MEDIUM: 1, CONF_LOW: 0}

REL_IMPORTS = "IMPORTS"
REL_DEFINES = "DEFINES"
REL_CALLS = "CALLS"
REL_INHERITS = "INHERITS"


def module_uid(path: str) -> str:
    return f"py:{path}::<module>"


def make_uid(path: str, qualname: str, ordinal: int = 1) -> str:
    return f"py:{path}::{qualname}" + (f"#{ordinal}" if ordinal > 1 else "")


@dataclass
class Symbol:
    uid: str
    kind: str                       # module | class | function | method
    name: str
    qualname: str                   # Outer.Inner.meth  /  func.inner
    file: str
    module: str                     # nombre dotted del módulo (mejor esfuerzo)
    line: int                       # 1-based, línea del `def`/`class`
    end_line: int
    col: int = 0                    # 0-based (UTF-16)
    name_line: int = 0              # posición del identificador (para joins con SCIP)
    name_col: int = 0
    parent: Optional[str] = None    # uid del símbolo contenedor
    decorators: List[str] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)
    is_async: bool = False
    conditional: bool = False       # definido dentro de if/try/match: puede coexistir con otra def homónima
    sources: List[str] = field(default_factory=list)
    legacy_id: str = ""             # id del esquema histórico (function:x, ...)
    node_id: str = ""               # id usado en graph.nodes (legacy o calificado)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("name_line", None)
        d.pop("name_col", None)
        return d


@dataclass
class ImportBinding:
    file: str
    line: int
    scope: str                      # uid del scope dueño (módulo o función)
    local: str                      # nombre ligado ("np", "uproc", "a" para `import a.b`)
    module: str                     # módulo destino tal como se escribió, sin puntos iniciales
    level: int = 0                  # nivel relativo (cantidad de puntos)
    name: Optional[str] = None      # símbolo importado en `from m import name`
    is_star: bool = False
    bound_top: bool = False         # `import a.b.c` liga solo `a`

    @property
    def written(self) -> str:
        """Módulo como figura en el código: '.util', '..a.b', 'os.path'."""
        return "." * self.level + self.module


@dataclass
class CallSite:
    file: str
    line: int
    col: int
    name_line: int                  # posición del identificador final del callee
    name_col: int
    caller: str                     # uid de la función/método (o módulo) que contiene la llamada
    expr: str                       # "self.process", "models.Handler", "super().run", "?.run"


@dataclass
class FileFacts:
    file: str
    module: str
    is_package: bool
    module_uid: str
    symbols: List[Symbol] = field(default_factory=list)
    imports: List[ImportBinding] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    # scope uid -> {variable: expresión de clase}  (inferencia local muy conservadora)
    local_types: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # clase uid -> {atributo: expresión de clase}  (`self.x = Cls()`)
    attr_types: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # función uid -> nombre del primer parámetro (self/cls)
    self_names: Dict[str, str] = field(default_factory=dict)
    parse_ok: bool = True
    parse_errors: int = 0
    backend: str = "ast"


@dataclass
class Edge:
    src: str
    dst: str
    relation: str
    file: Optional[str] = None
    line: int = 0
    col: int = 0
    confidence: str = CONF_HIGH
    resolved_by: str = ""
    ambiguous: bool = False
    external: bool = False
    expr: str = ""                  # texto del callee / módulo tal como se escribió
    symbols: List[str] = field(default_factory=list)   # nombres importados (IMPORTS)

    def key(self):
        return (self.src, self.dst, self.relation, self.line, self.col)

    def to_dict(self) -> dict:
        d = {k: v for k, v in asdict(self).items()
             if v not in (None, "", [], False) or k in ("src", "dst", "relation", "line")}
        return d
