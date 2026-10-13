"""
Índice de módulos del proyecto y resolución de imports.

Reemplaza el criterio histórico (`basename(archivo) == nombre de módulo`), que
colisionaba cuando había dos `util.py`, ignoraba el nivel de los imports
relativos (`from .util import x`) y trataba como externos los paquetes propios.

Estrategia, de más a menos confiable:
  1. relativo  : aritmética de rutas desde el archivo importador (`from ..a import b`)
  2. raíz      : `a.b.c` exacto respecto de una raíz de paquete inferida
  3. hermano   : módulo en el mismo directorio que el importador (semántica de script)
  4. sufijo    : el path termina en `a/b/c` (carpeta contenedora de un zip, layouts raros)

Nada de esto toca el filesystem: opera solo sobre el conjunto de paths recibido.
"""

from __future__ import annotations
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .model import CONF_HIGH, CONF_MEDIUM, CONF_LOW

_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | {"__future__"}


def _dirname(p: str) -> str:
    return p.rsplit("/", 1)[0] if "/" in p else ""


def _join(*parts: str) -> str:
    return "/".join(x for x in parts if x)


@dataclass
class ModuleRes:
    kind: str                       # file | namespace | external
    file: Optional[str] = None
    modname: str = ""               # dotted resuelto (interno) o pedido (externo)
    how: str = ""                   # relative | root | sibling | suffix | external
    confidence: str = CONF_HIGH
    ambiguous: bool = False
    candidates: List[str] = field(default_factory=list)
    external_kind: str = ""         # stdlib | third_party

    @property
    def internal(self) -> bool:
        return self.kind != "external"


class ModuleIndex:
    def __init__(self, paths: Iterable[str]):
        self.paths: List[str] = sorted(set(paths))
        self.pathset: Set[str] = set(self.paths)
        self.dirs: Set[str] = set()
        for p in self.paths:
            d = _dirname(p)
            while True:
                self.dirs.add(d)
                if not d:
                    break
                d = _dirname(d)
        init_dirs = {_dirname(p) for p in self.paths if p.rsplit("/", 1)[-1] == "__init__.py"}
        roots: Set[str] = set()
        for d in init_dirs:
            if _dirname(d) not in init_dirs:           # paquete de nivel superior
                roots.add(_dirname(d))
        for p in self.paths:                           # scripts sueltos: su directorio es raíz
            d = _dirname(p)
            if not any(self._under(d, r) for r in roots):
                roots.add(d)
        self.roots: List[str] = sorted(roots, key=lambda r: (-len(r), r))
        self.mod_of: Dict[str, Tuple[str, bool]] = {}
        self.exact: Dict[Tuple[str, str], str] = {}    # (raíz, dotted) -> archivo
        for p in self.paths:
            root = self._root_of(p)
            name, is_pkg = self._modname(p, root)
            self.mod_of[p] = (name, is_pkg)
            self.exact[(root, name)] = p
        self.suffix: Dict[str, List[str]] = {}
        for p in self.paths:
            parts = self._parts(p)
            for i in range(len(parts)):
                self.suffix.setdefault(".".join(parts[i:]), []).append(p)

    # ── construcción ─────────────────────────────────
    @staticmethod
    def _under(d: str, root: str) -> bool:
        return root == "" or d == root or d.startswith(root + "/")

    def _root_of(self, path: str) -> str:
        d = _dirname(path)
        for r in self.roots:                            # ya ordenadas de más profunda a menos
            if self._under(d, r):
                return r
        return ""

    @staticmethod
    def _parts(path: str) -> List[str]:
        parts = path[:-3].split("/") if path.endswith(".py") else path.split("/")
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        return parts

    def _modname(self, path: str, root: str) -> Tuple[str, bool]:
        rel = path[len(root) + 1:] if root else path
        is_pkg = rel.endswith("__init__.py")
        parts = self._parts(rel)
        return ".".join(parts), is_pkg

    def module_of(self, path: str) -> Tuple[str, bool]:
        hit = self.mod_of.get(path)
        if hit is not None:
            return hit
        parts = self._parts(path) if path else []
        return (parts[-1] if parts else "", False)

    # ── resolución ───────────────────────────────────
    def _file_or_ns(self, base_dir: str, parts: List[str]) -> Optional[Tuple[str, Optional[str]]]:
        """('file', ruta) | ('namespace', None) | None para base_dir/parts."""
        target = _join(base_dir, *parts)
        if not parts:
            init = _join(base_dir, "__init__.py")
            if init in self.pathset:
                return ("file", init)
            return ("namespace", None) if base_dir in self.dirs else None
        if target + ".py" in self.pathset:
            return ("file", target + ".py")
        init = target + "/__init__.py"
        if init in self.pathset:
            return ("file", init)
        if target in self.dirs:
            return ("namespace", None)
        return None

    def resolve(self, dotted: str, level: int, from_file: str, strict: bool = False) -> ModuleRes:
        """
        Resuelve `dotted` (sin puntos iniciales) importado desde `from_file`.
        `strict=True` solo admite resolución relativa o exacta por raíz (se usa
        para decidir si `from m import n` importa un submódulo `m.n`).
        """
        parts = [p for p in dotted.split(".") if p] if dotted else []
        if level > 0:
            base = _dirname(from_file)
            for _ in range(level - 1):
                if not base:
                    return self._external(dotted, level)
                base = _dirname(base)
            hit = self._file_or_ns(base, parts)
            if hit is None:
                return self._external(dotted, level)
            return self._mk(hit, dotted, "relative", CONF_HIGH)
        if not parts:
            return self._external(dotted, 0)

        top = parts[0]
        stdlib = top in _STDLIB
        importer_root = self._root_of(from_file)
        # candidato = (score, distancia, vía, clave de identidad, hit); mayor score y menor distancia ganan
        cands: List[Tuple[int, int, str, str, Tuple[str, Optional[str]]]] = []

        for r in self.roots:
            if stdlib and r != "":
                continue            # un `logging.py` dentro de una subcarpeta no oculta a la stdlib
            hit = self._file_or_ns(r, parts)
            if hit is not None:
                score = 3 if r == importer_root else 2
                key = hit[1] or _join(r, *parts)
                cands.append((score, self._distance(from_file, key), "root", key, hit))
        if not strict and not stdlib:
            hit = self._file_or_ns(_dirname(from_file), parts)
            if hit is not None:
                key = hit[1] or _join(_dirname(from_file), *parts)
                cands.append((2, 0, "sibling", key, hit))
            for fp in self.suffix.get(dotted, []):
                cands.append((1, self._distance(from_file, fp), "suffix", fp, ("file", fp)))
        if not cands:
            return self._external(dotted, 0)

        best = max(c[0] for c in cands)
        # un mismo destino alcanzado por dos vías (p.ej. raíz y sufijo) no es ambigüedad
        uniq: Dict[str, tuple] = {}
        for c in sorted((c for c in cands if c[0] == best), key=lambda c: (c[1], c[3])):
            uniq.setdefault(c[3], c)
        ranked = sorted(uniq.values(), key=lambda c: (c[1], c[3]))
        chosen = ranked[0]
        ambiguous = len(ranked) > 1 and ranked[0][1] == ranked[1][1]
        conf = CONF_HIGH if best == 3 else (CONF_MEDIUM if best >= 1 else CONF_LOW)
        if ambiguous:
            conf = CONF_LOW
        res = self._mk(chosen[4], dotted, chosen[2], conf)
        res.ambiguous = ambiguous
        res.candidates = [c[3] for c in ranked]
        return res

    @staticmethod
    def _distance(a: str, b: str) -> int:
        """Pasos de directorio entre dos paths (menor = más cercano)."""
        pa, pb = _dirname(a).split("/"), _dirname(b).split("/")
        i = 0
        while i < min(len(pa), len(pb)) and pa[i] == pb[i]:
            i += 1
        return (len(pa) - i) + (len(pb) - i)

    def _mk(self, hit, dotted: str, how: str, conf: str) -> ModuleRes:
        kind, path = hit
        if kind == "file":
            name, _ = self.module_of(path)
            return ModuleRes("file", path, name, how, conf)
        return ModuleRes("namespace", None, dotted, how, conf)

    def _external(self, dotted: str, level: int) -> ModuleRes:
        top = dotted.split(".")[0] if dotted else ""
        ek = "stdlib" if top in _STDLIB else "third_party"
        return ModuleRes("external", None, ("." * level) + dotted, "external", CONF_HIGH, external_kind=ek)
