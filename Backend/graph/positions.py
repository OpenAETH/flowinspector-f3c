"""
Conversión de columnas entre backends.

* `ast` y tree-sitter entregan columnas como offset en BYTES UTF-8 dentro de la línea.
* SCIP (Pyright) las entrega en unidades UTF-16 por defecto.

Sin esta conversión, cualquier línea con caracteres no-ASCII antes del símbolo
desalinea el join entre backends. Las líneas se separan como lo hace el
tokenizer de Python (\\n, \\r\\n, \\r), no con `str.splitlines`.
"""

from __future__ import annotations
import re
from typing import List

_NL = re.compile(r"\r\n|\r|\n")


def split_lines(source: str) -> List[bytes]:
    """Líneas del fuente como bytes UTF-8, sin terminadores."""
    return [ln.encode("utf-8", "surrogatepass") for ln in _NL.split(source)]


def byte_col_to_utf16(line_bytes: bytes, byte_col: int) -> int:
    """Offset en bytes UTF-8 -> unidades UTF-16 dentro de la misma línea."""
    if byte_col <= 0:
        return 0
    head = line_bytes[:byte_col]
    if head.isascii():
        return byte_col
    return len(head.decode("utf-8", "ignore").encode("utf-16-le")) // 2


def line_bytes_at(lines: List[bytes], line1: int) -> bytes:
    """Línea 1-based, tolerante a índices fuera de rango."""
    return lines[line1 - 1] if 1 <= line1 <= len(lines) else b""
