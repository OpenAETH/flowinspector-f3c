"""
Lector mínimo de índices SCIP (https://github.com/sourcegraph/scip, `scip.proto`).

Decodifica directamente el wire format de protobuf para los pocos campos que
necesitamos, evitando agregar `protobuf` como dependencia. Números de campo
verificados contra scip.proto:

    Index       : metadata=1, documents=2, external_symbols=3
    Document    : relative_path=1, occurrences=2, symbols=3, language=4, position_encoding=6
    Occurrence  : range=1 (packed), symbol=2, symbol_roles=3, enclosing_range=7,
                  single_line_range=8, multi_line_range=9
    SymbolInfo  : symbol=1, documentation=3, relationships=4, kind=5
    SymbolRole  : Definition=0x1, Import=0x2, WriteAccess=0x4, ReadAccess=0x8, ForwardDefinition=0x40
    PositionEncoding: UTF8=1, UTF16=2, UTF32=3
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

ROLE_DEFINITION = 0x1
ROLE_IMPORT = 0x2
ROLE_FORWARD_DEF = 0x40

ENC_UNSPECIFIED, ENC_UTF8, ENC_UTF16, ENC_UTF32 = 0, 1, 2, 3


class ScipFormatError(ValueError):
    pass


def _varint(buf: bytes, i: int) -> Tuple[int, int]:
    shift = res = 0
    while True:
        if i >= len(buf):
            raise ScipFormatError("varint truncado")
        b = buf[i]
        i += 1
        res |= (b & 0x7F) << shift
        if not b & 0x80:
            return res, i
        shift += 7
        if shift > 70:
            raise ScipFormatError("varint demasiado largo")


def _fields(buf: bytes) -> Iterator[Tuple[int, int, object]]:
    """(campo, wire_type, valor); valor es int (wt 0/1/5) o bytes (wt 2)."""
    i, n = 0, len(buf)
    while i < n:
        key, i = _varint(buf, i)
        fno, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(buf, i)
            yield fno, wt, v
        elif wt == 2:
            ln, i = _varint(buf, i)
            if i + ln > n:
                raise ScipFormatError("campo length-delimited truncado")
            yield fno, wt, buf[i:i + ln]
            i += ln
        elif wt == 1:
            if i + 8 > n:
                raise ScipFormatError("fixed64 truncado")
            yield fno, wt, int.from_bytes(buf[i:i + 8], "little")
            i += 8
        elif wt == 5:
            if i + 4 > n:
                raise ScipFormatError("fixed32 truncado")
            yield fno, wt, int.from_bytes(buf[i:i + 4], "little")
            i += 4
        else:
            raise ScipFormatError(f"wire type no soportado: {wt}")


def _packed_ints(b: bytes) -> List[int]:
    out, i = [], 0
    while i < len(b):
        v, i = _varint(b, i)
        out.append(v if v < (1 << 31) else v - (1 << 32))      # int32 con signo
    return out


@dataclass
class Occurrence:
    start_line: int                 # 0-based
    start_char: int
    end_line: int
    end_char: int
    symbol: str
    roles: int = 0

    @property
    def is_definition(self) -> bool:
        return bool(self.roles & ROLE_DEFINITION)


@dataclass
class ScipDocument:
    path: str
    encoding: int = ENC_UNSPECIFIED
    occurrences: List[Occurrence] = field(default_factory=list)
    symbols: Dict[str, int] = field(default_factory=dict)       # símbolo -> Kind


@dataclass
class ScipIndex:
    tool: str = ""
    tool_version: str = ""
    documents: Dict[str, ScipDocument] = field(default_factory=dict)


def _occurrence(buf: bytes) -> Optional[Occurrence]:
    rng: List[int] = []
    symbol, roles = "", 0
    for fno, wt, v in _fields(buf):
        if fno == 1 and wt == 2:
            rng = _packed_ints(v)
        elif fno == 1 and wt == 0:                              # no empaquetado
            rng.append(v)
        elif fno == 2 and wt == 2:
            symbol = v.decode("utf-8", "replace")
        elif fno == 3 and wt == 0:
            roles = v
        elif fno == 8 and wt == 2:                              # SingleLineRange
            d = {f: x for f, w, x in _fields(v) if w == 0}
            rng = [d.get(1, 0), d.get(2, 0), d.get(3, 0)]
        elif fno == 9 and wt == 2:                              # MultiLineRange
            d = {f: x for f, w, x in _fields(v) if w == 0}
            rng = [d.get(1, 0), d.get(2, 0), d.get(3, 0), d.get(4, 0)]
    if len(rng) == 3:
        return Occurrence(rng[0], rng[1], rng[0], rng[2], symbol, roles)
    if len(rng) == 4:
        return Occurrence(rng[0], rng[1], rng[2], rng[3], symbol, roles)
    return None


def _document(buf: bytes) -> ScipDocument:
    doc = ScipDocument(path="")
    for fno, wt, v in _fields(buf):
        if fno == 1 and wt == 2:
            doc.path = v.decode("utf-8", "replace")
        elif fno == 2 and wt == 2:
            o = _occurrence(v)
            if o is not None:
                doc.occurrences.append(o)
        elif fno == 3 and wt == 2:
            sym, kind = "", 0
            for f2, w2, x in _fields(v):
                if f2 == 1 and w2 == 2:
                    sym = x.decode("utf-8", "replace")
                elif f2 == 5 and w2 == 0:
                    kind = x
            if sym:
                doc.symbols[sym] = kind
        elif fno == 6 and wt == 0:
            doc.encoding = v
    return doc


def parse_index(data: bytes) -> ScipIndex:
    idx = ScipIndex()
    for fno, wt, v in _fields(data):
        if fno == 1 and wt == 2:                                # Metadata
            for f2, w2, x in _fields(v):
                if f2 == 2 and w2 == 2:                         # ToolInfo
                    for f3, w3, y in _fields(x):
                        if f3 == 1 and w3 == 2:
                            idx.tool = y.decode("utf-8", "replace")
                        elif f3 == 2 and w3 == 2:
                            idx.tool_version = y.decode("utf-8", "replace")
        elif fno == 2 and wt == 2:
            d = _document(v)
            if d.path:
                idx.documents[d.path] = d
    return idx
