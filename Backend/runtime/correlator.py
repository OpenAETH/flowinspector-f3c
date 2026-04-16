"""
Flow Inspector v4 — Correlator
================================
Resuelve el node_id de un evento runtime contra el catálogo
de nodos del análisis estático.

Estrategia de resolución (en orden de prioridad):
  1. Match exacto de id
  2. Match por nombre de función (function:<name> o method:<cls>.<name>)
  3. Match por basename de archivo (file:<path>)
  4. Match por nombre parcial (sufijo)
  5. Crear nodo dinámico si no se encuentra nada

El correlador también actualiza las aristas:
cuando ve FUNCTION_CALL de A → B, crea/actualiza FlowEdge(A, B, "calls").
"""

from __future__ import annotations
import os, re
from typing import Dict, Optional, Tuple
from .models import Flow, FlowEvent, FlowNode, FlowEdge, FlowType, EdgeType, NodeType, ActionType


class Correlator:
    """
    Stateless — opera sobre un Flow y retorna el resolved_node_id.
    Se instancia una vez y se reutiliza para todos los eventos del flow.
    """

    def __init__(self, flow: Flow):
        self._flow = flow
        self._index = self._build_index(flow)

    def _build_index(self, flow: Flow) -> Dict[str, str]:
        """
        Construye un índice invertido: name/alias → node_id.
        Permite resolución O(1) en el hot path.
        """
        idx: Dict[str, str] = {}
        for nid, node in flow.nodes.items():
            # exact id
            idx[nid] = nid
            # label / name
            lbl = node.name
            if lbl:
                idx[lbl] = nid
                # short name (last segment after ".")
                short = lbl.split(".")[-1]
                if short and short != lbl:
                    idx.setdefault(short, nid)
            # basename for files
            if node.path:
                bn = os.path.basename(node.path)
                idx.setdefault(bn, nid)
                idx.setdefault(bn.rsplit(".", 1)[0], nid)
        return idx

    def refresh_index(self) -> None:
        """Rebuilds index after dynamic nodes are added."""
        self._index = self._build_index(self._flow)

    def resolve(self, raw_node_id: str) -> str:
        """
        Resuelve raw_node_id a un nid del grafo.
        Si no existe, crea un nodo dinámico y lo registra.
        Devuelve el nid resuelto.
        """
        flow = self._flow

        # 1. Exact match
        if raw_node_id in self._index:
            return self._index[raw_node_id]

        # 2. Try common patterns
        # "module.function" or "ClassName.method"
        if "." in raw_node_id:
            cls_part, fn_part = raw_node_id.rsplit(".", 1)
            method_id = f"method:{cls_part}.{fn_part}"
            if method_id in flow.nodes:
                self._index[raw_node_id] = method_id
                return method_id
            fn_id = f"function:{fn_part}"
            if fn_id in flow.nodes:
                self._index[raw_node_id] = fn_id
                return fn_id

        # 3. function: prefix
        fn_id = f"function:{raw_node_id}"
        if fn_id in flow.nodes:
            self._index[raw_node_id] = fn_id
            return fn_id

        # 4. file: prefix — try matching by path suffix
        for nid, node in flow.nodes.items():
            if node.type == NodeType.FILE and node.path:
                if node.path.endswith(raw_node_id) or raw_node_id.endswith(os.path.basename(node.path)):
                    self._index[raw_node_id] = nid
                    return nid

        # 5. Partial suffix match on labels
        candidates = [
            nid for nid, node in flow.nodes.items()
            if node.name and (
                node.name.endswith(raw_node_id)
                or raw_node_id.endswith(node.name)
            )
        ]
        if len(candidates) == 1:
            self._index[raw_node_id] = candidates[0]
            return candidates[0]

        # 6. Create dynamic node
        dyn = FlowNode.dynamic(name=raw_node_id)
        dyn.id = f"dynamic:{raw_node_id}"  # stable id so we can re-resolve
        flow.nodes[dyn.id] = dyn
        self._index[raw_node_id] = dyn.id
        self._index[dyn.id]      = dyn.id
        return dyn.id

    def correlate(self, event: FlowEvent) -> FlowEvent:
        """
        Resuelve el node_id del evento y actualiza la arista si corresponde.
        Modifica el evento in-place (sets resolved_node_id).
        """
        resolved = self.resolve(event.node_id)
        event.resolved_node_id = resolved

        # Update traversal edge: FUNCTION_CALL caller → callee
        if event.action == ActionType.FUNCTION_CALL:
            caller_raw = event.payload.get("caller")
            if caller_raw:
                caller_id = self.resolve(caller_raw)
                self._upsert_edge(caller_id, resolved, EdgeType.CALLS)

        # API_CALL: function → endpoint
        if event.action == ActionType.API_CALL:
            endpoint = event.payload.get("endpoint", "")
            if endpoint:
                ep_id = self._ensure_endpoint_node(endpoint, event.payload.get("method", "GET"))
                self._upsert_edge(resolved, ep_id, EdgeType.TRIGGERS)

        return event

    def _upsert_edge(self, from_id: str, to_id: str, etype: EdgeType) -> None:
        flow = self._flow
        for edge in flow.edges:
            if edge.from_id == from_id and edge.to_id == to_id and edge.type == etype:
                edge.traversal_count += 1
                import time as _t
                edge.last_traversed_ms = int(_t.time() * 1000)
                return
        import time as _t
        flow.edges.append(FlowEdge(
            from_id            = from_id,
            to_id              = to_id,
            type               = etype,
            traversal_count    = 1,
            last_traversed_ms  = int(_t.time() * 1000),
        ))

    def _ensure_endpoint_node(self, endpoint: str, method: str = "GET") -> str:
        nid = f"endpoint:{method.upper()} {endpoint}"
        if nid not in self._flow.nodes:
            self._flow.nodes[nid] = FlowNode(
                id       = nid,
                name     = f"{method.upper()} {endpoint}",
                type     = NodeType.ENDPOINT,
                origin   = "runtime",
            )
            self._index[nid] = nid
        return nid


# ── Per-flow correlator cache ─────────────────────────────

_correlators: Dict[str, Correlator] = {}

def get_correlator(flow: Flow) -> Correlator:
    """Devuelve el correlator del flow, creándolo si no existe."""
    if flow.id not in _correlators:
        _correlators[flow.id] = Correlator(flow)
    return _correlators[flow.id]

def invalidate_correlator(flow_id: str) -> None:
    """Llama esto cuando se adjunta un nuevo análisis estático al flow."""
    _correlators.pop(flow_id, None)
