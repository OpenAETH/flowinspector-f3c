"""
Flow Inspector v4 — Runtime Data Models
========================================
Modelo unificado para análisis estático + eventos de runtime.

FlowNode es el punto de unión: los nodos del grafo estático
y los eventos de runtime comparten el mismo id scheme.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from enum import Enum
import time, uuid


# ─── Enums ───────────────────────────────────────────────

class FlowType(str, Enum):
    STATIC  = "static"
    RUNTIME = "runtime"
    HYBRID  = "hybrid"   # has both static structure and runtime events

class NodeType(str, Enum):
    FILE      = "file"
    FUNCTION  = "function"
    CLASS     = "class"
    ENDPOINT  = "endpoint"
    MODULE    = "module"
    SELECTOR  = "selector"     # CSS
    JS_FN     = "js_function"
    JS_CLASS  = "js_class"
    DYNAMIC   = "dynamic"      # created at runtime, not found in static analysis

class EdgeType(str, Enum):
    IMPORTS    = "imports"
    CALLS      = "calls"
    TRIGGERS   = "triggers"
    DEFINES    = "defines"
    FILE_USES  = "file_uses"
    USES_STYLE = "uses_style"
    USES_SCRIPT= "uses_script"
    CSS_IMPORT = "css_import"
    LINKS_TO   = "links_to"

class ActionType(str, Enum):
    FUNCTION_CALL  = "function_call"
    FUNCTION_RETURN= "function_return"
    EXCEPTION      = "exception"
    API_CALL       = "api_call"
    API_RESPONSE   = "api_response"
    EVENT_LISTENER = "event_listener"
    FETCH_CALL     = "fetch_call"
    FETCH_RESPONSE = "fetch_response"
    DOM_QUERY      = "dom_query"
    CUSTOM         = "custom"


# ─── Core entities ───────────────────────────────────────

@dataclass
class FlowNode:
    """
    Punto de unión entre análisis estático y runtime.
    
    id scheme:
      file:path/to/file.py
      function:my_func
      method:MyClass.my_method
      class:MyClass
      endpoint:POST /analyze/upload
      dynamic:<uuid>        ← creado en runtime si no existe estático
    """
    id:       str
    name:     str
    type:     NodeType
    path:     Optional[str]  = None   # archivo fuente
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Runtime enrichment (populated after events arrive)
    call_count:    int   = 0
    error_count:   int   = 0
    last_seen_ms:  Optional[int] = None
    avg_duration_ms: Optional[float] = None
    origin: Literal["static", "runtime", "both"] = "static"

    def is_hot(self, threshold: int = 5) -> bool:
        """Nodo 'caliente': fue llamado al menos N veces en runtime."""
        return self.call_count >= threshold

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "name":           self.name,
            "type":           self.type.value,
            "path":           self.path,
            "metadata":       self.metadata,
            "call_count":     self.call_count,
            "error_count":    self.error_count,
            "last_seen_ms":   self.last_seen_ms,
            "avg_duration_ms":self.avg_duration_ms,
            "origin":         self.origin,
        }

    @classmethod
    def from_static_node(cls, nid: str, static_data: dict) -> "FlowNode":
        """Crea un FlowNode desde un nodo del grafo estático existente."""
        ntype_map = {
            "file":     NodeType.FILE,
            "function": NodeType.FUNCTION,
            "class":    NodeType.CLASS,
            "module":   NodeType.MODULE,
            "selector": NodeType.SELECTOR,
        }
        raw_type = static_data.get("type", "function")
        subtype  = static_data.get("subtype", "")
        if subtype == "js" and raw_type == "function":
            ntype = NodeType.JS_FN
        elif subtype == "js" and raw_type == "class":
            ntype = NodeType.JS_CLASS
        else:
            ntype = ntype_map.get(raw_type, NodeType.FUNCTION)

        return cls(
            id       = nid,
            name     = static_data.get("label", nid.split(":")[-1]),
            type     = ntype,
            path     = static_data.get("path"),
            metadata = {k: v for k, v in static_data.items()
                        if k not in ("id", "label", "type", "path")},
            origin   = "static",
        )

    @classmethod
    def dynamic(cls, name: str, ntype: NodeType = NodeType.DYNAMIC) -> "FlowNode":
        """Crea un nodo dinámico detectado en runtime sin contraparte estática."""
        return cls(
            id     = f"dynamic:{uuid.uuid4().hex[:8]}:{name}",
            name   = name,
            type   = ntype,
            origin = "runtime",
        )


@dataclass
class FlowEdge:
    from_id:  str
    to_id:    str
    type:     EdgeType
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Runtime enrichment
    traversal_count: int = 0
    last_traversed_ms: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "from":              self.from_id,
            "to":                self.to_id,
            "type":              self.type.value,
            "metadata":          self.metadata,
            "traversal_count":   self.traversal_count,
            "last_traversed_ms": self.last_traversed_ms,
        }


@dataclass
class FlowEvent:
    """
    Evento de runtime capturado por @track_flow / JS proxy.
    Append-only — jamás se modifica una vez guardado.
    """
    id:         str
    flow_id:    str
    node_id:    str
    action:     ActionType
    timestamp_ms: int
    payload:    Dict[str, Any] = field(default_factory=dict)

    # Computed fields (set by correlator)
    resolved_node_id: Optional[str] = None   # puede diferir de node_id si se resolvió a un estático

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "flow_id":          self.flow_id,
            "node_id":          self.node_id,
            "action":           self.action.value,
            "timestamp_ms":     self.timestamp_ms,
            "payload":          self.payload,
            "resolved_node_id": self.resolved_node_id,
        }

    @classmethod
    def create(
        cls,
        flow_id:    str,
        node_id:    str,
        action:     ActionType,
        payload:    dict = None,
    ) -> "FlowEvent":
        return cls(
            id           = uuid.uuid4().hex,
            flow_id      = flow_id,
            node_id      = node_id,
            action       = action,
            timestamp_ms = int(time.time() * 1000),
            payload      = payload or {},
        )


@dataclass
class Flow:
    """
    Proyecto analizado. Contiene tanto la estructura estática
    como el log de eventos runtime.
    """
    id:         str
    project_id: str
    name:       str
    type:       FlowType        = FlowType.STATIC
    created_ms: int             = field(default_factory=lambda: int(time.time() * 1000))
    metadata:   Dict[str, Any]  = field(default_factory=dict)

    # Static analysis result (from v3)
    static_graph: Optional[dict] = None   # {nodes, edges} from DependencyGraphBuilder

    # Runtime data
    events:  List[FlowEvent]    = field(default_factory=list)
    nodes:   Dict[str, FlowNode] = field(default_factory=dict)  # id → FlowNode
    edges:   List[FlowEdge]     = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "id":           self.id,
            "project_id":   self.project_id,
            "name":         self.name,
            "type":         self.type.value,
            "created_ms":   self.created_ms,
            "total_nodes":  len(self.nodes),
            "total_edges":  len(self.edges),
            "total_events": len(self.events),
            "static_nodes": sum(1 for n in self.nodes.values() if n.origin == "static"),
            "runtime_nodes":sum(1 for n in self.nodes.values() if n.origin == "runtime"),
            "both_nodes":   sum(1 for n in self.nodes.values() if n.origin == "both"),
        }


# ─── Pydantic schemas for API ────────────────────────────
# (import only when FastAPI is available)

try:
    from pydantic import BaseModel as _BM

    class FlowEventIngest(_BM):
        """Payload que llega a POST /flow-events."""
        flow_id:    str
        node_id:    str                       # nombre/path de la función/archivo
        action:     str                       # ActionType value
        timestamp_ms: Optional[int] = None   # si no viene, se usa server time
        payload:    Dict[str, Any] = {}
        source:     str = "python"            # "python" | "js" | "custom"

    class FlowEventBatch(_BM):
        """Ingesta en batch para reducir HTTP overhead."""
        events: List[FlowEventIngest]

except ImportError:
    pass  # Se usa sin FastAPI (ej: en el decorator standalone)
