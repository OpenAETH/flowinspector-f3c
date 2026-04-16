"""
Flow Inspector v4 — Event Store
================================
Almacenamiento append-only de FlowEvent.
Diseño: in-memory durante la sesión + flush a JSONL en disco.

Por qué append-only:
  - Los eventos de runtime son hechos inmutables (algo ocurrió en t)
  - Permite reconstruir cualquier estado histórico
  - Sin locks complejos: solo se escribe al final
  - JSONL = cada línea es un JSON válido → fácil de grep/stream
"""

from __future__ import annotations
import json, os, threading, time
from collections import defaultdict
from typing import Dict, Iterator, List, Optional
from .models import Flow, FlowEvent, FlowNode, FlowEdge, FlowType, ActionType


class EventStore:
    """
    Store central. Un solo EventStore por proceso backend.
    Thread-safe para escrituras concurrentes del sampler.
    """

    def __init__(self, data_dir: str = ".flow_data"):
        self._dir   = data_dir
        self._lock  = threading.Lock()
        self._flows: Dict[str, Flow] = {}
        os.makedirs(data_dir, exist_ok=True)

    # ── Flow management ──────────────────────────────────

    def get_or_create_flow(self, flow_id: str, name: str = "", project_id: str = "") -> Flow:
        with self._lock:
            if flow_id not in self._flows:
                self._flows[flow_id] = Flow(
                    id         = flow_id,
                    project_id = project_id or flow_id,
                    name       = name or flow_id,
                    type       = FlowType.RUNTIME,
                )
            return self._flows[flow_id]

    def get_flow(self, flow_id: str) -> Optional[Flow]:
        return self._flows.get(flow_id)

    def list_flows(self) -> List[dict]:
        return [f.summary() for f in self._flows.values()]

    def attach_static_analysis(self, flow_id: str, analysis: dict) -> Flow:
        """
        Vincula el resultado del análisis estático v3 a un Flow existente
        o lo crea si no existe. Inicializa FlowNodes desde el grafo estático.
        """
        flow = self.get_or_create_flow(flow_id, name=flow_id)
        flow.static_graph = analysis.get("graph")
        flow.type = FlowType.HYBRID

        # Hydrate FlowNodes from static graph
        static_nodes = analysis.get("graph", {}).get("nodes", {})
        with self._lock:
            for nid, ndata in static_nodes.items():
                if nid not in flow.nodes:
                    flow.nodes[nid] = FlowNode.from_static_node(nid, ndata)

            # Hydrate FlowEdges
            for edge in analysis.get("graph", {}).get("edges", []):
                from_id  = edge.get("from", "")
                to_id    = edge.get("to", "")
                rel      = edge.get("relation", "calls")
                etype_map = {
                    "IMPORTS":   "imports",
                    "DEFINES":   "calls",
                    "CALLS":     "calls",
                    "FILE_USES": "file_uses",
                    "USES_SCRIPT":"uses_script",
                    "USES_STYLE":"uses_style",
                    "CSS_IMPORT":"css_import",
                    "LINKS_TO":  "links_to",
                }
                from .models import EdgeType
                try:
                    etype = EdgeType(etype_map.get(rel, "calls"))
                except ValueError:
                    etype = EdgeType.CALLS
                flow.edges.append(FlowEdge(
                    from_id  = from_id,
                    to_id    = to_id,
                    type     = etype,
                    metadata = {k: v for k, v in edge.items()
                                if k not in ("from", "to", "relation")},
                ))
        return flow

    # ── Event ingestion ──────────────────────────────────

    def append_event(self, event: FlowEvent) -> FlowEvent:
        """
        Agrega un evento al store. O(1) amortizado.
        Persiste en JSONL en background.
        """
        flow = self.get_or_create_flow(event.flow_id)

        with self._lock:
            flow.events.append(event)
            self._update_node_stats(flow, event)
            if flow.type == FlowType.STATIC:
                flow.type = FlowType.HYBRID

        # Async flush (fire-and-forget)
        threading.Thread(
            target=self._flush_event,
            args=(event,),
            daemon=True,
        ).start()

        return event

    def append_batch(self, events: List[FlowEvent]) -> int:
        """Ingesta en batch. Devuelve cantidad aceptada."""
        accepted = 0
        for ev in events:
            self.append_event(ev)
            accepted += 1
        return accepted

    # ── Queries ──────────────────────────────────────────

    def get_timeline(
        self,
        flow_id:   str,
        from_ms:   Optional[int] = None,
        to_ms:     Optional[int] = None,
        node_ids:  Optional[List[str]] = None,
        actions:   Optional[List[str]] = None,
        limit:     int = 500,
    ) -> List[dict]:
        """
        Devuelve eventos ordenados por timestamp con filtros opcionales.
        """
        flow = self.get_flow(flow_id)
        if not flow:
            return []

        events = flow.events
        if from_ms:  events = [e for e in events if e.timestamp_ms >= from_ms]
        if to_ms:    events = [e for e in events if e.timestamp_ms <= to_ms]
        if node_ids: events = [e for e in events if e.resolved_node_id in node_ids
                                                  or e.node_id in node_ids]
        if actions:  events = [e for e in events if e.action.value in actions]

        events = sorted(events, key=lambda e: e.timestamp_ms)
        return [e.to_dict() for e in events[:limit]]

    def get_active_nodes_at(self, flow_id: str, timestamp_ms: int, window_ms: int = 5000) -> List[str]:
        """
        Nodos activos en una ventana temporal [t - window, t].
        Usado por el frontend para el modo live.
        """
        flow = self.get_flow(flow_id)
        if not flow: return []
        lo = timestamp_ms - window_ms
        return list({
            e.resolved_node_id or e.node_id
            for e in flow.events
            if lo <= e.timestamp_ms <= timestamp_ms
        })

    # ── Node stats update ────────────────────────────────

    def _update_node_stats(self, flow: Flow, event: FlowEvent) -> None:
        """Actualiza contadores en FlowNode al recibir un evento."""
        nid = event.resolved_node_id or event.node_id
        if nid not in flow.nodes:
            # Nodo dinámico: no estaba en el grafo estático
            from .models import NodeType
            flow.nodes[nid] = FlowNode.dynamic(
                name  = event.payload.get("function_name", nid),
                ntype = NodeType.FUNCTION,
            )
            flow.nodes[nid].id = nid  # preserve the id the correlator assigned
        else:
            if flow.nodes[nid].origin == "static":
                flow.nodes[nid].origin = "both"

        node = flow.nodes[nid]
        node.last_seen_ms = event.timestamp_ms

        if event.action == ActionType.FUNCTION_CALL:
            node.call_count += 1
        elif event.action == ActionType.EXCEPTION:
            node.error_count += 1
        elif event.action == ActionType.FUNCTION_RETURN:
            dur = event.payload.get("duration_ms")
            if dur is not None:
                if node.avg_duration_ms is None:
                    node.avg_duration_ms = float(dur)
                else:
                    # running average (exponential smoothing α=0.3)
                    node.avg_duration_ms = 0.7 * node.avg_duration_ms + 0.3 * dur


    # ── Fase 3: Project & time-window queries ─────────────

    def get_flows_by_project(self, project_id: str) -> List["Flow"]:
        """Devuelve todos los flows de un proyecto."""
        return [f for f in self._flows.values() if f.project_id == project_id]

    def get_flows_in_window(self, from_ms: int, to_ms: int) -> List["Flow"]:
        """Flows que tienen al menos un evento en la ventana temporal."""
        result = []
        for flow in self._flows.values():
            for ev in flow.events:
                if from_ms <= ev.timestamp_ms <= to_ms:
                    result.append(flow)
                    break
        return result

    def list_projects(self) -> List[dict]:
        """Lista todos los proyectos con metricas basicas."""
        from collections import defaultdict as _dd
        projects: dict = {}
        for flow in self._flows.values():
            pid = flow.project_id
            if pid not in projects:
                projects[pid] = {"project_id": pid, "flow_count": 0,
                                  "total_events": 0, "total_errors": 0, "flows": []}
            p = projects[pid]
            p["flow_count"]   += 1
            p["total_events"] += len(flow.events)
            p["total_errors"] += sum(1 for e in flow.events if e.action.value == "exception")
            p["flows"].append(flow.id)
        return list(projects.values())

    def search_events(self, query: str, project_id: Optional[str] = None,
                      from_ms: Optional[int] = None, to_ms: Optional[int] = None,
                      severity: Optional[str] = None, limit: int = 200) -> List[dict]:
        """Full-text search en payloads. severity='error' para solo excepciones."""
        results = []
        target = (self.get_flows_by_project(project_id)
                  if project_id else list(self._flows.values()))
        q = query.lower()
        for flow in target:
            for ev in flow.events:
                if from_ms and ev.timestamp_ms < from_ms: continue
                if to_ms   and ev.timestamp_ms > to_ms:   continue
                if severity == "error" and ev.action.value != "exception": continue
                if q in str(ev.payload).lower() or q in ev.node_id.lower():
                    d = ev.to_dict()
                    d["project_id"] = flow.project_id
                    results.append(d)
                    if len(results) >= limit:
                        return results
        return results

    def get_error_clusters(self, flow_id: str) -> List[dict]:
        """Agrupa excepciones por tipo+nodo. Para el panel de auditoria."""
        flow = self.get_flow(flow_id)
        if not flow: return []
        clusters: dict = {}
        for ev in flow.events:
            if ev.action.value != "exception": continue
            exc_type = (ev.payload or {}).get("exception_type", "UnknownError")
            nid      = ev.resolved_node_id or ev.node_id
            key      = f"{exc_type}:{nid}"
            if key not in clusters:
                clusters[key] = {"exception_type": exc_type, "node_id": nid,
                                  "count": 0, "first_ms": ev.timestamp_ms,
                                  "last_ms": ev.timestamp_ms,
                                  "sample_message": (ev.payload or {}).get("message","")[:200]}
            c = clusters[key]
            c["count"] += 1
            c["last_ms"] = max(c["last_ms"], ev.timestamp_ms)
        return sorted(clusters.values(), key=lambda x: -x["count"])

    def get_node_timeline(self, flow_id: str, node_id: str, limit: int = 100) -> List[dict]:
        """Timeline de eventos para un nodo. Calls, returns y excepciones."""
        flow = self.get_flow(flow_id)
        if not flow: return []
        events = sorted(
            [ev for ev in flow.events if (ev.resolved_node_id or ev.node_id) == node_id],
            key=lambda e: e.timestamp_ms
        )[:limit]
        return [ev.to_dict() for ev in events]

    # ── Persistence ──────────────────────────────────────

    def _flush_event(self, event: FlowEvent) -> None:
        """Escribe un evento en el archivo JSONL del flow."""
        path = os.path.join(self._dir, f"{event.flow_id}.jsonl")
        line = json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass  # store stays in-memory; disk write is best-effort

    def load_from_disk(self, flow_id: str) -> int:
        """
        Carga eventos desde JSONL al iniciar el servidor.
        Devuelve cantidad de eventos cargados.
        """
        path = os.path.join(self._dir, f"{flow_id}.jsonl")
        if not os.path.exists(path):
            return 0

        count = 0
        flow  = self.get_or_create_flow(flow_id)
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    event = FlowEvent(
                        id           = d["id"],
                        flow_id      = d["flow_id"],
                        node_id      = d["node_id"],
                        action       = ActionType(d["action"]),
                        timestamp_ms = d["timestamp_ms"],
                        payload      = d.get("payload", {}),
                        resolved_node_id = d.get("resolved_node_id"),
                    )
                    flow.events.append(event)
                    self._update_node_stats(flow, event)
                    count += 1
                except Exception:
                    continue  # línea corrupta, skip
        return count


# ── Singleton ─────────────────────────────────────────────
# Importar desde aquí en app.py:  from runtime.store import store

store = EventStore(
    data_dir=os.environ.get("FLOW_DATA_DIR", ".flow_data")
)
