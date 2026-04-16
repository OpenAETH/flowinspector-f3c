"""
Flow Inspector v4 — Session Export
=====================================
Exporta una sesión completa como bundle JSON reproducible.

El bundle contiene todo lo necesario para:
  1. Reproducir el replay sin el servidor
  2. Enviar como entregable a un cliente de auditoría (CAE/DAE)
  3. Comparar dos sesiones (SessionDiff)
  4. Importar en otra instancia de FlowInspector

Formato de salida:
  {
    "version":    "4.0",
    "exported_at": <iso>,
    "flow":        { ...summary... },
    "static_graph":{ nodes, edges },
    "events":      [ ...FlowEvent.to_dict()... ],
    "frames":      [ ...ReplayFrame.to_dict()... ],
    "coverage":    { ...CoverageReport... },
    "hot_paths":   [ ... ],
    "summary":     { ...executive summary... }
  }
"""

from __future__ import annotations
import json, gzip, datetime
from typing import List, Optional
from .models import Flow
from .replay  import ReplayEngine, HotPathAnalyzer, CoverageReport, ReplayFrame


class SessionExporter:
    """
    Genera bundles de sesión exportables.
    Soporta JSON plano y JSON.GZ comprimido.
    """

    VERSION = "4.0"

    def __init__(
        self,
        window_ms:  int = 3000,
        trail_len:  int = 20,
        max_frames: int = 2000,
    ):
        self._engine   = ReplayEngine(window_ms=window_ms, max_frames=max_frames, trail_len=trail_len)
        self._hot_path = HotPathAnalyzer(path_len=3, top_n=10)

    # ── Main export ──────────────────────────────────────

    def export(
        self,
        flow:        Flow,
        from_ms:     Optional[int] = None,
        to_ms:       Optional[int] = None,
        include_raw_events: bool   = True,
        include_frames:     bool   = True,
    ) -> dict:
        """
        Genera el bundle completo.
        include_raw_events=False → bundle más liviano, sin eventos crudos
        include_frames=False     → omite los frames (útil para auditorías solo con coverage)
        """
        frames   = self._engine.build(flow, from_ms=from_ms, to_ms=to_ms)
        coverage = CoverageReport.build(flow)
        hot      = self._hot_path.analyze(frames) if frames else []

        bundle: dict = {
            "version":      self.VERSION,
            "exported_at":  datetime.datetime.utcnow().isoformat() + "Z",
            "flow":         flow.summary(),
            "static_graph": flow.static_graph or {"nodes": {}, "edges": []},
            "coverage":     coverage.to_dict(),
            "hot_paths":    hot,
            "summary":      self._executive_summary(flow, frames, coverage, hot),
        }

        if include_raw_events:
            bundle["events"] = [e.to_dict() for e in flow.events]

        if include_frames:
            bundle["frames"]      = [f.to_dict() for f in frames]
            bundle["frame_count"] = len(frames)

        return bundle

    # ── Serialization ────────────────────────────────────

    def to_json(self, bundle: dict, indent: int = 2) -> str:
        return json.dumps(bundle, ensure_ascii=False, indent=indent)

    def to_json_gz(self, bundle: dict) -> bytes:
        raw = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return gzip.compress(raw, compresslevel=6)

    def to_jsonl(self, flow: Flow) -> str:
        """
        Exporta los eventos como JSONL (una línea por evento).
        Formato más eficiente para ingestión en sistemas externos.
        """
        lines = []
        for event in sorted(flow.events, key=lambda e: e.timestamp_ms):
            lines.append(json.dumps(event.to_dict(), ensure_ascii=False))
        return "\n".join(lines)

    # ── Executive summary ─────────────────────────────────

    def _executive_summary(
        self,
        flow:     Flow,
        frames:   List[ReplayFrame],
        coverage: CoverageReport,
        hot:      list,
    ) -> dict:
        """
        Resumen ejecutivo legible por humanos.
        Pensado para el entregable de auditorías CAE/DAE.
        """
        events   = flow.events
        total    = len(events)
        errors   = [e for e in events if e.action.value == "exception"]
        api_calls = [e for e in events if e.action.value in ("api_call", "fetch_call")]
        durations = [
            e.payload.get("duration_ms")
            for e in events
            if e.action.value == "function_return"
               and e.payload.get("duration_ms") is not None
        ]

        avg_dur = round(sum(durations) / len(durations), 2) if durations else None
        max_dur = round(max(durations), 2) if durations else None

        # Session duration
        ts_sorted = sorted(e.timestamp_ms for e in events) if events else [0]
        session_ms = ts_sorted[-1] - ts_sorted[0] if len(ts_sorted) > 1 else 0

        # Error rate
        calls = [e for e in events if e.action.value == "function_call"]
        error_rate = round(100 * len(errors) / max(len(calls), 1), 1)

        # Stack depth stats
        max_depth = max((f.stack_depth for f in frames), default=0)

        # Top erroring nodes
        err_by_node: dict = {}
        for e in errors:
            nid = e.resolved_node_id or e.node_id
            err_by_node[nid] = err_by_node.get(nid, 0) + 1
        top_errors = sorted(err_by_node.items(), key=lambda x: -x[1])[:5]

        return {
            "project":           flow.project_id,
            "flow_id":           flow.id,
            "session_duration_ms": session_ms,
            "total_events":      total,
            "total_frames":      len(frames),
            "function_calls":    len(calls),
            "api_calls":         len(api_calls),
            "exceptions":        len(errors),
            "error_rate_pct":    error_rate,
            "coverage_pct":      coverage.coverage_pct,
            "uncovered_nodes":   coverage.uncovered_nodes,
            "max_stack_depth":   max_depth,
            "avg_duration_ms":   avg_dur,
            "max_duration_ms":   max_dur,
            "hot_node":          hot[0]["path"][0] if hot else None,
            "top_error_nodes":   [{"node_id": n, "count": c} for n, c in top_errors],
            "runtime_only_nodes":sum(1 for n in flow.nodes.values() if n.origin == "runtime"),
        }

    # ── Import (load bundle back into store) ─────────────

    @staticmethod
    def from_bundle(bundle: dict, store) -> Flow:
        """
        Carga un bundle exportado de vuelta al store.
        Permite reproducir una sesión sin re-ejecutar el código.
        """
        import time as _t
        from .models import FlowEvent, ActionType, FlowType
        from .correlator import invalidate_correlator

        flow_data = bundle.get("flow", {})
        flow_id   = flow_data.get("id", f"import-{int(_t.time())}")
        name      = flow_data.get("name", flow_id)

        flow = store.get_or_create_flow(flow_id, name=name)
        flow.type = FlowType.HYBRID

        # Attach static graph if present
        static = bundle.get("static_graph")
        if static:
            store.attach_static_analysis(flow_id, {"graph": static})
            invalidate_correlator(flow_id)

        # Load raw events if present (preferred), else reconstruct from frames
        raw_events = bundle.get("events") or []
        if not raw_events:
            raw_events = [
                f["event"] for f in bundle.get("frames", [])
                if f.get("event")
            ]

        imported = 0
        for ev_dict in raw_events:
            try:
                action = ActionType(ev_dict.get("action", "custom"))
            except ValueError:
                action = ActionType.CUSTOM
            event = FlowEvent(
                id               = ev_dict.get("id", ""),
                flow_id          = flow_id,
                node_id          = ev_dict.get("node_id", ""),
                action           = action,
                timestamp_ms     = ev_dict.get("timestamp_ms", 0),
                payload          = ev_dict.get("payload", {}),
                resolved_node_id = ev_dict.get("resolved_node_id"),
            )
            flow.events.append(event)
            store._update_node_stats(flow, event)
            imported += 1

        return flow
