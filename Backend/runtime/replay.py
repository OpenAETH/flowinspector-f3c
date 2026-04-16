"""
Flow Inspector v4 — Replay Engine  v2
========================================
Fase 2: call stack, diffs diferenciales, execution trails,
paths animados, hot path analysis y coverage report.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from .models import Flow, FlowEvent, ActionType


# ── FrameDiff ────────────────────────────────────────────

@dataclass
class FrameDiff:
    added_nodes:   List[str]
    removed_nodes: List[str]
    added_edges:   List[dict]
    removed_edges: List[dict]
    stack_delta:   int          # +1 call, -1 return, 0 otros

    def to_dict(self) -> dict:
        return {
            "added_nodes":   self.added_nodes,
            "removed_nodes": self.removed_nodes,
            "added_edges":   self.added_edges,
            "removed_edges": self.removed_edges,
            "stack_delta":   self.stack_delta,
        }


# ── ReplayFrame v2 ───────────────────────────────────────

@dataclass
class ReplayFrame:
    frame:            int
    timestamp_ms:     int
    elapsed_ms:       int
    session_pct:      float
    event:            dict
    active_nodes:     List[str]
    active_edges:     List[dict]
    animated_edges:   List[dict]   # aristas que se acaban de encender
    cumulative_nodes: List[str]
    highlight:        Optional[str]
    payload_preview:  str
    call_stack:       List[str]    # LIFO, más reciente al final
    stack_depth:      int
    execution_path:   List[str]    # últimos N nids recorridos
    diff:             Optional[FrameDiff] = None
    heat:             Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "frame":            self.frame,
            "timestamp_ms":     self.timestamp_ms,
            "elapsed_ms":       self.elapsed_ms,
            "session_pct":      round(self.session_pct, 2),
            "event":            self.event,
            "active_nodes":     self.active_nodes,
            "active_edges":     self.active_edges,
            "animated_edges":   self.animated_edges,
            "cumulative_nodes": self.cumulative_nodes,
            "highlight":        self.highlight,
            "payload_preview":  self.payload_preview,
            "call_stack":       self.call_stack,
            "stack_depth":      self.stack_depth,
            "execution_path":   self.execution_path,
            "diff":             self.diff.to_dict() if self.diff else None,
            "heat":             {k: round(v, 3) for k, v in self.heat.items()},
        }


# ── Call Stack Tracker ───────────────────────────────────

class CallStackTracker:
    def __init__(self):
        self._stack: deque[str] = deque()

    def push(self, nid: str) -> None:
        self._stack.append(nid)

    def pop(self, nid: str) -> None:
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i] == nid:
                del self._stack[i]
                return

    def current(self) -> List[str]:
        return list(self._stack)

    def depth(self) -> int:
        return len(self._stack)


# ── Replay Engine v2 ─────────────────────────────────────

class ReplayEngine:
    """
    window_ms  — ms hacia atrás para active_nodes (default 3000)
    max_frames — límite de frames por sesión
    trail_len  — longitud del execution_path visible
    """

    def __init__(self, window_ms: int = 3000, max_frames: int = 2000, trail_len: int = 20):
        self.window_ms  = window_ms
        self.max_frames = max_frames
        self.trail_len  = trail_len

    def build(self, flow: Flow, from_ms: Optional[int] = None, to_ms: Optional[int] = None) -> List[ReplayFrame]:
        events = sorted(flow.events, key=lambda e: e.timestamp_ms)
        if from_ms: events = [e for e in events if e.timestamp_ms >= from_ms]
        if to_ms:   events = [e for e in events if e.timestamp_ms <= to_ms]
        events = events[:self.max_frames]
        if not events:
            return []

        t_start = events[0].timestamp_ms
        t_span  = max(events[-1].timestamp_ms - t_start, 1)

        # Build edge lookup from flow
        edge_map: Dict[str, dict] = {}
        for e in flow.edges:
            key = f"{e.from_id}→{e.to_id}"
            edge_map[key] = {
                "from":            e.from_id,
                "to":              e.to_id,
                "type":            e.type.value,
                "traversal_count": e.traversal_count,
            }

        call_counts: Dict[str, int]   = defaultdict(int)
        call_tracker   = CallStackTracker()
        cumulative:    Set[str]       = set()
        trail: deque[str]             = deque(maxlen=self.trail_len)
        frames: List[ReplayFrame]     = []
        prev_active:   Set[str]       = set()
        prev_edge_keys: Set[str]      = set()

        for i, event in enumerate(events):
            nid    = event.resolved_node_id or event.node_id
            action = event.action

            if action == ActionType.FUNCTION_CALL:
                call_tracker.push(nid)
                call_counts[nid] += 1
            elif action == ActionType.FUNCTION_RETURN:
                call_tracker.pop(nid)

            cumulative.add(nid)
            trail.append(nid)

            # Active nodes window
            ws = event.timestamp_ms - self.window_ms
            active_nids = list({
                (e.resolved_node_id or e.node_id)
                for e in events
                if ws <= e.timestamp_ms <= event.timestamp_ms
            })
            active_set = set(active_nids)

            # Active edges
            active_edges = [
                v for k, v in edge_map.items()
                if v["from"] in active_set and v["to"] in active_set
            ]
            cur_edge_keys = {f"{e['from']}→{e['to']}" for e in active_edges}

            # Animated edges: newly active this frame
            animated_edges = [
                v for k, v in edge_map.items()
                if k in (cur_edge_keys - prev_edge_keys)
            ]

            # Inferred call edge from payload (caller → callee)
            caller_raw = (event.payload or {}).get("caller")
            if action == ActionType.FUNCTION_CALL and caller_raw:
                caller_id = self._resolve(caller_raw, flow)
                inf_key = f"{caller_id}→{nid}"
                if inf_key not in edge_map:
                    animated_edges.append({
                        "from": caller_id, "to": nid,
                        "type": "calls", "traversal_count": 1, "inferred": True,
                    })

            # Diff
            diff = FrameDiff(
                added_nodes   = list(active_set - prev_active),
                removed_nodes = list(prev_active - active_set),
                added_edges   = [v for k, v in edge_map.items() if k in (cur_edge_keys - prev_edge_keys)],
                removed_edges = [v for k, v in edge_map.items() if k in (prev_edge_keys - cur_edge_keys)],
                stack_delta   = 1 if action == ActionType.FUNCTION_CALL else
                               -1 if action == ActionType.FUNCTION_RETURN else 0,
            )

            # Heat map
            max_c = max(call_counts.values()) if call_counts else 1
            heat = {nid_: round(c / max_c, 3) for nid_, c in call_counts.items()}

            frames.append(ReplayFrame(
                frame            = i,
                timestamp_ms     = event.timestamp_ms,
                elapsed_ms       = event.timestamp_ms - t_start,
                session_pct      = 100 * (event.timestamp_ms - t_start) / t_span,
                event            = event.to_dict(),
                active_nodes     = active_nids,
                active_edges     = active_edges,
                animated_edges   = animated_edges,
                cumulative_nodes = list(cumulative),
                highlight        = nid,
                payload_preview  = self._preview(event),
                call_stack       = call_tracker.current(),
                stack_depth      = call_tracker.depth(),
                execution_path   = list(trail),
                diff             = diff,
                heat             = heat,
            ))

            prev_active    = active_set
            prev_edge_keys = cur_edge_keys

        return frames

    def _resolve(self, raw: str, flow: Flow) -> str:
        fn_id = f"function:{raw}"
        if fn_id in flow.nodes:
            return fn_id
        for nid in flow.nodes:
            if nid.endswith(f":{raw}") or nid.endswith(f".{raw}"):
                return nid
        return f"unknown:{raw}"

    def _preview(self, event: FlowEvent) -> str:
        p = event.payload or {}
        a = event.action.value
        if a == "function_call":
            fn = p.get("function_name", event.node_id)
            args = p.get("args_preview", "")
            return f"{fn}({args})" if args else f"{fn}()"
        if a == "function_return":
            fn = p.get("function_name", event.node_id)
            s = f"← {fn}"
            ret = p.get("return_preview", "")
            dur = p.get("duration_ms")
            if ret: s += f" → {ret}"
            if dur is not None: s += f"  [{dur:.1f}ms]"
            return s
        if a == "exception":
            return f"✕ {p.get('exception_type','Exception')}: {p.get('message','')[:60]}"
        if a in ("api_call", "fetch_call"):
            return f"{p.get('method','GET')} {p.get('url', p.get('endpoint',''))}"
        if a == "api_response":
            s = f"HTTP {p.get('status_code','?')}"
            dur = p.get("duration_ms")
            if dur is not None: s += f"  [{dur:.1f}ms]"
            return s
        if a == "event_listener":
            return f"on:{p.get('event_type','')} {p.get('selector','')}"
        return f"{a}  {str(p)[:60]}"

    def get_frame(self, frames: List[ReplayFrame], idx: int) -> Optional[ReplayFrame]:
        if 0 <= idx < len(frames): return frames[idx]
        return None

    def get_frame_at_time(self, frames: List[ReplayFrame], ts: int) -> Optional[ReplayFrame]:
        if not frames: return None
        return min(frames, key=lambda f: abs(f.timestamp_ms - ts))


# ── Hot Path Analyzer ─────────────────────────────────────

class HotPathAnalyzer:
    """
    Ventana deslizante sobre execution_path para detectar
    secuencias de nodos recurrentes.
    """
    def __init__(self, path_len: int = 3, top_n: int = 10):
        self.path_len = path_len
        self.top_n    = top_n

    def analyze(self, frames: List[ReplayFrame]) -> List[dict]:
        counts: Dict[Tuple[str, ...], int] = defaultdict(int)
        for frame in frames:
            trail = frame.execution_path
            for j in range(len(trail) - self.path_len + 1):
                counts[tuple(trail[j: j + self.path_len])] += 1
        sorted_paths = sorted(counts.items(), key=lambda x: -x[1])
        total = max(len(frames), 1)
        return [
            {"path": list(p), "count": c, "pct": round(100 * c / total, 1)}
            for p, c in sorted_paths[: self.top_n]
        ]


# ── Coverage Report ───────────────────────────────────────

@dataclass
class CoverageReport:
    total_static_nodes: int
    covered_nodes:      int
    uncovered_nodes:    int
    coverage_pct:       float
    covered_node_ids:   List[str]
    uncovered_node_ids: List[str]
    error_nodes:        List[str]
    hot_nodes:          List[dict]   # top 20 por call_count

    def to_dict(self) -> dict:
        return {
            "total_static_nodes": self.total_static_nodes,
            "covered_nodes":      self.covered_nodes,
            "uncovered_nodes":    self.uncovered_nodes,
            "coverage_pct":       round(self.coverage_pct, 1),
            "covered_node_ids":   self.covered_node_ids,
            "uncovered_node_ids": self.uncovered_node_ids,
            "error_nodes":        self.error_nodes,
            "hot_nodes":          self.hot_nodes,
        }

    @classmethod
    def build(cls, flow: Flow) -> "CoverageReport":
        static_ids   = {nid for nid, n in flow.nodes.items() if n.origin in ("static", "both")}
        covered_ids  = {nid for nid, n in flow.nodes.items() if n.call_count > 0 or n.origin == "both"}
        error_ids    = {nid for nid, n in flow.nodes.items() if n.error_count > 0}
        uncovered    = static_ids - covered_ids
        hot = sorted(
            [{"node_id": nid, "name": flow.nodes[nid].name,
              "call_count": flow.nodes[nid].call_count,
              "error_count": flow.nodes[nid].error_count,
              "avg_duration_ms": flow.nodes[nid].avg_duration_ms}
             for nid in covered_ids if nid in flow.nodes],
            key=lambda x: -x["call_count"],
        )[:20]
        return cls(
            total_static_nodes = len(static_ids),
            covered_nodes      = len(covered_ids),
            uncovered_nodes    = len(uncovered),
            coverage_pct       = 100 * len(covered_ids) / max(len(static_ids), 1),
            covered_node_ids   = list(covered_ids),
            uncovered_node_ids = list(uncovered),
            error_nodes        = list(error_ids),
            hot_nodes          = hot,
        )


# ── Session Comparator ────────────────────────────────────

@dataclass
class SessionDiff:
    flow_id_a:      str
    flow_id_b:      str
    new_coverage:   List[str]
    lost_coverage:  List[str]
    new_errors:     List[str]
    fixed_errors:   List[str]
    coverage_delta: float

    def to_dict(self) -> dict:
        return {
            "flow_id_a":      self.flow_id_a,
            "flow_id_b":      self.flow_id_b,
            "new_coverage":   self.new_coverage,
            "lost_coverage":  self.lost_coverage,
            "new_errors":     self.new_errors,
            "fixed_errors":   self.fixed_errors,
            "coverage_delta": round(self.coverage_delta, 1),
        }

    @classmethod
    def compare(cls, flow_a: Flow, flow_b: Flow) -> "SessionDiff":
        cov_a = {nid for nid, n in flow_a.nodes.items() if n.call_count > 0}
        cov_b = {nid for nid, n in flow_b.nodes.items() if n.call_count > 0}
        err_a = {nid for nid, n in flow_a.nodes.items() if n.error_count > 0}
        err_b = {nid for nid, n in flow_b.nodes.items() if n.error_count > 0}
        rep_a = CoverageReport.build(flow_a)
        rep_b = CoverageReport.build(flow_b)
        return cls(
            flow_id_a      = flow_a.id,
            flow_id_b      = flow_b.id,
            new_coverage   = list(cov_b - cov_a),
            lost_coverage  = list(cov_a - cov_b),
            new_errors     = list(err_b - err_a),
            fixed_errors   = list(err_a - err_b),
            coverage_delta = rep_b.coverage_pct - rep_a.coverage_pct,
        )
