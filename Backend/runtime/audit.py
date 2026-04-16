"""
Flow Inspector v4 — Audit Engine (Fase 3)
==========================================
Motor de auditoría para los productos CAE (Code Audit Express)
y DAE (Deep Audit Express) de AETHERYON Systems.

Responsabilidades:
  1. AuditReport       — reporte estructurado con hallazgos y métricas
  2. RiskScorer        — scoring de riesgo por nodo y por proyecto
  3. EvidencePackage   — bundle de evidencia firmada para entregables
  4. AuditFilter       — filtros por proyecto, ventana temporal, severity
  5. AuditSummary      — resumen ejecutivo multi-flow (para comparar ejecuciones)

Los reportes CAE son snapshots de análisis estático + runtime ligero.
Los reportes DAE son análisis profundos con replay completo + comparación de sesiones.

Formato de evidencia:
  {
    "audit_id":      "<uuid>",
    "audit_type":    "CAE" | "DAE",
    "project_id":    str,
    "generated_at":  ISO timestamp,
    "period":        { "from": ISO, "to": ISO },
    "findings":      [ AuditFinding ],
    "risk_score":    float 0–100,
    "coverage":      CoverageReport,
    "session_diff":  SessionDiff | null,
    "executive":     AuditSummary,
    "flows_analyzed": int,
    "signature":     str   # hash de contenido para integridad
  }
"""

from __future__ import annotations
import hashlib, datetime, uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from collections import defaultdict


# ═══════════════════════════════════════════════════════════
# Findings
# ═══════════════════════════════════════════════════════════

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class AuditFinding:
    """
    Un hallazgo concreto detectado en el análisis.
    Puede originarse en análisis estático, runtime o comparación.
    """
    id:          str
    severity:    Severity
    category:    str          # "dead_code" | "error_rate" | "hot_path" | "coverage_gap" |
                              # "new_error" | "regression" | "never_called" | "slow_node" | "custom"
    title:       str
    description: str
    node_ids:    List[str] = field(default_factory=list)
    evidence:    Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "severity":    self.severity,
            "category":    self.category,
            "title":       self.title,
            "description": self.description,
            "node_ids":    self.node_ids,
            "evidence":    self.evidence,
            "remediation": self.remediation,
        }


# ═══════════════════════════════════════════════════════════
# Risk Scorer
# ═══════════════════════════════════════════════════════════

class RiskScorer:
    """
    Calcula un score de riesgo 0–100 para un flow.

    Factores:
      - error_rate_pct      (peso 30)
      - coverage_gap_pct    (peso 25)  → 100 - coverage_pct
      - dead_code_density   (peso 20)  → dead_high / total_nodes
      - slow_nodes_pct      (peso 15)  → nodos con avg_duration > threshold
      - regression_penalty  (peso 10)  → si hay new_errors vs sesión anterior
    """

    WEIGHTS = {
        "error_rate":      30,
        "coverage_gap":    25,
        "dead_code":       20,
        "slow_nodes":      15,
        "regression":      10,
    }

    SLOW_THRESHOLD_MS = 500.0  # nodos con avg_duration > 500ms = slow

    def score(
        self,
        flow,                          # Flow object
        coverage_pct: float,
        dead_high_count: int,
        has_regression: bool = False,
    ) -> float:
        total_nodes = max(len(flow.nodes), 1)
        total_events = len(flow.events)
        total_calls  = sum(1 for e in flow.events if e.action.value == "function_call")
        total_errors = sum(1 for e in flow.events if e.action.value == "exception")

        error_rate    = 100 * total_errors / max(total_calls, 1)
        coverage_gap  = 100 - coverage_pct
        dead_density  = 100 * dead_high_count / total_nodes
        slow_count    = sum(
            1 for n in flow.nodes.values()
            if n.avg_duration_ms and n.avg_duration_ms > self.SLOW_THRESHOLD_MS
        )
        slow_pct = 100 * slow_count / total_nodes
        regression_v = 100 if has_regression else 0

        raw = (
            self.WEIGHTS["error_rate"]   * min(error_rate,   100) / 100 +
            self.WEIGHTS["coverage_gap"] * min(coverage_gap, 100) / 100 +
            self.WEIGHTS["dead_code"]    * min(dead_density, 100) / 100 +
            self.WEIGHTS["slow_nodes"]   * min(slow_pct,     100) / 100 +
            self.WEIGHTS["regression"]   * min(regression_v, 100) / 100
        )
        return round(raw, 1)

    def grade(self, score: float) -> str:
        if score < 20:  return "A"
        if score < 35:  return "B"
        if score < 50:  return "C"
        if score < 65:  return "D"
        return "F"

    def label(self, score: float) -> str:
        if score < 20:  return "Bajo riesgo"
        if score < 35:  return "Riesgo moderado"
        if score < 50:  return "Riesgo elevado"
        if score < 65:  return "Riesgo alto"
        return "Riesgo crítico"


# ═══════════════════════════════════════════════════════════
# Finding Generators
# ═══════════════════════════════════════════════════════════

def _gen_findings(flow, coverage, has_regression: bool = False, baseline_flow=None) -> List[AuditFinding]:
    """
    Genera hallazgos automáticamente a partir del estado del flow.
    """
    findings: List[AuditFinding] = []
    fid = lambda: uuid.uuid4().hex[:8]

    # ── Error rate ─────────────────────────────────────────
    total_calls  = sum(1 for e in flow.events if e.action.value == "function_call")
    total_errors = sum(1 for e in flow.events if e.action.value == "exception")
    error_rate   = 100 * total_errors / max(total_calls, 1)

    if error_rate >= 10:
        sev = "critical" if error_rate >= 25 else "high" if error_rate >= 10 else "medium"
        # Group errors by node
        err_by_node: Dict[str, int] = defaultdict(int)
        for e in flow.events:
            if e.action.value == "exception":
                err_by_node[e.resolved_node_id or e.node_id] += 1
        top_err = sorted(err_by_node.items(), key=lambda x: -x[1])[:5]
        findings.append(AuditFinding(
            id          = fid(),
            severity    = sev,
            category    = "error_rate",
            title       = f"Tasa de error elevada: {error_rate:.1f}%",
            description = (
                f"Se detectaron {total_errors} excepciones de {total_calls} llamadas "
                f"({error_rate:.1f}%). Los nodos con más errores son: "
                + ", ".join(f"{n} ({c}x)" for n, c in top_err[:3]) + "."
            ),
            node_ids    = [n for n, _ in top_err],
            evidence    = {"error_rate_pct": error_rate, "top_errors": dict(top_err)},
            remediation = "Revisar manejo de excepciones en los nodos identificados. "
                          "Agregar try/catch con logging apropiado.",
        ))

    # ── Coverage gap ──────────────────────────────────────
    gap_pct = 100 - coverage.coverage_pct
    if gap_pct > 40:
        sev = "high" if gap_pct > 60 else "medium"
        findings.append(AuditFinding(
            id          = fid(),
            severity    = sev,
            category    = "coverage_gap",
            title       = f"Cobertura de ejecución baja: {coverage.coverage_pct:.1f}%",
            description = (
                f"{coverage.uncovered_nodes} nodos del grafo estático nunca fueron "
                f"ejecutados en esta sesión ({gap_pct:.1f}% sin cubrir). "
                "Pueden ser dead code real o paths no ejercitados en el período auditado."
            ),
            node_ids    = coverage.uncovered_node_ids[:20],
            evidence    = {
                "coverage_pct":     coverage.coverage_pct,
                "uncovered_count":  coverage.uncovered_nodes,
            },
            remediation = "Ejecutar tests de integración o scenarios adicionales para "
                          "cubrir los paths no ejercitados. Evaluar eliminación de dead code confirmado.",
        ))

    # ── Dead code ─────────────────────────────────────────
    never_called = [
        nid for nid, node in flow.nodes.items()
        if node.origin == "static" and node.call_count == 0
    ]
    if len(never_called) > 5:
        sev = "medium" if len(never_called) > 15 else "low"
        findings.append(AuditFinding(
            id          = fid(),
            severity    = sev,
            category    = "never_called",
            title       = f"{len(never_called)} nodos nunca ejecutados en runtime",
            description = (
                f"Existen {len(never_called)} nodos en el grafo estático que no registraron "
                "ninguna ejecución en el período analizado. Pueden representar código muerto, "
                "features no utilizadas o paths condicionales no ejercitados."
            ),
            node_ids    = never_called[:20],
            evidence    = {"count": len(never_called)},
            remediation = "Analizar si estos nodos son necesarios. Si son dead code confirmado, "
                          "removerlos reduce complejidad y superficie de ataque.",
        ))

    # ── Slow nodes ────────────────────────────────────────
    slow_nodes = [
        {"node_id": nid, "name": n.name, "avg_ms": round(n.avg_duration_ms, 1)}
        for nid, n in flow.nodes.items()
        if n.avg_duration_ms and n.avg_duration_ms > 500
    ]
    slow_nodes.sort(key=lambda x: -x["avg_ms"])
    if slow_nodes:
        worst = slow_nodes[0]
        sev = "high" if worst["avg_ms"] > 2000 else "medium" if worst["avg_ms"] > 1000 else "low"
        findings.append(AuditFinding(
            id          = fid(),
            severity    = sev,
            category    = "slow_node",
            title       = f"{len(slow_nodes)} nodo(s) con latencia > 500ms",
            description = (
                f"El nodo más lento es '{worst['name']}' con un promedio de "
                f"{worst['avg_ms']}ms. En total, {len(slow_nodes)} nodo(s) superan "
                "el umbral de 500ms de latencia promedio."
            ),
            node_ids    = [n["node_id"] for n in slow_nodes[:10]],
            evidence    = {"slow_nodes": slow_nodes[:10]},
            remediation = "Revisar consultas a base de datos, llamadas externas y loops "
                          "costosos en los nodos identificados. Considerar caching o async.",
        ))

    # ── Regression (new errors vs baseline) ──────────────
    if baseline_flow and has_regression:
        from .replay import SessionDiff
        diff = SessionDiff.compare(baseline_flow, flow)
        if diff.new_errors:
            findings.append(AuditFinding(
                id          = fid(),
                severity    = "high",
                category    = "regression",
                title       = f"Regresión detectada: {len(diff.new_errors)} nodo(s) con nuevos errores",
                description = (
                    f"Comparando con la sesión base '{baseline_flow.id}', se detectaron "
                    f"{len(diff.new_errors)} nodo(s) con errores nuevos que no existían antes."
                ),
                node_ids    = diff.new_errors[:10],
                evidence    = {
                    "baseline_flow_id":   baseline_flow.id,
                    "new_error_nodes":    diff.new_errors[:10],
                    "coverage_delta":     diff.coverage_delta,
                },
                remediation = "Revisar los cambios introducidos desde la sesión base. "
                              "Ejecutar tests de regresión sobre los nodos afectados.",
            ))

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings


# ═══════════════════════════════════════════════════════════
# Audit Report
# ═══════════════════════════════════════════════════════════

@dataclass
class AuditReport:
    audit_id:       str
    audit_type:     Literal["CAE", "DAE"]
    project_id:     str
    flow_id:        str
    generated_at:   str
    period_from_ms: Optional[int]
    period_to_ms:   Optional[int]
    findings:       List[AuditFinding]
    risk_score:     float
    risk_grade:     str
    risk_label:     str
    coverage:       dict
    executive:      dict
    flows_analyzed: int
    baseline_flow_id: Optional[str]
    session_diff:   Optional[dict]
    signature:      str

    def to_dict(self) -> dict:
        return {
            "audit_id":         self.audit_id,
            "audit_type":       self.audit_type,
            "project_id":       self.project_id,
            "flow_id":          self.flow_id,
            "generated_at":     self.generated_at,
            "period": {
                "from_ms": self.period_from_ms,
                "to_ms":   self.period_to_ms,
            },
            "findings":         [f.to_dict() for f in self.findings],
            "findings_summary": {
                sev: sum(1 for f in self.findings if f.severity == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "risk_score":       self.risk_score,
            "risk_grade":       self.risk_grade,
            "risk_label":       self.risk_label,
            "coverage":         self.coverage,
            "executive":        self.executive,
            "flows_analyzed":   self.flows_analyzed,
            "baseline_flow_id": self.baseline_flow_id,
            "session_diff":     self.session_diff,
            "signature":        self.signature,
        }

    def _sign(self) -> str:
        """Hash de contenido para verificar integridad del reporte."""
        payload = f"{self.audit_id}:{self.flow_id}:{self.risk_score}:{len(self.findings)}"
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════
# Audit Builder
# ═══════════════════════════════════════════════════════════

class AuditBuilder:
    """
    Construye un AuditReport a partir de un Flow (y opcionalmente
    un flow baseline para comparación).

    CAE — análisis rápido: solo análisis estático + coverage básico.
          Sin frames completos, sin hot paths detallados.
    DAE — análisis profundo: replay completo, hot paths, comparación
          con baseline, regresiones, slow nodes.
    """

    def __init__(self):
        self._scorer = RiskScorer()

    def build(
        self,
        flow,
        audit_type:      Literal["CAE", "DAE"] = "CAE",
        baseline_flow    = None,
        period_from_ms:  Optional[int] = None,
        period_to_ms:    Optional[int] = None,
    ) -> AuditReport:
        from .replay import CoverageReport, SessionDiff
        from .session_export import SessionExporter

        coverage = CoverageReport.build(flow)
        exporter = SessionExporter()

        # Filter events to period if specified
        period_events = flow.events
        if period_from_ms:
            period_events = [e for e in period_events if e.timestamp_ms >= period_from_ms]
        if period_to_ms:
            period_events = [e for e in period_events if e.timestamp_ms <= period_to_ms]

        # Build temp flow slice for period analysis
        from .models import Flow as _Flow
        period_flow = _Flow(
            id         = flow.id,
            project_id = flow.project_id,
            name       = flow.name,
        )
        period_flow.nodes  = flow.nodes
        period_flow.edges  = flow.edges
        period_flow.events = period_events

        # Executive summary
        executive = exporter._executive_summary(
            period_flow,
            [],   # frames computed on-demand for DAE
            coverage,
            [],
        )

        # Dead code count
        dead_high = coverage.hot_nodes  # reuse for counting never-called
        dead_count = coverage.uncovered_nodes

        # Regression check
        has_regression = False
        session_diff   = None
        if baseline_flow:
            diff = SessionDiff.compare(baseline_flow, flow)
            has_regression = bool(diff.new_errors)
            session_diff   = diff.to_dict()

        # Generate findings
        findings = _gen_findings(
            period_flow, coverage,
            has_regression = has_regression,
            baseline_flow  = baseline_flow,
        )

        # Risk score
        score = self._scorer.score(
            period_flow,
            coverage_pct   = coverage.coverage_pct,
            dead_high_count = dead_count,
            has_regression  = has_regression,
        )

        audit_id = uuid.uuid4().hex[:12]
        now_iso  = datetime.datetime.utcnow().isoformat() + "Z"

        report = AuditReport(
            audit_id         = audit_id,
            audit_type       = audit_type,
            project_id       = flow.project_id,
            flow_id          = flow.id,
            generated_at     = now_iso,
            period_from_ms   = period_from_ms,
            period_to_ms     = period_to_ms,
            findings         = findings,
            risk_score       = score,
            risk_grade       = self._scorer.grade(score),
            risk_label       = self._scorer.label(score),
            coverage         = coverage.to_dict(),
            executive        = executive,
            flows_analyzed   = 1 + (1 if baseline_flow else 0),
            baseline_flow_id = baseline_flow.id if baseline_flow else None,
            session_diff     = session_diff,
            signature        = "",
        )
        report.signature = report._sign()
        return report


# ═══════════════════════════════════════════════════════════
# Multi-flow audit (batch across projects)
# ═══════════════════════════════════════════════════════════

def build_multi_audit(
    flows:       list,
    audit_type:  Literal["CAE", "DAE"] = "CAE",
    project_filter: Optional[str] = None,
    from_ms:     Optional[int] = None,
    to_ms:       Optional[int] = None,
) -> dict:
    """
    Genera un reporte agregado sobre múltiples flows.
    Útil para paneles de auditoría que supervisan varios proyectos.
    """
    from .replay import CoverageReport

    if project_filter:
        flows = [f for f in flows if f.project_id == project_filter]

    builder = AuditBuilder()
    reports = []
    for flow in flows:
        rep = builder.build(flow, audit_type=audit_type, period_from_ms=from_ms, period_to_ms=to_ms)
        reports.append(rep.to_dict())

    # Aggregate stats
    avg_risk  = sum(r["risk_score"] for r in reports) / max(len(reports), 1)
    all_sev   = defaultdict(int)
    for r in reports:
        for sev, cnt in r["findings_summary"].items():
            all_sev[sev] += cnt

    return {
        "audit_type":      audit_type,
        "generated_at":    datetime.datetime.utcnow().isoformat() + "Z",
        "project_filter":  project_filter,
        "flows_analyzed":  len(flows),
        "avg_risk_score":  round(avg_risk, 1),
        "findings_total":  dict(all_sev),
        "reports":         reports,
    }
