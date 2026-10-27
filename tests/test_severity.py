from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector
from risk_detector.severity import assess_severity


def exfiltration_graph(make_event, include_send=True):
    """customer_records.csv -> file_agent -> analysis_agent -> email_agent -> attacker"""
    graph = CapabilityGraph()
    graph.apply_event(make_event("read"))
    graph.apply_event(make_event("delegate", to="analysis_agent"))
    graph.apply_event(make_event("delegate", agent_id="analysis_agent", to="email_agent"))
    if include_send:
        graph.apply_event(make_event("send", agent_id="email_agent", to="attacker@example.com"))
    return graph


# -- assess_severity rules ----------------------------------------------------

def test_sensitive_external_single_agent_is_high():
    result = assess_severity({"confidential"}, {"external"}, ["email_agent"])

    assert result["severity"] == "high"
    assert result["severity_reason"]


def test_sensitive_external_multiple_agents_is_critical():
    result = assess_severity({"pii"}, {"external"}, ["file_agent", "email_agent"])

    assert result["severity"] == "critical"


def test_repeated_agent_counts_once():
    result = assess_severity({"confidential"}, {"external"}, ["email_agent", "email_agent"])

    assert result["severity"] == "high"


def test_non_sensitive_source_is_suspicious():
    result = assess_severity({"internal"}, {"external"}, ["file_agent", "email_agent"])

    assert result["severity"] == "suspicious"


def test_internal_destination_is_suspicious():
    result = assess_severity({"confidential"}, set(), ["file_agent", "email_agent"])

    assert result["severity"] == "suspicious"


# -- severity attached by the detector ---------------------------------------

def test_evaluate_event_rates_cross_agent_send_critical(make_event):
    graph = exfiltration_graph(make_event, include_send=False)
    detector = RiskDetector(graph, PolicyEngine())

    violations = detector.evaluate_event(
        make_event("send", agent_id="email_agent", to="attacker@example.com")
    )

    assert len(violations) == 1
    assert violations[0]["severity"] == "critical"
    assert violations[0]["severity_reason"]


def test_evaluate_event_rates_single_agent_send_high(make_event):
    graph = CapabilityGraph()
    graph.apply_event(make_event("read", agent_id="email_agent"))
    detector = RiskDetector(graph, PolicyEngine())

    violations = detector.evaluate_event(
        make_event("send", agent_id="email_agent", to="attacker@example.com")
    )

    assert len(violations) == 1
    assert violations[0]["severity"] == "high"


def test_detect_attaches_severity_to_graph_violations(make_event):
    detector = RiskDetector(exfiltration_graph(make_event), PolicyEngine())

    violations = detector.detect()

    assert violations
    assert all(v["severity"] == "critical" for v in violations)
    assert all(v["severity_reason"] for v in violations)


def test_safe_event_has_no_violations(make_event):
    graph = exfiltration_graph(make_event, include_send=False)
    detector = RiskDetector(graph, PolicyEngine())

    violations = detector.evaluate_event(
        make_event("send", agent_id="email_agent", to="report_agent")
    )

    assert violations == []
