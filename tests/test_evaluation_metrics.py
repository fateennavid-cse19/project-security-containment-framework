import pytest

from simulator.evaluate import format_ratio, security_metrics


#==================================================
# Security effectiveness metric calculations
#==================================================

def test_security_metrics_for_graph_scan_results():
    metrics = security_metrics(
        {"TP": 6, "FP": 1, "TN": 5, "FN": 0},
        attack_leaks=6,
        attack_total=6,
    )

    assert metrics["precision"] == pytest.approx(6 / 7)
    assert metrics["recall"] == 1.0
    assert metrics["prohibited_path_coverage"] == 1.0
    assert metrics["accuracy"] == pytest.approx(11 / 12)
    assert metrics["false_positive_rate"] == pytest.approx(1 / 6)
    assert metrics["false_negative_rate"] == 0.0
    assert metrics["benign_allow_rate"] == pytest.approx(5 / 6)
    assert metrics["attack_success_rate"] == 1.0
    assert metrics["attack_prevention_rate"] == 0.0


def test_security_metrics_for_inline_gate_results():
    metrics = security_metrics(
        {"TP": 6, "FP": 0, "TN": 6, "FN": 0},
        attack_leaks=0,
        attack_total=6,
    )

    assert metrics == {
        "precision": 1.0,
        "recall": 1.0,
        "prohibited_path_coverage": 1.0,
        "accuracy": 1.0,
        "false_positive_rate": 0.0,
        "false_negative_rate": 0.0,
        "benign_allow_rate": 1.0,
        "attack_success_rate": 0.0,
        "attack_prevention_rate": 1.0,
    }


def test_security_metrics_handle_zero_denominators():
    metrics = security_metrics(
        {"TP": 0, "FP": 0, "TN": 0, "FN": 0},
        attack_leaks=0,
        attack_total=0,
    )

    assert all(value is None for value in metrics.values())
    assert format_ratio(None) == "n/a"


def test_security_metrics_reject_invalid_counts():
    with pytest.raises(ValueError):
        security_metrics({"TP": 1, "FP": 0, "TN": 1})

    with pytest.raises(ValueError):
        security_metrics({"TP": 1, "FP": -1, "TN": 1, "FN": 0})

    with pytest.raises(ValueError):
        security_metrics(
            {"TP": 1, "FP": 0, "TN": 1, "FN": 0},
            attack_leaks=2,
            attack_total=1,
        )
