"""Run with: python -m dashboard.server"""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4
import json

from disruption_optimizer.baselines import ContainmentGate
from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from simulator.scenarios import ALL_SCENARIOS
from simulator.simulator import MultiAgentSimulator


def run_dashboard(scenario_id, mode):
    scenarios = {
        scenario.scenario_id: scenario
        for scenario in ALL_SCENARIOS
    }

    if scenario_id not in scenarios:
        raise ValueError("Unknown scenario")

    if mode not in {"shutdown", "static", "adaptive"}:
        raise ValueError("Unknown strategy")

    scenario = scenarios[scenario_id]

    graph = CapabilityGraph()
    collector = EventCollector(graph)

    gate = ContainmentGate(
        graph,
        PolicyEngine(),
        mode=mode,
    )

    incidents = []
    frames = []
    events = []

    run_id = uuid4().hex[:12]

    def check(event):
        """Capture evidence before applying containment."""
        violations = deepcopy(
            gate.detector.evaluate_event(event)
        )

        before = deepcopy(graph.snapshot())
        old_count = len(gate.decisions)

        allowed = gate(event)

        if len(gate.decisions) > old_count:
            decision = deepcopy(gate.decisions[-1])

            severity_order = {
                "suspicious": 0,
                "high": 1,
                "critical": 2,
            }

            severity = max(
                (
                    violation.get("severity", "suspicious")
                    for violation in violations
                ),
                key=lambda value: severity_order[value],
            )

            incidents.append({
                "incident_id": (
                    f"{run_id}-INC-{len(incidents) + 1:03d}"
                ),
                "timestamp": event["timestamp"],
                "severity": severity,
                "violations": violations,
                "decision": decision,
                "proposed_event": deepcopy(event),
                "graph_before": before,
                "graph_after_cut": deepcopy(graph.snapshot()),
            })

        return allowed

    def collect(event):
        """Capture the graph after each actual simulator event."""
        if not collector.collect(event):
            raise ValueError(
                "Simulator produced an invalid event"
            )

        events.append(deepcopy(event))

        frames.append({
            "graph": deepcopy(graph.snapshot()),
            "events": deepcopy(events),
            "incidents": deepcopy(incidents),
        })

    simulator = MultiAgentSimulator(
        sinks=[collect],
        gate=check,
    )

    simulator.run(scenario)

    return {
        "run_id": run_id,
        "scenario": scenario_id,
        "mode": mode,
        "frames": frames,
        "limitations": (
            "Scenario replay; adaptive weights default to zero. "
            "Graph data-lineage limitation remains."
        ),
    }


class Handler(BaseHTTPRequestHandler):
    def reply(
        self,
        status,
        data,
        content_type="application/json",
    ):
        if isinstance(data, bytes):
            body = data
        else:
            body = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            html = Path(__file__).with_name(
                "index.html"
            ).read_bytes()

            self.reply(
                200,
                html,
                "text/html; charset=utf-8",
            )

        elif self.path == "/api/scenarios":
            self.reply(
                200,
                [
                    {
                        "id": scenario.scenario_id,
                        "label": scenario.trajectory_type,
                    }
                    for scenario in ALL_SCENARIOS
                ],
            )

        else:
            self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/api/run":
            self.reply(404, {"error": "Not found"})
            return

        allowed_origins = {
            None,
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        }

        if self.headers.get("Origin") not in allowed_origins:
            self.reply(
                403,
                {"error": "Origin not allowed"},
            )
            return

        try:
            length = int(
                self.headers.get("Content-Length", "0")
            )

            if not 0 < length <= 4096:
                raise ValueError("Invalid request size")

            payload = json.loads(
                self.rfile.read(length)
            )

            if not isinstance(payload, dict):
                raise ValueError("Expected an object")

            result = run_dashboard(
                payload.get("scenario"),
                payload.get("mode"),
            )

        except (ValueError, TypeError) as error:
            self.reply(
                400,
                {"error": str(error)},
            )
            return

        except Exception:
            self.reply(
                500,
                {
                    "error": (
                        "Run failed; check the server terminal"
                    )
                },
            )
            return

        self.reply(200, result)


if __name__ == "__main__":
    print(
        "Dashboard: http://127.0.0.1:8000 "
        "— Ctrl+C to stop"
    )

    server = ThreadingHTTPServer(
        ("127.0.0.1", 8000),
        Handler,
    )

    server.serve_forever()