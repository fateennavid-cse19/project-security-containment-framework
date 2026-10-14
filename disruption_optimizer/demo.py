from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine

from simulator.simulator import MultiAgentSimulator
from simulator.scenarios import ALL_SCENARIOS
from simulator.evaluate import leaked

from disruption_optimizer.baselines import ContainmentGate


def main():
    for scenario in ALL_SCENARIOS:
        for mode in (
            "shutdown",
            "static",
            "adaptive",
        ):
            graph = CapabilityGraph()

            gate = ContainmentGate(
                graph,
                PolicyEngine(),
                mode=mode,
            )

            simulator = MultiAgentSimulator(
                sinks=[EventCollector(graph).collect],
                gate=gate,
            )

            events = simulator.run(scenario)

            successful = sum(
                event["result"] == "success"
                for event in events
            )

            print(
                f"{scenario.scenario_id}: {mode}; "
                f"success={successful}/{len(events)}; "
                f"leaked={leaked(events)}; "
                f"decisions={len(gate.decisions)}"
            )

            for decision in gate.decisions:
                selected = [
                    (
                        edge["source"],
                        edge["target"],
                        edge["action"],
                    )
                    for edge in decision["edges"]
                ]

                print(
                    "  cut:",
                    selected,
                    "cost:",
                    decision["cost"],
                )


if __name__ == "__main__":
    main()