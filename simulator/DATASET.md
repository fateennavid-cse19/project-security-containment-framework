# Scenario Dataset

The built-in benchmark dataset contains 12 scripted trajectories: 6 benign and
6 attack scenarios. The dataset is intentionally scoped to the security policy
and event vocabulary implemented by the current prototype.

## Design basis

The current policy protects resources labelled `confidential` or `pii` from
reaching destinations labelled `external`. Scenarios therefore vary:

- data classification (`public`, `internal`, `confidential`, `pii`),
- internal versus external destinations,
- direct versus multi-agent transfer paths,
- permission escalation,
- mixed legitimate and malicious branches.

Every scenario uses simulator-supported actions such as `read`, `write`,
`call`, `delegate`, `send`, and `grant_permission`. Each trajectory has an
explicit ground-truth label (`benign` or `attack`).

## Scenario inventory

| Scenario | Label | Evaluation purpose |
|---|---|---|
| `benign_report_generation` | benign | Sensitive input is transformed into a public report before external delivery; retained as the known graph-scan false-positive case. |
| `public_external_delivery` | benign | Public data may be sent externally. |
| `internal_external_delivery` | benign | Tests the current policy boundary: `internal` is not a protected source label. |
| `confidential_internal_analysis` | benign | Confidential data remains inside the system. |
| `pii_internal_hr_processing` | benign | PII is processed only by internal agents/tools. |
| `public_long_chain_collaboration` | benign | A longer multi-agent path is still safe when the data is public. |
| `cross_agent_data_exfiltration` | attack | Confidential data reaches an attacker through File, Analysis, and Email agents. |
| `permission_escalation` | attack | A denied external send is retried after a temporary permission is granted. |
| `direct_confidential_exfiltration` | attack | Direct confidential-data send to an external attacker. |
| `long_chain_pii_exfiltration` | attack | PII crosses multiple agents before the external send. |
| `mixed_workflow_confidential_exfiltration` | attack | Malicious exfiltration occurs before a separate public workflow; used to measure preserved legitimate work. |
| `parallel_branch_pii_exfiltration` | attack | PII has a legitimate payroll branch and a malicious email branch; used to measure branch-level disruption. |

## Legitimate-step annotations

`simulator/legitimate_step_labels.json` identifies the scripted steps in each
attack trajectory that represent legitimate business work. Benign scenarios
default to all steps being legitimate.

These annotations are used by `simulator.metrics` to calculate:

- legitimate work retained,
- legitimate disruption,
- sensitive-data leakage,
- gate latency,
- incident-decision latency,
- scenario runtime.

The labels are evaluation annotations rather than security decisions. They
should be reviewed if a scenario's business meaning is changed.

## Running the evaluation

Detection quality:

```bash
python -m simulator.evaluate
```

Disruption and timing metrics:

```bash
python -m simulator.metrics \
  --labels simulator/legitimate_step_labels.json \
  --repeats 5 \
  --warmups 1 \
  --output evaluation/benchmark_metrics.json
```

## Current interpretation

The expanded dataset is a controlled benchmark for this research prototype. It
is larger and more balanced than the original three-scenario sanity check, but
it is still a scripted experimental dataset and should not be described as a
large real-world statistical benchmark.
