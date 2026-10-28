# project-security-containment-framework

Minimum-Disruption Security Containment Framework for Multi-Agent AI Systems

Research prototype: detect dangerous capability paths that emerge from
*combinations* of individually-authorised agent permissions, and contain them
with the smallest possible intervention (block one edge/permission) instead of
shutting down the whole workflow. See `Project-full-doc.docx` for the full
design and `priority-list.docx` for what's in/out of scope.

## Progress

Following the 7-phase plan in `Internal-Security_Framework_7Week_Gantt_Chart.xlsx`.

**Phase 1 (Week 1) -- Architecture & Data Schema: done**

- `schema/` -- the standard event schema (#3) that agents/simulator report
  actions to, plus example event batches (including the worked cross-agent
  exfiltration scenario from the project doc).
- `api/` -- OpenAPI 3.1 spec (#45) for the 6 integration endpoints
  (`/events`, `/evaluate`, `/graph`, `/contain`, `/incidents`, `/policies`).
  References the event schema directly so the two can't drift apart.
- `graph_engine/` -- the Dynamic Capability Graph (#6): a live directed graph
  of agents/tools/resources/destinations/permissions that ingests events and
  answers reachability queries. `graph_engine/demo.py` replays the worked
  exfiltration example and shows a single edge block breaking the dangerous
  path while safe upstream work stays reachable.

**Phase 2 (Week 2) -- Simulator & Event Ingestion Engine: done**

- `simulator/` -- the Multi-Agent Simulator (#1): replays scripted scenarios
  (one benign workflow, two attacks) as a live stream of schema-valid events.
  Agents track the permissions and data they hold, so a missing permission
  produces a `denied` event, and blocking a step upstream makes later steps
  that depend on it fail with `error`. A `gate` hook sees every proposed event
  before it executes -- this is where enforcement plugs in.
- `event_collector/` -- the Event Collector (#4): validates incoming events
  against the schema, classifies them, and applies them to the graph.
- `context_classifier/` -- the Context Classifier (#5): labels each event's
  trust boundary, transfer type, and sensitive-data exposure.
- `audit_history/` -- Agent Activity Audit History (#31): appends events plus
  their context to a JSONL log, with filtering and a simple log view.

**Phase 3 (Week 3) -- Risk Detector & Enforcement: in progress**

- `policy_engine/` -- the Policy Engine (#8). Currently holds one policy,
  `POL-001`: confidential/PII data must not reach an external destination.
- `risk_detector/` -- the path-finding Risk Detector (#9): finds graph paths
  from sensitive resources to prohibited destinations, both on the current
  graph (`detect()`) and for a proposed event before it executes
  (`evaluate_event()`).
- Risk/severity levels (#11) were added in Task 3.2 (see below).
  Containment decisions are applied through the simulator gate by
  `disruption_optimizer.baselines.ContainmentGate` (Phase 4); the Enforcement
  Engine (#16, #24) is not yet a separate component.

**Known limitation:** `detect()` flags the benign report workflow as a
violation. The graph records which agents are connected but not which data
moved along each edge, so the confidential input and the public summary look
like one flow. `evaluate_event()` is not affected because it checks the
classification of the object actually being sent. This is now recorded as an
expected-failure test and measured by the evaluation script (see Testing).

## Recent additions — Task 3.2, Phase 4, Phase 5, Phase 6.1 and Phase 6.3

### Task 3.2 — Risk / Severity Levels (#11)

Added `risk_detector/severity.py` and updated `risk_detector/detector.py`.

Both `detect()` and `evaluate_event()` now include `severity` and
`severity_reason` in their violation records.

| Level | Prototype rule |
|---|---|
| Suspicious | A detected policy violation without sensitive external exposure |
| High | Confidential or PII data can reach an external destination through at most one agent |
| Critical | The same exposure involves two or more distinct agents |

Safe events still return an empty violation list. With the current policy,
violations normally receive High or Critical ratings.

These are project rules, not calibrated attack probabilities.
The existing graph-scan false positive remains unchanged.

### Phase 4 — Disruption Optimiser & Baselines

Added the `disruption_optimizer/` package:

| File | Purpose |
|---|---|
| `__init__.py` | Package definition |
| `core.py` | Disruption cost model and constrained minimum-cut optimiser |
| `baselines.py` | Shutdown, static-cut and adaptive containment strategies |
| `demo.py` | Runs the strategies against the built-in scenarios |

Added `tests/test_disruption_optimizer.py` for Phase 4 testing.

**4.1 — Disruption Cost Model (#14) & Minimum-Cut Optimiser (#15)**

The optimiser selects the lowest-cost permitted edge cut between the supplied
protected sources and prohibited destinations.

It handles parallel action edges, ignores blocked edges, respects protected
edges, and reports infeasible cuts without modifying the graph during planning.

Static mode uses the base edge cost. Adaptive mode uses:

```text
cost = base cost × (1 + workload + criticality)
```

Workload and criticality are nonnegative caller-supplied weights.

**4.2 — Baseline A: Shutdown (#36) & Baseline B: Static Cut (#37)**

- Shutdown denies the unsafe triggering action and stops subsequent actions.
- Static cut selects connections to block using fixed base costs.

**4.3 — Adaptive Containment (#38)**

Adaptive containment recalculates the cut using the current workload and
criticality weights. These weights can be updated during a run.

Selected restrictions persist through the simulator gate. The triggering unsafe
action is also denied because an upstream cut cannot erase data an agent already
holds.

Each decision records its strategy, selected edges, cost, reason and feasibility.
If a permitted cut is infeasible, the triggering action is denied and the
infeasible result is recorded.

The default demo uses no additional weights, so static and adaptive strategies
may choose the same cut. Automatic workload measurement is not implemented.

### Phase 5 — Operator Security Dashboard

Added the `dashboard/` package:

| File | Purpose |
|---|---|
| `__init__.py` | Package definition |
| `server.py` | Local dashboard server and scenario evidence capture |
| `index.html` | Overview, graph and incident-detail interface |

**5.1 — Security Dashboard Overview (#26)**

Displays events, successful actions, incident count, sensitive external sends,
and agent activity.

Successful action counts are not a measure of legitimate tasks preserved.

**5.2 — Interactive Capability Graph (#27)**

Displays graph snapshots after each simulator event, with:

- Step-by-step replay.
- Zoom and pan.
- Node inspection.
- Blocked-edge visibility.
- Selected incident-path highlighting.

This is simulator replay, not live production monitoring.

**5.3 — Auditable Incident Detail (#28)**

Displays incident ID, timestamp, severity, policy, dangerous path, selected
containment edges, planned cost, feasibility, and supporting event and graph
evidence.

Complete run evidence can be downloaded as JSON.

Dashboard records are held in memory and are not automatically written to the
existing audit-history logger. JSON export is not a tamper-evident audit store.

The dashboard server supplies `/`, `/api/scenarios`, and `/api/run`.
It does not yet implement the complete specification in `api/openapi.yaml`.


### Phase 6.1 — Expanded Scenario Dataset

The built-in benchmark now contains 12 scripted trajectories: 6 benign and
6 attack scenarios. The scenarios stay within the policy and event vocabulary
implemented by the current prototype. `simulator/DATASET.md` documents the
design and `simulator/legitimate_step_labels.json` provides legitimate-step
annotations for attack trajectories.

The expanded dataset adds public/internal policy-boundary cases, internal
processing of confidential/PII data, direct and long-chain exfiltration, and
mixed/parallel workflows designed to measure preserved legitimate work.

Current detection results are:

```text
graph scan   TP=6 FP=1 TN=5 FN=0  precision=0.86 recall=1.00
inline gate  TP=6 FP=0 TN=6 FN=0  precision=1.00 recall=1.00
```

The single graph-scan false positive is the existing
`benign_report_generation` limitation. With inline containment enabled, all
six attack scenarios are blocked without sensitive-data leakage.

The controlled dataset is suitable for prototype evaluation but is not a
large real-world statistical benchmark.

### Phase 6.3 — Operational Disruption & Gate Latency

Added `simulator/metrics.py`, which runs every built-in scenario under each
containment strategy (shutdown, static, adaptive) and reports:

- Legitimate work retained compared with an uncontained reference run.
- Measured wall-clock gate latency per call (mean and p95), plus the time to
  detect, plan and apply restrictions for each incident.

```bash
.venv/bin/python -m simulator.metrics
```

Options: `--repeats`, `--warmups`, `--labels` (a JSON file mapping scenario
IDs to their legitimate step numbers) and `--output` (write results as JSON).

Limitations:

- Attack scenarios require legitimate-step annotations for retention metrics.
  The repository now provides `simulator/legitimate_step_labels.json` for the
  built-in attack scenarios.
- Gate samples include both allowed and denied calls. Events rejected by base
  access control never reach the gate.
- The default adaptive weights are zero.
- The 12-scenario dataset is a controlled scripted benchmark, not a large
  real-world statistical dataset.

### Validation of the additions

`tests/test_severity.py` and `tests/test_disruption_optimizer.py` cover
Task 3.2 and Phase 4:

- **Severity:** each rating rule, and the severity attached by both
  `detect()` and `evaluate_event()`.
- **Cost model:** static and adaptive costs, and rejection of invalid values.
- **Minimum cut:** the cheapest cut, parallel and blocked edges, protected
  edges, infeasible cuts, multiple endpoints, and adaptive re-weighting.
- **Containment gate:** every strategy against every scenario. No attack leaks
  data, the benign workflow is untouched, blocks persist on replay, shutdown
  costs more than a static cut, and an infeasible cut still denies the trigger.

Dashboard validation previously checked replay frames and incident evidence
for the original three scenarios across nine scenario/strategy combinations.
JavaScript syntax was checked; automated browser interaction and visual testing
of the expanded 12-scenario dataset remain outstanding.

## Testing

**Status:** 120 passed, 1 expected failure. Line coverage is 78% of all
source code, or about 97% when `dashboard/server.py` and `simulator/metrics.py`
are excluded. The metrics module now has dataset-level tests, but its CLI and
timing-report paths are only partially covered; the dashboard server still has
no automated tests. Demo and evaluation scripts are excluded from coverage.

The tests are organised in layers, from single components up to the whole
pipeline:

| Level | What it checks | Where |
|---|---|---|
| Unit | Each component on its own: graph edge direction and labels, block/revoke containment, context classification, collector validation, policy definitions, detector rules, severity rules, disruption cost model and minimum cut | `tests/test_graph_engine.py`, `test_context_classifier.py`, `test_event_collector.py`, `test_policy_engine.py`, `test_risk_detector.py`, `test_severity.py`, `test_disruption_optimizer.py` |
| Integration | Components working together: simulator -> collector -> graph, collector -> audit log with context | `tests/test_simulator.py`, `audit_history/test_audit_logger.py` |
| System (end-to-end) | The full pipeline stopping attacks: the Risk Detector gate denies prohibited sends, and every containment strategy stops all six attack scenarios without sensitive leakage | `test_detector_gate_stops_exfiltration_end_to_end`, `test_every_attack_is_blocked_without_sensitive_leak` |
| Edge / negative cases | Malformed scenarios rejected before any event (7 cases), invalid events rejected without side effects, public or internal data not flagged, queries on unknown nodes | across the files above |
| Contract | Every simulated event is valid against `schema/event_schema.json` | `test_all_scenarios_emit_schema_valid_events` |
| Reproducibility | Seeded runs produce identical timestamps | `test_jitter_is_reproducible_with_seed` |

**Detection evaluation.** `simulator/evaluate.py` runs every scenario through
both detection modes and scores it against the scenario's ground-truth label
(`benign` / `attack`):

```
graph scan   TP=6 FP=1 TN=5 FN=0  precision=0.86 recall=1.00
inline gate  TP=6 FP=0 TN=6 FN=0  precision=1.00 recall=1.00
```

Both modes catch every attack. The graph scan's single false positive is the
known `benign_report_generation` limitation; the inline gate correctly allows
all six benign scenarios, and no sensitive data leaks from any of the six
attack scenarios when containment is enabled. The 12-scenario dataset is a
controlled research benchmark and should not be presented as a large
real-world statistical sample. See `simulator/DATASET.md` for the scenario
design and legitimate-step annotations used for disruption metrics.

**Issues found by testing:**

- The Event Collector opened the schema by relative path and crashed unless
  run from the repo root. Fixed; covered by `test_works_outside_the_repo_root`.
- The audit history test ran as a plain script (pytest collected 0 tests) and
  deleted the real `audit_history.jsonl`. Rewritten as pytest tests that use a
  temporary file.
- The `detect()` false positive above, kept as a strict `xfail` test so it
  shows up as soon as it is fixed.

**Still to test:** the dashboard server (`dashboard/server.py`) and the
Phase 6.3 metrics script (`simulator/metrics.py`); the Enforcement Engine
(#16, #24) once it is a separate component; and the full API in
`api/openapi.yaml`. Gate latency is now measured by `simulator.metrics`, but
no test enforces a latency limit.

**Server:** only the local dashboard server exists (`python -m
dashboard.server`). It serves `/`, `/api/scenarios` and `/api/run`, not the
integration API described in `api/openapi.yaml`.

## Repo layout

```
schema/              Event schema (#3) + example event batches
api/                 OpenAPI spec (#45) for the integration API
graph_engine/        Dynamic Capability Graph (#6) + demo
simulator/           Multi-Agent Simulator (#1), built-in scenarios, demo, detection evaluation + Phase 6.3 metrics
event_collector/     Event Collector (#4)
context_classifier/  Context Classifier (#5)
audit_history/       Audit history logging (#31) + its tests
policy_engine/       Policy Engine (#8)
risk_detector/       Path-finding Risk Detector (#9) + severity levels (#11)
disruption_optimizer/ Disruption cost model, minimum-cut optimiser, containment strategies + demo
dashboard/           Operator security dashboard (local server + single-page UI)
tests/               Unit, integration and system tests (shared fixtures in conftest.py)
requirements.txt     Python dependencies for everything above
pytest.ini           Test discovery and import path
.coveragerc          Coverage settings (source only; tests and scripts excluded)
.venv/               Local virtualenv (not committed; recreate with steps below)
```

## How to run the project as it stands

Nothing here is a live service yet -- these steps validate the schema and
API spec, run the demos, and run the test suite.

**1. Set up the environment** (from the repo root):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

**2. Validate the event schema against the example events:**

```bash
.venv/bin/python -c "
import json, jsonschema
schema = json.load(open('schema/event_schema.json'))
validator = jsonschema.Draft202012Validator(schema)
for f in ['schema/examples/cross_agent_exfiltration.json', 'schema/examples/benign_and_permission_grant.json']:
    for e in json.load(open(f)):
        validator.validate(e)
print('all example events are valid')
"
```

**3. Validate the OpenAPI spec:**

```bash
.venv/bin/python -c "
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename
spec, base_uri = read_from_filename('api/openapi.yaml')
validate(spec, base_uri=base_uri)
print('spec is valid')
"
```

**4. Run the graph engine demo** (replays the worked exfiltration example,
shows containment breaking the dangerous path while preserving safe work):

```bash
.venv/bin/python -m graph_engine.demo
```

**5. Run the simulator demo** (runs every built-in scenario through the
collector and graph, then reruns the exfiltration attack with the Risk
Detector as the gate, which blocks the external send before it executes):

```bash
.venv/bin/python -m simulator.demo
```

**6. Run the tests** (add `--cov --cov-report=term-missing` for a coverage
report):

```bash
.venv/bin/python -m pytest -q
```

**7. Run the detection evaluation** (scores both detection modes against each
scenario's ground-truth label):

```bash
.venv/bin/python -m simulator.evaluate
```

Run the `-m` commands from the repo root so Python can find the packages. The
test suite works from any directory.

See each subdirectory's README for design details and open questions.

## Running the new additions on Windows

Run these commands from the main project folder containing `requirements.txt`.

### Install dependencies

```powershell
python -m pip install -r requirements.txt
```

If Windows does not recognise `python`, use `py` instead.

### Run all tests

```powershell
python -m pytest -q
```

### Run Phase 4 tests

```powershell
python -m pytest tests/test_disruption_optimizer.py -q
```

### Run the Phase 4 strategy comparison

```powershell
python -m disruption_optimizer.demo
```

The output shows successful actions, whether sensitive data leaked, selected
cut edges, and planned disruption costs for each strategy.

### Start the Phase 5 dashboard

```powershell
python -m dashboard.server
```

Open:

```text
http://127.0.0.1:8000
```

Keep the terminal running while using the dashboard.

1. Select a scenario and strategy.
2. Click **Run scenario**.
3. Review **Overview**, **Capability graph**, and **Incident detail**.
4. Use the slider or **Play replay** to inspect each step.
5. Click **Download evidence** to export the run.

Press **Ctrl + C** in the terminal to stop the server.

### Fix a missing dependency warning in VS Code

Install the dependencies, then ensure VS Code uses the same Python interpreter
as the terminal.

Find the terminal interpreter with:

```powershell
python -c "import sys; print(sys.executable)"
```

Press **Ctrl + Shift + P → Python: Select Interpreter** and select that path.