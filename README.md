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
- Not yet built: risk/severity levels (#11) and the Enforcement Engine
  (#16, #24).

**Known limitation:** `detect()` flags the benign report workflow as a
violation. The graph records which agents are connected but not which data
moved along each edge, so the confidential input and the public summary look
like one flow. `evaluate_event()` is not affected because it checks the
classification of the object actually being sent. This is now recorded as an
expected-failure test and measured by the evaluation script (see Testing).

## Recent additions — Task 3.2, Phase 4 and Phase 5

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

### Validation of the additions

The development copy with severity and Phase 4 tests produced:

```text
96 passed, 1 xfailed
```

Without `tests/test_severity.py`, the expected count is 89 passed and 1 xfailed.
Run the local test suite to confirm the current checkout.

Dashboard validation checked replay frames and incident evidence for all nine
built-in scenario/strategy combinations. JavaScript syntax was checked;
automated browser interaction and visual testing remain outstanding.

The original 97% coverage figure below describes the earlier codebase and has
not been remeasured for these additions.

## Testing

**Status:** 73 passed, 1 expected failure, 97% line coverage of source code
(demo and evaluation scripts excluded).

The tests are organised in layers, from single components up to the whole
pipeline:

| Level | What it checks | Where |
|---|---|---|
| Unit | Each component on its own: graph edge direction and labels, block/revoke containment, context classification, collector validation, policy definitions, detector rules | `tests/test_graph_engine.py`, `test_context_classifier.py`, `test_event_collector.py`, `test_policy_engine.py`, `test_risk_detector.py` |
| Integration | Components working together: simulator -> collector -> graph, collector -> audit log with context | `tests/test_simulator.py`, `audit_history/test_audit_logger.py` |
| System (end-to-end) | The full pipeline stopping an attack: with the Risk Detector as the gate, the exfiltration send is denied and the attacker is unreachable in the graph | `test_detector_gate_stops_exfiltration_end_to_end` |
| Edge / negative cases | Malformed scenarios rejected before any event (7 cases), invalid events rejected without side effects, public or internal data not flagged, queries on unknown nodes | across the files above |
| Contract | Every simulated event is valid against `schema/event_schema.json` | `test_all_scenarios_emit_schema_valid_events` |
| Reproducibility | Seeded runs produce identical timestamps | `test_jitter_is_reproducible_with_seed` |

**Detection evaluation.** `simulator/evaluate.py` runs every scenario through
both detection modes and scores it against the scenario's ground-truth label
(`benign` / `attack`):

```
graph scan   TP=2 FP=1 TN=0 FN=0  precision=0.67 recall=1.00
inline gate  TP=2 FP=0 TN=1 FN=0  precision=1.00 recall=1.00
```

Both modes catch every attack. The graph scan's false positive is the known
limitation above; the inline gate gets the benign workflow right, and with it
in place no sensitive data leaks in either attack. With only three scenarios
these numbers are a sanity check, not a statistical result -- growing the
benchmark dataset (#35) is the follow-up.

**Issues found by testing:**

- The Event Collector opened the schema by relative path and crashed unless
  run from the repo root. Fixed; covered by `test_works_outside_the_repo_root`.
- The audit history test ran as a plain script (pytest collected 0 tests) and
  deleted the real `audit_history.jsonl`. Rewritten as pytest tests that use a
  temporary file.
- The `detect()` false positive above, kept as a strict `xfail` test so it
  shows up as soon as it is fixed.

**Still to test:** the Enforcement Engine (#16, #24) and severity levels (#11)
once built, the API against `api/openapi.yaml` once a server exists, and gate
latency per event (the gate runs inline, so it must stay fast).

**Not built yet:** there is no running server. Everything above runs as
scripts and tests, but nothing listens on a port.

## Repo layout

```
schema/              Event schema (#3) + example event batches
api/                 OpenAPI spec (#45) for the integration API
graph_engine/        Dynamic Capability Graph (#6) + demo
simulator/           Multi-Agent Simulator (#1), built-in scenarios, demo + detection evaluation
event_collector/     Event Collector (#4)
context_classifier/  Context Classifier (#5)
audit_history/       Audit history logging (#31) + its tests
policy_engine/       Policy Engine (#8)
risk_detector/       Path-finding Risk Detector (#9)
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