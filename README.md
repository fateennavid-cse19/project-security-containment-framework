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
classification of the object actually being sent.

**Not built yet:** there is no running server. Everything above runs as
scripts and tests, but nothing listens on a port.

## Repo layout

```
schema/              Event schema (#3) + example event batches
api/                 OpenAPI spec (#45) for the integration API
graph_engine/        Dynamic Capability Graph (#6) + demo
simulator/           Multi-Agent Simulator (#1), built-in scenarios + demo
event_collector/     Event Collector (#4)
context_classifier/  Context Classifier (#5)
audit_history/       Audit history logging (#31) + its tests
policy_engine/       Policy Engine (#8)
risk_detector/       Path-finding Risk Detector (#9)
tests/               Tests for the risk detector and simulator
requirements.txt     Python dependencies for everything above
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

**6. Run the tests:**

```bash
.venv/bin/python -m pytest -q
```

All commands must be run from the repo root, since some components open
`schema/event_schema.json` by relative path.

See each subdirectory's README for design details and open questions.
