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

**Not built yet:** there is no running server. Everything above is validated
via scripts (schema validation, OpenAPI validation, the graph demo) but
nothing listens on a port. That starts in Phase 2/3 once the simulator is
generating real event traffic and the detector/enforcement logic exists to
sit behind the API.

**Next up -- Phase 2 (Week 2):** Multi-Agent Simulator (#1), Event Collector
(#4), Context Classifier (#5).

## Repo layout

```
schema/            Event schema (#3) + example event batches
api/                OpenAPI spec (#45) for the integration API
graph_engine/       Dynamic Capability Graph (#6) + demo
requirements.txt    Python dependencies for everything above
.venv/              Local virtualenv (not committed; recreate with steps below)
```

## How to run the project as it stands

Nothing here is a live service yet -- these steps validate the schema and
API spec, and run the graph engine against example data.

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

See each subdirectory's `README.md` for design details and open questions.
