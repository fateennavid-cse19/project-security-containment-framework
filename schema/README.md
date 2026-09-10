# Event Schema

`event_schema.json` defines the single input format the Event Collector (#4) accepts
from the Multi-Agent Simulator (#1) or any real agent platform integrating via
`POST /events`. Every action, transfer, tool call, or permission change is one Event.

## Shape

Each event is `agent_id` (actor) + `action` (edge type) + `object` (what's acted on) +
`destination` (where it flows, if anywhere). This mirrors the graph edges described in
the project doc: read, delegate/pass, call/invoke, send.

- `action`: `read | write | call | delegate | send | grant_permission | revoke_permission`
- `object`: a `resource | tool | permission`, with a `classification` label
  (`public | internal | confidential | pii`) when it's a resource
- `destination`: an `agent | tool | external` endpoint, with `is_external` flagging
  prohibited-sink candidates
- `permission_id`: which permission authorised the action -- this is what the
  Minimum-Disruption Optimiser (#15) revokes when computing a cut
- `ground_truth_label`: benign/attack tagging for the Scenario Dataset (#35) and
  metrics (#39). **Evaluation-only** -- the Policy Engine (#8) and Compositional Risk
  Detector (#9) must never read this field, or the evaluation is meaningless.

## Examples

- `examples/cross_agent_exfiltration.json` -- the four-event chain from the worked
  example in the project doc (File Agent reads confidential data -> delegates to
  Analysis Agent -> delegates to Email Agent -> blocked send to an external address).
- `examples/benign_and_permission_grant.json` -- an ordinary external send that should
  stay allowed, plus a temporary permission grant (#17).

## Validating events

```
.venv/bin/pip install jsonschema   # already installed in this repo's .venv
.venv/bin/python -c "
import json, jsonschema
schema = json.load(open('schema/event_schema.json'))
validator = jsonschema.Draft202012Validator(schema)
for e in json.load(open('schema/examples/cross_agent_exfiltration.json')):
    validator.validate(e)
print('ok')
"
```

## Open questions for later phases

- `goal_id` and goal-mismatch scoring (#7) are optional now; wire them up once the
  Context Classifier (#5) can compare declared goal vs. actual action.
- Temporary permissions (`grant_permission` with `metadata.expires_at`) need the
  simulator or Event Collector to emit a matching `revoke_permission` event at
  expiry -- not yet enforced by the schema itself, just documented in metadata.
