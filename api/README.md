# REST API Spec

`openapi.yaml` (OpenAPI 3.1) documents the 6 endpoints from the project doc's
"Reusable software interface" section. It `$ref`s `../schema/event_schema.json`
directly for the event payloads, so the API and event schema can't drift apart.

## Endpoints

| Endpoint | Mutates graph? | Purpose |
|---|---|---|
| `POST /events` | Yes | Commit an event, run the detector, get back a decision |
| `POST /evaluate` | No | Dry-run the same check on a hypothetical event/path |
| `GET /graph` | -- | Current capability graph (dashboard's Live Graph page, #27) |
| `POST /contain` | Yes (unless `simulate: true`) | Apply/preview a containment action; used by baselines #36/#37 to force a specific action |
| `GET /incidents`, `GET /incidents/{id}` | -- | List / full explanation of a decision (#28) |
| `PATCH /policies` | -- | Update protected sources, prohibited sinks, risk weights |

## Key design call (flagged, not stated explicitly in the project doc)

`/events` commits and synchronously evaluates; `/evaluate` is side-effect-free.
This split gives agents a way to ask "would this be allowed?" before acting, and
gives the optimiser (#15) a way to score candidate cuts without touching real state.

## Validating the spec

```
.venv/bin/pip install openapi-spec-validator   # already installed in this repo's .venv
.venv/bin/python -c "
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename
spec, base_uri = read_from_filename('api/openapi.yaml')
validate(spec, base_uri=base_uri)
print('valid')
"
```

## Open questions for later phases

- `IncidentRecord.explanation.rejected_alternatives` assumes the optimiser records
  every candidate cut it considered, not just the winner -- confirm the optimiser
  (#15) is designed to retain that before Phase 4.
- `/contain` currently takes a single `source`/`target` pair; `isolate` and
  `emergency_stop` only use `source` (target is null) -- revisit if isolate ever
  needs to name more than one node.
