# Dynamic Capability Graph (#6)

`graph.py` wraps a `networkx.MultiDiGraph` and knows how to update itself from
one Event (`schema/event_schema.json`). It's the live data structure the
Compositional Risk Detector (#9, Phase 3) will search for prohibited paths, and
what `GET /graph` (`api/openapi.yaml`) serialises for the dashboard.

## Files

- `models.py` -- `NodeType`, `EdgeAction` enums and the `Node`/`Edge` dataclasses.
- `graph.py` -- `CapabilityGraph`: `apply_event()`, `block_edge()`,
  `revoke_permission()`, `is_reachable()`, `snapshot()`.
- `demo.py` -- replays the worked exfiltration example from the project doc.

## Design calls worth flagging (not fully specified in the project doc)

**Edge direction follows data flow, not "who calls whom."** A `read` edge points
resource -> agent (data flows into the agent); `delegate`/`send` point agent ->
destination; `write`/`call` point agent -> object. This is what makes
`customer_records.csv -> file_agent -> analysis_agent -> email_agent -> attacker@example.com`
a single directed walk that `is_reachable()` can find -- reachability from a
protected *resource* to a prohibited *destination* only works if reads point
the opposite way from delegates/sends. If Phase 3's detector expects a
different convention, this is the place to change it.

**Blocking marks an edge, it doesn't delete it.** `block_edge()` sets
`blocked=True` and `is_reachable()` ignores blocked edges, but the edge stays
in the graph so the dashboard's Live Capability Graph page (#27) can render
"blocked" edges distinctly rather than have them silently vanish.

**`grant_permission`/`revoke_permission` don't create flow edges.** They create/
update a `Permission` node's `active`/`revoked` label. `revoke_permission` also
walks all edges tagged with that `permission_id` and blocks them -- this is a
reasonable first cut at "removing a permission should break whatever it was
authorising," but the real Minimum-Disruption Optimiser (#15) will need to
choose *which* permission to revoke, not just react to one being revoked.
Treat `revoke_permission` here as a mechanism the optimiser can call, not the
optimiser itself.

**Costs are a placeholder.** Every edge defaults to `cost=1.0`; the real
Disruption Cost Model (#14, Phase 4) is what should compute these.

## Try it

```
.venv/bin/python -m graph_engine.demo
```

Applies the worked example's read + two delegate events, shows
`customer_records.csv` is reachable at `email_agent`, blocks the single
`analysis_agent -> email_agent` edge, and shows the path is now broken while
`file_agent -> analysis_agent` (safe work) still stands.
