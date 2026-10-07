# Event Collector (#4)

## Purpose

The Event Collector receives runtime events, validates them against the
standard event schema, derives contextual information through the
Context Classifier, records the collected event, and forwards the valid
raw event to the Dynamic Capability Graph.

It acts as the main ingestion point between generated agent activity and
the framework's runtime security components.

## Responsibilities

The Event Collector:

-   validates incoming events against `schema/event_schema.json`;
-   rejects invalid events before they affect the graph;
-   passes valid events to the Context Classifier;
-   stores the original event together with its derived context;
-   forwards the original valid event to the Dynamic Capability Graph.

The Event Collector does **not** determine whether an event is
malicious, assign risk severity, identify policy violations, or make
containment decisions.

## How It Works

For each incoming event:

1.  Validate the event against the event schema.
2.  Reject the event if schema validation fails.
3.  Pass the valid event to the Context Classifier.
4.  Store the event and derived context together.
5.  Apply the raw event to the Dynamic Capability Graph.
6.  Return `True` when collection succeeds.

Collected events are stored in the following form:

``` python
{
    "event": event,
    "context": context
}
```

Keeping context outside the raw event preserves compatibility with the
event schema, which does not allow arbitrary additional top-level
properties.

## Input

A dictionary representing an event that conforms to
`schema/event_schema.json`.

Examples of supported actions include:

-   `read`
-   `write`
-   `call`
-   `delegate`
-   `send`
-   `grant_permission`
-   `revoke_permission`

## Output

`collect(event)` returns:

-   `True` when the event is valid and successfully collected;
-   `False` when schema validation fails.

Collected events can be retrieved using:

``` python
collector.get_events()
```

## Processing Flow

``` text
Incoming Event
      |
      v
Schema Validation
      |
      v
Context Classifier (#5)
      |
      v
Store Event + Context
      |
      v
Dynamic Capability Graph (#6)
```

## Current Limitations

-   Events are currently stored in memory.
-   The collector does not provide persistent audit storage.
-   Security policy evaluation is handled by the Policy Engine and
    Compositional Risk Detector rather than by the collector.
-   Containment decisions are handled by later framework components.
