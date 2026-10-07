# Compositional Risk Detector (#9)

## Purpose

The Compositional Risk Detector identifies prohibited security paths
that emerge from combinations of otherwise individual agent actions and
capabilities.

It evaluates the Dynamic Capability Graph (#6) against policies supplied
by the Policy Engine (#8).

A key goal is to detect risks that are not necessarily visible from one
event in isolation but become unsafe when several actions compose into
an end-to-end path.

## Responsibilities

The Risk Detector:

-   retrieves active policies from the Policy Engine;
-   identifies graph nodes matching policy labels;
-   searches active, non-blocked graph paths;
-   detects existing policy violations;
-   evaluates whether a proposed event would complete a prohibited path;
-   reports the nodes and edges involved in a detected violation;
-   retains permission IDs and edge costs for later containment
    analysis.

The Risk Detector does **not** decide which edge or permission should be
blocked. Minimum-disruption containment is handled by later framework
components.

## Detection Modes

### `detect()`

Checks the current graph for active paths that violate registered
policies.

Conceptually:

``` text
Current Dynamic Capability Graph
            |
            v
       Policy Engine
            |
            v
      Active path search
            |
            v
        Violations
```

If no prohibited path currently exists:

``` python
detector.detect()
```

returns:

``` python
[]
```

### `evaluate_event(event)`

Evaluates a proposed event before it is allowed to complete.

This supports pre-enforcement detection. The detector checks whether the
sensitive object already has an active path to the agent proposing the
action and whether the proposed destination satisfies a prohibited
policy.

For the worked example:

``` text
customer_records.csv
        | read
        v
    file_agent
        | delegate
        v
 analysis_agent
        | delegate
        v
   email_agent
        | proposed send
        v
attacker@example.com
```

The first three actions create an active path to `email_agent`. The
proposed external send would extend that path to an external destination
and therefore satisfy `POL-001`.

## Violation Output

Detected violations are represented using the `Violation` model.

A violation contains:

``` text
Violation
|-- policy_id
|-- source
|-- destination
|-- path
`-- edges
    |-- source
    |-- target
    |-- action
    |-- permission_id
    `-- cost
```

An example path is:

``` python
[
    "customer_records.csv",
    "file_agent",
    "analysis_agent",
    "email_agent",
    "attacker@example.com"
]
```

The associated edge information identifies the capabilities that compose
the path:

``` text
customer_records.csv --read------> file_agent
file_agent ----------delegate---> analysis_agent
analysis_agent ------delegate---> email_agent
email_agent ----------send-------> attacker@example.com
```

This information is intended to support later minimum-disruption
containment analysis.

## Policy Matching

The detector compares labels derived from the source and destination
against the labels required by each policy.

For the current `POL-001`:

``` text
Source classification        Destination
---------------------        -----------
confidential                 external
PII                          external
```

Both satisfy the sensitive-data-to-external policy.

Public data does not satisfy the sensitive source condition, and an
internal destination does not satisfy the external destination
condition.

## Active Paths and Containment

Blocked graph edges are excluded from path searches.

For example, before containment:

``` text
customer_records.csv
        v
    file_agent
        v
 analysis_agent
        v
   email_agent
```

is reachable.

If containment blocks:

``` text
analysis_agent --delegate--> email_agent
```

the sensitive resource can still reach `analysis_agent`, preserving the
upstream work, while it can no longer reach `email_agent`.

Re-evaluating the proposed external send then produces no violation
because the required compositional path has been broken.

## Testing

Run the detector tests from the repository root:

``` powershell
python -m pytest -v
```

The current tests cover:

-   no existing policy violation before the external send;
-   confidential data proposed for external transfer;
-   PII proposed for external transfer;
-   public data proposed for external transfer;
-   confidential data proposed for an internal destination;
-   an external send from an agent with no path to the sensitive
    resource;
-   removal of the prohibited path after containment;
-   the node path and edge/permission details returned for a detected
    violation.

## Current Limitations

-   The current implementation focuses on label-based source and
    destination policies.
-   Proposed-event evaluation currently targets the event/path model
    required by the initial sensitive-data exfiltration scenario.
-   Path reporting uses node paths with associated active edge lookup;
    parallel-edge handling will need to become more explicit before
    minimum-disruption optimization relies on individual edge
    identities.
-   Edge costs currently use the prototype cost values supplied by the
    graph.
-   The detector reports prohibited paths but does not select or apply
    containment actions.
-   Risk/severity scoring is separate from the current initial detector
    implementation.
