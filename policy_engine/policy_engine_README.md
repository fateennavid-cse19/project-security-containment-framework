# Policy Engine (#8)

## Purpose

The Policy Engine defines the security rules that describe prohibited
states or paths in the multi-agent system.

It provides these policies to the Compositional Risk Detector (#9),
which determines whether the current graph or a proposed event satisfies
the conditions of a prohibited policy.

## Responsibilities

The Policy Engine:

-   stores the active security policies;
-   provides policies to the Risk Detector;
-   defines the labels that identify prohibited source and destination
    combinations.

The Policy Engine does **not** search the graph, detect paths, assign
containment actions, or decide which capability should be blocked.

## Policy Structure

A policy contains:

``` text
policy_id
name
source_labels
destination_labels
description
```

The `source_labels` identify protected or restricted source nodes, while
`destination_labels` identify destinations to which those sources must
not become reachable.

## Current Policy

### POL-001 --- Sensitive Data to External Destination

The initial policy prevents sensitive information from becoming
reachable at an external destination.

``` python
source_labels = {"confidential", "pii"}
destination_labels = {"external"}
```

Conceptually:

``` text
confidential / PII
        |
        | prohibited active path
        v
external destination
```

The policy does not specify how many agents may occur between the source
and destination. Detecting those multi-step paths is the responsibility
of the Compositional Risk Detector.

## Policy Engine

The `PolicyEngine` maintains the active policy collection.

For example:

``` python
policy_engine = PolicyEngine()
policies = policy_engine.get_policies()
```

The current prototype initially registers `POL-001`.

## Relationship to the Risk Detector

``` text
Policy Engine (#8)
      |
      | defines what is prohibited
      v
Compositional Risk Detector (#9)
      |
      | searches/evaluates paths
      v
Violation
```

This separation allows policies to describe security requirements
without embedding graph-search logic inside the policy definitions.

## Current Limitations

-   Policies are currently defined in Python rather than loaded from an
    external configuration file.
-   The initial implementation contains a small policy set focused on
    the worked sensitive-data exfiltration scenario.
-   Risk severity is not currently part of the policy definition.
-   Policies do not choose containment actions or calculate
    minimum-disruption cuts.
