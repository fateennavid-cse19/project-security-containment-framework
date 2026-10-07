# Context Classifier (#5)

## Purpose

The Context Classifier derives security-relevant context from validated
runtime events.

Its role is to convert raw event fields into higher-level contextual
descriptions that can be used by later security components without
making policy or containment decisions itself.

## Responsibilities

The current classifier derives three contextual fields:

-   `trust_boundary`
-   `transfer_context`
-   `sensitive_exposure`

The classifier does **not** determine whether an event violates a
policy, assign risk severity, or decide whether an action should be
blocked.

## Derived Context

### `trust_boundary`

Describes whether an event crosses a trust boundary.

Possible values:

-   `none` --- no destination is involved;
-   `internal` --- the destination remains inside the system;
-   `internal_to_external` --- the event targets an external
    destination.

### `transfer_context`

Describes the type of transfer represented by the event.

Possible values:

-   `none` --- the action is not a `delegate` or `send`;
-   `unknown` --- a transfer action has no destination;
-   `internal_transfer` --- data is transferred to an internal
    destination;
-   `external_transfer` --- data is transferred to an external
    destination.

### `sensitive_exposure`

Describes whether sensitive data is exposed, or whether an exposure was
attempted.

The current sensitive classifications are:

-   `confidential`
-   `pii`

Possible values:

-   `none` --- no sensitive external exposure is represented;
-   `external_exposure` --- sensitive data was successfully transferred
    externally;
-   `attempted_external_exposure` --- an external transfer of sensitive
    data was denied;
-   `unknown` --- sensitive data targets an external destination but the
    result cannot be classified as successful or denied.

## Example

A denied external send of confidential data may produce:

``` python
{
    "trust_boundary": "internal_to_external",
    "transfer_context": "external_transfer",
    "sensitive_exposure": "attempted_external_exposure"
}
```

An internal delegation may produce:

``` python
{
    "trust_boundary": "internal",
    "transfer_context": "internal_transfer",
    "sensitive_exposure": "none"
}
```

## Input

A validated event dictionary containing fields such as:

-   `action`
-   `object`
-   `destination`
-   `result`

## Output

`classify(event)` returns a context dictionary:

``` python
{
    "trust_boundary": "...",
    "transfer_context": "...",
    "sensitive_exposure": "..."
}
```

## Design Boundary

The Context Classifier describes **what kind of security context an
event represents**.

It deliberately does not make conclusions such as:

``` text
"high risk"
"malicious"
"policy violation"
"block this action"
```

Those decisions belong to later components such as the Policy Engine
(#8), Compositional Risk Detector (#9), and containment logic.

## Current Limitations

-   Classification currently uses only information available directly in
    the event.
-   Agent trust is not inferred because authoritative agent-trust
    metadata is not yet available.
-   Permission IDs are not interpreted from their names.
-   Resource subtypes are not inferred from identifiers such as file
    extensions.
-   Goal mismatch analysis is reserved for later development.
