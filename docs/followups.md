# Argent follow-ups

Small design and compiler notes that are worth keeping, but not yet ready for
their own branch or design doc.

## Expanded capsules and route templates

An app that expands a shared capsule may also need compiler-owned route
commitments for a multi-actor route graph. Those commitments must not occupy a
`virtual` slot: virtual slots are implementation-owned mutable state, while
route commitments are fixed app context.

Use one physical redeem script with two logical cuts:

```text
internal app view:
[ prefix ][ fixed route context ][ concrete state ][ suffix ]

external capsule view:
[ prefix + fixed route context ][ BaseCapsule state ][ suffix ]
```

Internal routes continue to use the app's ordinary generated templates. Their
route commitments do not depend on external handles, so route cycles remain
non-recursive.

The route context is compiler-owned, fixed during bootstrap, and immutable
afterward. It is not authored state even if its serialized bytes occupy the
template-variable region used by the internal cut.

An external `actor_type<BaseCapsule>` handle uses the wider cut. The route
context becomes part of the prefix, leaving only the stable capsule ABI as the
variable region. The handle therefore commits to both the concrete actor and
its bootstrapped route context. The same internal template may have different
external handles in different app route graphs.

Artifact sketch:

```json
{
  "canonical_template_hash": "<canonical-template-hash>",
  "actor_type_handles": {
    "BaseCapsule": "<external-capsule-handle>"
  }
}
```

`canonical_template_hash` identifies the ordinary generated template used by
internal routes. `actor_type_handles.BaseCapsule` identifies the wider
`actor_type<BaseCapsule>` cut exposed to external apps.

Compiler requirements:

- encode route context canonically in a compiler-owned region before the capsule
- initialize that context during bootstrap and preserve it as immutable metadata
- keep virtual slots exclusively for implementation-owned state
- record the external cut, capsule ABI, and route-context encoding in the artifact
- keep internal route commitments independent of external capsule handles
- populate or validate the exact target route context on every internal route;
  validating only the ordinary target template is insufficient
- preserve or reuse the route context when an external transition keeps the
  same `actor_type<BaseCapsule>` handle
- reject incompatible capsule layouts and cut descriptors before building a
  transaction

Fixture:

```rust
state AgentCapsule {
    covid controller_id;
    virtual strategy;
}

state ForagerState expands AgentCapsule {
    strategy: ForagerStrategy;
}

state TraderState expands AgentCapsule {
    strategy: TraderStrategy;
}

actor Forager owns ForagerState {
    entry become_trader() emits one Trader {
        become Trader(next_trader);
    }
}
```

## Leader and delegate entrypoint relations

Clarify how paired transaction inputs relate when one entrypoint leads a
transition and another entrypoint authorizes or mirrors it.

Things to make explicit in docs/tests:

- co-spend presence proves only that a covenant id appears in the transaction
- peer covenant ids in state bind which counterparty is authorized
- shared output validation is what makes two inputs agree on the same transition
- runtime builder pairing is convenience, not covenant security

Open question: should Argent eventually have source syntax for declaring a
paired entry relation, or should this remain expressed through `observes`,
`co_spent()`, consumed inputs, and output checks?

## Correlated output variants

Allow `emits` to declare valid combinations of output actors rather than only
an independent actor union for each output:

```rust
emits {
    left: A;
    right: B;
} | {
    left: C;
    right: D;
}
```

This represents `(A x B) | (C x D)`. The current form:

```rust
emits {
    left: A | C;
    right: B | D;
}
```

represents `(A | C) x (B | D)` and leaves the entry body to reject the invalid
cross-combinations.

Initially require every alternative to use the same named output handles and
ordering. The compiler should verify that each internal terminal route set
matches one declared alternative. The artifact should record the source-level
alternatives so a typed builder can match concrete outputs without exposing a
terminal path index.

## Genesis launch roots

Expose artifact/runtime guidance for actors that look genesis-created: actors
with no incoming non-self creation route in the app graph.

This should probably feed a future launch-plan API or warning, not the low-level
`populate_genesis_covenants` helper. The low-level helper should keep doing
exactly what the caller asked for: bind the provided transaction output groups.

The useful invariant is advisory: if an actor has no way to be created by
another actor in the same covenant, a launcher likely needs to create at least
one genesis output for it, unless the app intentionally leaves that actor
unlaunched.

## Launch proofs

Support producing and verifying a launch proof for one genesis covenant group.
Each group launches one covenant; a transaction that launches multiple covenants
can carry multiple launch proofs.

The proof should include:

- the authorizing funding outpoint
- the covenant id derived from that outpoint and the ordered launch outputs
- each initial actor state
- each output's redeem-script preimage: template prefix, encoded state, template
  suffix
- each corresponding P2SH script public key

Verification should show:

- the actor state encodes to the claimed redeem script
- the redeem script hashes to the launch output script public key
- the ordered outputs and authorizing outpoint recompute the covenant id

The goal is to explain a covenant id already seen in a live UTXO: given the
funding outpoint and initial actor states, show exactly how that id was
launched, so auditing the contracts and initial states gives confidence in the
live covenant.

## ICC controller/asset bootstrap

Document the safe bootstrap pattern for assets whose state authorizes a
controller by covenant-id co-spend.

The delicate case:

- the asset accepts `controller_id.co_spent()` or an equivalent covenant-id
  co-spend check
- the controller is not yet bound to the asset covenant id
- a controller init transaction can accidentally authorize unrelated asset
  spends unless it proves the asset is being created at the same boundary

The recommended pattern is:

- create an uninitialized controller covenant first
- create the asset covenant and initialize the controller in the same
  transaction
- have controller init bind to the asset output covenant id
- have controller init also prove that the asset output is genesis-created, not
  a continuation of an existing asset spend

The proof should check that the asset output is authorized by the controller
init input and that the authorizing input is not already the same asset covenant
id. This keeps the launch easy to audit: the asset id is born at the same point
where the controller becomes bound to it, so later controller co-spends cannot
retroactively cover an unchecked pre-existing asset transition.
