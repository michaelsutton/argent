# Argent follow-ups

Small design and compiler notes that are worth keeping, but not yet ready for
their own branch or design doc.

## Expanded capsules and route templates

Check what happens when a capsule state is extended by another app, and that
extending app has multiple actors whose route graph requires generated template
fields.

The core invariant to preserve:

- the base capsule ABI observed by another app remains stable
- expanded states can satisfy `actor<BaseCapsule>` handles
- hidden route/template fields needed by the extending app do not leak into the
  observed capsule ABI
- generated state-layout/cut validation rejects mismatched compiled layouts

Useful fixture:

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
`authorized()`, consumed inputs, and output checks?

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

- the asset accepts `controller_id.authorized()` or an equivalent covenant-id
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
