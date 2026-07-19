# Argent follow-ups

Small design and compiler notes that are worth keeping, but not yet ready for
their own branch or design doc.

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

## Entry-wide template witness deduplication

Build one template-witness plan for the whole entry instead of planning
`emits`, `observes`, and `spawns` independently. The current spawn lowering
already shares prefix and suffix bytes between spawn outputs that use the same
`actor_type` expression; extend that rule across all entry clauses.

Deduplicate by semantic template identity, not by output handle or state type:

- references to the same fixed actor, including imported actors, are identical
- repeated uses of the same source `actor_type<State>` value are identical
- independent open actor bindings remain distinct even when they expose the
  same state type

Keep transaction locations separate from template identity. Every input and
output still needs its own index, while template bytes, lengths, hashes, and
route proofs may be shared.

The planner must also choose the witness form for each identity:

- input-only validation needs prefix and suffix lengths
- output-only validation needs prefix and suffix bytes
- an output may reuse a matching input template
- identities used by both read and write paths need one deliberate choice
  between input reuse and passing bytes from which lengths can be derived

Pin representative generated Sil and sigscript-size changes so later clause
lowering does not reintroduce duplicate template witnesses.

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
