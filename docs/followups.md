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

## Open observation: shape checks vs. behavioural checks

Open ICC (`observes { inputs { actor<State> as x } }`) proves *shape*, not
*behaviour*. The observer confirms a covenant of the expected actor/state layout
is present in the transaction; it does not re-execute that covenant's body. The
observed covenant is a separate input that validates itself against its own
script.

This is sound as long as observers only *read* fields they can independently
constrain. The subtle case is when an observer writes an output whose contents
are lifted from an observed peer via an *unconstrained* hidden witness. In
`open_icc/core.ag`, `Cell.advance` fills the new occupant's `strategy` from a
witness (`gen__remote_agent_next_strategy`) that the Cell covenant does not tie
back to the observed agent's own transition. A misbehaving agent implementation
could therefore let a Cell advance with a strategy the agent itself would never
have produced. The observed agent still validates *its* own output, so this is
safe when the agent is well-behaved, but the coupling is behavioural, not
enforced by the Cell.

Worth deciding explicitly:

- document that open observation is a shape contract, and that any field an
  observer copies out of an observed peer must either be re-derived by the
  observer or be validated by the peer's own transition in the same tx
- consider a lint: warn when a hidden witness feeds an output state field that
  originates from an observed-but-not-re-executed covenant

## In-script hashing: BLAKE2b vs BLAKE3 cost

The generated Silverscript verifies template hashes, route-family tables, and
virtual-slot preimages with `blake2b` (see the route-family digest check and the
`Forager` virtual-slot unpack). On Toccata, BLAKE3 costs ~1 SU/byte versus
BLAKE2b's ~2 SU/byte, and the per-input SU allowance is bounded by the committed
compute budget. Route tables (`byte[N*32]`) and expansion preimages are the
largest things hashed in-script, so the hash choice directly scales the SU cost
of the widest-fan-out actors.

Worth deciding explicitly: is BLAKE2b a hard requirement (e.g. it must match the
covenant-id hash the protocol computes), or is it an internal Argent choice for
template/route/slot commitments that could switch to BLAKE3 and roughly halve
the hashing SU on the hot path? If the covenant id itself is BLAKE2b-derived,
the id check is fixed, but the *internal* commitments (route digest, slot
digest) are Argent's own and could differ.
