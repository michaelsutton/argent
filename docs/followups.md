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
