# Argent follow-ups

This file contains small follow-up items. Each item gives its area, context,
and required work.

## Entry-wide template witness deduplication

**Area:** Compiler lowering, artifact recipes, `argent-rt`, generated Sil, and
size tests.

**Context:** Generated Sil uses template witnesses to validate actor inputs and
outputs. The compiler already shares template information between `consumes`
and direct `emits`. It also shares within one `observes` block and across
`spawns` blocks that use the same fixed actor or source `actor_type` value.

The witness-form rule is established:

- Input-only and input-plus-output use prefix and suffix lengths.
- Output-only uses prefix and suffix bytes.

Sharing stops at the current planner-group boundaries. The same template
identity can receive separate witnesses when it appears in direct routes,
`observes`, and `spawns`.

**Follow-up:** Reuse one template identity across all entry clauses when
appropriate. Uses of the same fixed actor have one identity. Uses of the same
source `actor_type<State>` value also have one identity. Separate open actor
bindings remain distinct.

Apply the existing witness-form rule after this entry-wide grouping. Record the
shared identity in the artifact so `argent-rt` supplies the witness once.

Existing fixtures pin sharing for `consumes` and `emits`, one `observes` block,
and repeated spawn targets. Add generated Sil and signature-script size tests
for these remaining cases:

- one actor used by direct `emits` and `spawns`
- one `actor_type` value used by `observes` and `spawns`
- one actor used by two `observes` blocks

## Decode observed application transactions

**Area:** `argent-rt`, the artifact ABI, and application observers or indexers.

**Context:** An observer can use covenant IDs to find raw Kaspa transactions
that belong to an application. It must decode the input actor state, the entry
call, and the output actor states. It uses these values to reconstruct the
application state.

The Argent artifact describes both user-declared ABI values and generated ABI
values.

Application code must currently know generated field or argument names such as
`gen__mux_routes`. These names are compiler details. An actor rename can change
them and break an observer.

**Follow-up:** Add `argent-rt` helpers that use the artifact to decode
application transactions. Return user-declared values with their source names.
Provide stable accessors for generated templates and route data.

Validate the actor, entry, state layout, and value types against the artifact.
Add a test in which an actor rename changes generated ABI names. The observer
must continue to work without a code change.

## Launch proofs

**Area:** `argent-rt`, launch APIs, and audit tools.

**Context:** One genesis output group launches one covenant. The covenant ID
depends on the authorizing funding outpoint and the ordered outputs. One
transaction can launch more than one covenant.

An auditor can find a live covenant UTXO without knowing its launch transaction
or initial actor states.

Argent has no standard proof package that explains how a live covenant ID was
launched. An auditor must collect and check the launch data manually.

**Follow-up:** Support one launch proof for each genesis covenant group. A
transaction that launches multiple covenants can have multiple proofs.

The proof must contain:

- The authorizing funding outpoint.
- The covenant ID that the system calculates from the outpoint and the ordered
  launch outputs.
- Each initial actor state.
- The redeem-script preimage for each output. This preimage contains the
  template prefix, the encoded state, and the template suffix.
- The related P2SH script public key for each output.

Verification must prove:

- The actor state encodes to the specified redeem script.
- The redeem script hashes to the launch-output script public key.
- The ordered outputs and the authorizing outpoint produce the specified
  covenant ID.

This proof lets an auditor confirm which contracts and initial states started
the live covenant.

## KCC20 bootstrap with `spawns`

**Area:** ICC examples, ICC documentation, and `argent-rt` runtime tests.

**Context:** The Argent KCC20 example has a `Minter` controller app and a
KCC20 asset app. During mint, `Minter` observes the asset-side `MinterProxy`.
The controller state stores the asset covenant ID.

The `kcc20_covenant_minter` test in Silverscript uses two transactions:

1. Launch an uninitialized `Minter` covenant.
2. Create the asset covenant and initialize `Minter` in the same transaction.

The Argent example implements mint but does not implement this bootstrap
sequence. It does not show how the controller receives the asset covenant ID.

**Follow-up:** Add `Minter::init`. Use `spawns` to create the asset covenant. Do
not add a separate genesis proof. The `spawns` lowering already proves that the
active `Minter` input creates the declared covenant group.

Use an `actor_type<MinterProxyState>` value for the proxy. Store it in the
uninitialized controller state. The controller needs this value because
`MinterProxy` belongs to a different app.

The entry has this shape:

```rust
entry init(sig owner_sig)
spawns asset by asset_id {
    outputs {
        proxy: self.proxy_type,
    }
}
emits one Minter {
    require(!initialized);
    require(checkSig(owner_sig, owner));

    MinterProxyState proxy_state = {
        controller_id: self.covenant_id,
    };
    require asset.outputs become {
        proxy <- self.proxy_type(proxy_state),
    };

    MinterState next_controller = {
        owner: owner,
        proxy_type: proxy_type,
        kcc20_covid: asset_id,
        amount: amount,
        initialized: true,
    };
    become Minter(next_controller);
}
```

Use the `spawn::asset` path in `argent-rt`. Add a runtime test for bootstrap
followed by mint. Add the source example to the ICC documentation. This work
does not need new spawn lowering.

## Correlated output variants

**Area:** Language syntax, compiler route analysis, artifacts, and typed
builders.

**Context:** An `emits` declaration can give each output a union of possible
actors. The compiler treats each output union independently.

For example:

```rust
emits {
    left: A | C,
    right: B | D,
}
```

This declaration permits `(A, B)`, `(A, D)`, `(C, B)`, and `(C, D)`.

An application can require only `(A, B)` or `(C, D)`. The current syntax cannot
declare this relationship. The entry body must reject `(A, D)` and `(C, B)`.
The artifact also cannot describe the relationship to a typed builder.

**Follow-up:** Let `emits` declare valid output groups:

```rust
emits {
    left: A,
    right: B,
} | {
    left: C,
    right: D,
}
```

This form permits only `(A, B)` and `(C, D)`.

At first, all alternatives must use the same output names and order. The
compiler must verify that each terminal route uses one declared alternative.
The artifact must record the source alternatives. A typed builder can then
match the outputs without exposing a terminal path index.
