# Argent design notes

Argent is an actor-style frontend for building multi-contract Silverscript apps
as well-formed covenant state machines. This document captures design choices
and the parts still under discussion.

The focus is the compiler/runtime boundary: generated Silverscript, portable
artifacts, ICC flows, route families, and the source features needed to make
those pieces usable from Argent.

## Settled for now

- Argent emits plain Silverscript, not Silverscript covenant macros.
- User state is declared once with `state`.
- `actor` owns persistent covenant state.
- `entry` declares callable transition paths.
- `emits` declares authorized output shape.
- `become` is tail-dispatch into successor actor state.
- Typed covenant inputs hide `readInputStateWithTemplate` boilerplate.
- Basic Silverscript data types stay visible as-is, such as `sig` and `pubkey`;
  Argent does not invent wrapper primitive types for them.
- Prefix/suffix witnesses are generated Silverscript ABI, not Argent source
  surface.
- Every `become` route must be allowed by the entry's `emits` declaration.
- Covenant input/output shape is a first-class Argent concern, even while the
  source syntax evolves.
- The main language/compiler contribution is hiding route logic, template
  propagation, and mechanical safety checks from application code.
- Named actor flows use a leader-auth output pattern by default.
- True cov-output N:M transitions are singleton per covenant id per transaction;
  ordinary named actor flows use auth-output coordination instead.
- Helper function bodies are expected to already be valid Silverscript-shaped
  code. Silverscript remains responsible for final helper/body validity where
  Argent has not lowered the expression itself.

## Surface syntax conventions

Argent uses different word orders for declarations and bindings. The syntax
reflects the purpose of each construct.

Declarations and value bindings follow Silverscript syntax. Argent-specific
transaction clauses extend the binding model to transaction roles and routes.

### Declarations

State fields, local variables, and callable parameters are declarations. A
declaration puts the type before the name.

```rust
state WalletState {
    int credits;
    pubkey initializer;
}

entry transfer(pubkey pk, int amount)
```

Type-first declarations preserve a direct high-level-to-Sil surface.

### Value bindings

A state value expression binds each field name to a value expression. A colon
separates the field name from the value expression. Commas separate the
bindings.

```rust
AgentCapsule next_agent = {
    energy: prev_state.energy - 1,
    generation: prev_state.generation,
};
```

`AgentCapsule next_agent` is a type-first declaration. The items in the braces
are value bindings. The final semicolon terminates the declaration.

### Role bindings

The `consumes`, `emits`, `spawns`, and `observes` clauses bind role names to
actor targets. A colon separates the role name from the actor target. Commas
separate the role bindings.

An actor target can be a fixed actor or a dynamic actor handle. This `observes`
clause uses a dynamic actor handle:

```rust
observes remote by self.agent_cov_id {
    inputs {
        agent: self.agent_type,
    }

    outputs {
        agent: self.agent_type,
    }
}
```

`agent` is the role name. `self.agent_type` selects the actor
implementation at runtime.

### Route bindings

A `become` block binds each output role to its next actor and state. The `<-`
operator separates the output role from the successor expression. Commas
separate the route bindings.

```rust
become {
    white_out <- Player(next_white),
    black_out <- Player(next_black),
};
```

`white_out` and `black_out` refer to roles in the `emits` clause. The final
semicolon terminates the `become` statement.

### Consistency rule

Declarations put the type before the declared name. Value, role, and route
bindings put the local name on the left. Commas separate items in binding
lists. Semicolons terminate declarations and statements.

## Execution context ladder

Silverscript provides `tx` and `this`. Argent adds `self`. Together, these names
form an abstraction ladder:

```text
tx      complete transaction
this    active consensus input and script
self    logical Argent actor
```

For example, `tx.outputs[i].value` reads the transaction, and
`this.activeInputIndex` identifies the input that runs the script.

The ladder moves through three abstraction levels. `tx` exposes the complete
transaction. `this` identifies the active input and script. `self` presents the
active input as a logical Argent actor.

`self` is a context namespace. It is not an actor handle or another first-class
actor value. Its valid and reserved members are:

```text
self.value  // Native KAS value of the UTXO consumed by the active input.
            // Type: int.
self.state  // Complete typed source-level state owned by the actor.
            // Type: the state named in the actor's owns clause.
self.cov_id // Reserved.
self.type   // Reserved.
self.ref    // Reserved.
```

An actor's effective top-level state cannot declare `state`, `value`, `cov_id`,
`type`, or `ref` as a field. This rule also applies to base fields and expansion
slots that are exposed by an expanded owned state.

The rule does not apply to fields of a nested state value. For example, the
`value` field below is valid because it is accessed through `payload`:

```rust
state Payload {
    int value;
}

state WalletState {
    Payload payload;
}
```

## Template hash rule

Template hashes must exclude all instance state, including hidden template fields.
The working rule is the chess rule:

```text
template_hash = blake2b(i64le(template_prefix.length) || template_prefix || i64le(template_suffix.length) || template_suffix)
```

The state bytes live between prefix and suffix, so template references stored in
state do not participate in their own template hash.

## Hidden ABI state

Template fields are hidden ABI state, not source-level user fields.

The compiler may add fields such as:

```text
gen__player_template
gen__game_template
gen__mux_routes_digest
```

Ordinary transitions must preserve these exactly. Bootstrap or explicit handoff
paths are the only places where hidden ABI state may be initialized or changed.

Open questions:

- Should imports name required symbols explicitly, such as
  `import PlayerState, GameState, player_ref from "./types.ag";`?
- Should hidden ABI fields be emitted as leading state fields, a named generated
  struct prefix, or another ABI convention?
- Do we need explicit source syntax for privileged bootstrap/handoff paths?
- How should generated code prevent user code from accidentally shadowing hidden
  field names?

## Bootstrap and launch proofs

The initial hidden ABI fields are correct because bootstrap constructs them
correctly. Later transitions preserve them.

The launch proof should let an auditor verify the current app from current UTXOs
plus opened covenant-id/bootstrap preimages, without replaying all history.

Open questions:

- What exact launch artifact should Argent generate?
- Is bootstrap a generated transaction builder, a manifest, a proof object, or
  all three?
- How do we represent one-time init paths in the source language?
- How much launch proof checking belongs in Argent tooling vs external auditors
  and indexers?
- What does a minimal proof for the Stones example look like?

## Transaction builder context

Argent source should not expose prefix/suffix witnesses, route proofs, template
preimages, or other Silverscript machinery. The `argent-runtime` crate provides
the current artifact-level `TxBuilder`; a future generated transaction builder
with an app context can wrap that lower-level surface and supply this material
behind app-specific methods.

Open questions:

- What exactly lives in the app context?
- Does the context own compiled template witnesses, route proof receipts,
  route-family table preimages, launch proof data, or all of them?
- How does the builder choose the right route preimage for a union output?
- Should the builder expose actor-level methods, entry-level methods, or both?
- How much validation should happen client-side before building the transaction?
- What is the boundary between generated Argent builder code and reusable
  Silverscript builder APIs?

## Route commitments

The route planner builds a deterministic commitment forest. Each actor gets a
cut that contains concrete actor templates and packed family digests. A route
transition keeps common nodes, opens packed families, and packs families that
the target does not need open.

The implementation separates three parts:

```text
graph classification -> commitment forest and cuts -> SIL lowering
```

Graph classification defines the current family and cohort policy. Commitment
planning has no Argent AST or SIL data. SIL lowering uses each cut transition to
generate fields, table witnesses, hashes, and output checks.

The planner data model supports nested commitment branches. Compiler lowering
currently supports one-level family tables. The artifact records route tables,
family metadata, cut-based receipts, and witness recipes. `argent-runtime` uses
these receipts to fill hidden witnesses.

[Route Planning](route-planner.md) defines the terms, policy, algorithms, and
compiler boundary. [Routing Optimization Opportunities](../src/routing/optimization.md)
records known cases where the current policy produces correct but inefficient
cuts.

Open questions:

- When should the planner create nested helper branches?
- Should source code or compiler configuration provide forest hints?
- When should the planner use a flat table instead of nested branches?
- How should the planner improve cohort selection without weakening cut
  equality or dependency propagation?

## Same-template shortcuts

Same-template outputs should use the cheaper same-script validation path.

Desired lowering rule:

```text
become self_template_actor(next_state)
  -> validateOutputState(output_idx, next_state)

become foreign_template_actor(next_state)
  -> validateOutputStateWithTemplate(output_idx, next_state, prefix, suffix, template_hash)
```

This should remove prefix/suffix witness parameters for outputs that continue
the active input's template, such as `League -> League`, `Player -> Player`, or
`StonesGame -> StonesGame`.

Input reads are subtler. A consumed peer may have the same actor type as the
active input, but covenant grouping alone does not prove that the peer input's
redeem script is really the same template. For peer inputs, even same-actor
inputs should keep `readInputStateWithTemplate(...)` unless another explicit
proof establishes same-template identity.

Safe default:

```text
self/current input fields:
  use contract fields, or readInputState(this.activeInputIndex) when a State value is needed

consumed peer input:
  use readInputStateWithTemplate(peer_idx, prefix_len, suffix_len, expected_template)
```

This matches the chess `delegate_start_game` pattern: it reads another `Player`
with `readInputStateWithTemplate` so the delegate independently proves that the
leader input is really a Player template, not just an arbitrary input in the same
covenant group.

Open questions:

- Should Argent infer same-template output shortcuts automatically? Probably yes.
- Should source syntax expose "already proven same template" peer inputs, or keep
  the conservative template-read default?
- Can the transaction builder carry reusable proof metadata so same-template peer
  inputs can opt into `readInputState(...)` safely in special cases?

## Input and output shape

The source wants to say:

```ag
require cov.inputs == [self, opponent];
```

The compiler currently emits exact leader-entry covenant input counts and conservative
delegate minimum counts. The source-level shape model can become more explicit.

Covenant shape should be first-class in Argent. The source spelling is still
open, but the shape belongs in declarations rather than unchecked user body
text.

Default actor-app lowering should use a coordinator shape:

```text
leader input:    reads peer inputs through OpCovInput*
leader outputs:  validates successors through OpAuthOutput*
delegate inputs: verify they are not leader and require OpAuthOutputCount(active) == 0
```

This still uses covenant input grouping for many-input transitions, but it avoids
covenant outputs for ordinary named actor flows. The practical upside is that
`1:N` auth-output groups can coexist naturally in one transaction, while true
`N:M` cov-output transitions remain singleton per covenant id per transaction.

True cov-output lowering should be reserved for explicit set-like transitions,
if Argent supports them later.

Open questions:

- What is the right declaration syntax for covenant input shape?
- Do delegate entries need a first-class notation for "same transaction, no
  outputs from me"?
- Should output handles always be named, even for `emits one`?
- How should output value policies be expressed without making `become` carry
  value rules?
- Should `cov[n]` and `auth[n]` remain explicit indexes or become named output
  handles?
- Do we need any source-level escape hatch for explicit cov-output transitions?

## Body lowering

The current compiler lowers the Stones subset into plain Silverscript. It handles
terminal `become`, simple locals, `if/else`, state constructors, output-handle
values, consumed-input values, and generated route validation.

Argent does not yet own a full source typechecker. The compiler performs the
analysis needed for lowering and leaves final helper/body validity to
Silverscript where possible.

Open questions:

- How much of Argent expression syntax should be Silverscript-like?
- Should Argent own a real expression AST early, or keep copying Silverscript-like
  helper code through?
- How should state constructors lower into hidden-plus-user state structs?
- How should union outputs be lowered when one handle can target several actors?
- What diagnostics should users get when a route needs a missing template witness?
- How much validation belongs in Argent before handing generated Silverscript to
  `silverc`?

## Exact continuation protection

Chess-style player and league continuations show that multi-actor apps need
actor-instance preservation discipline, not just template checks.

Open questions:

- Which continuation invariants should Argent infer from actor/state
  declarations?
- Which should remain explicit `require(...)` code?
- Should "same actor instance, same hidden ABI state" become a reusable generated
  pattern?
- How should settlement actors prove they are closing exactly the intended live
  actors?

## Compiler obligations

Argent-generated code must eventually enforce:

- exact covenant input shape where declared
- exact authorized output shape where declared
- hidden ABI state preservation
- typed foreign input template checks
- same-template output validation through `validateOutputState` where applicable
- route commitment membership checks
- successor state validation with the chosen template
- no `become` route outside the entry's declared `emits` set

Anything not generated must be obvious in source and reviewable as application
logic.
