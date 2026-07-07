# Argent Design Notes

Argent is an actor-style frontend for building multi-contract Silverscript apps
as closed, well-formed covenant state machines. This note is a parking lot for
design commitments and, more importantly, the parts still under discussion.

The project is experimental and in very early stages. These notes are not a
specification; they are a working map of the current prototype and the design
pressure we have noticed while studying chess-style Silverscript apps.
They are also not a roadmap or commitment that the project will continue.

## Settled For Now

- Argent emits plain Silverscript, not Silverscript covenant macros.
- User state is declared once with `state`.
- `actor` owns persistent covenant state.
- `entry` declares callable transition paths.
- `emits` declares authorized output shape.
- `become` is tail-dispatch into successor actor state.
- Typed covenant inputs should hide `readInputStateWithTemplate` boilerplate.
- Basic Silverscript data types should stay visible as-is, such as `sig` and
  `pubkey`; Argent should not invent wrapper primitive types.
- Prefix/suffix witnesses are generated Silverscript ABI, not Argent source
  surface.
- Every `become` route must be allowed by the entry's `emits` declaration.
- Covenant input/output shape is a first-class Argent concern, even if syntax is
  still pending.
- The main language/compiler contribution is hiding route logic, template
  propagation, and mechanical safety checks from application code.
- Named actor flows should use a leader-auth output pattern by default.
- True cov-output N:M transitions are singleton per covenant id per transaction;
  Argent should not fight that limitation by default.
- Helper function bodies are expected to already be valid Silverscript-shaped
  code. Argent should not work hard to repair or verify user helper code; that is
  delegated to Silverscript.

## Template Hash Rule

Template hashes must exclude all instance state, including hidden template fields.
The working rule is the chess rule:

```text
template_hash = blake2b(template_prefix || template_suffix)
```

The state bytes live between prefix and suffix, so template references stored in
state do not participate in their own template hash.

## Hidden ABI State

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
- Should `self.state` include hidden ABI state implicitly, or mean only user
  state with compiler-added ABI fields copied around it?

## Bootstrap And Launch Proofs

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

## Transaction Builder Context

Argent source should not expose prefix/suffix witnesses, route proofs, template
preimages, or other Silverscript machinery. A generated transaction builder with
an app context should wrap the lower-level Silverscript builders and supply this
material.

Open questions:

- What exactly lives in the app context?
- Does the context own compiled template witnesses, route proof receipts,
  route-family table preimages, launch proof data, or all of them?
- How does the builder choose the right route preimage for a union output?
- Should the builder expose actor-level methods, entry-level methods, or both?
- How much validation should happen client-side before building the transaction?
- What is the boundary between generated Argent builder code and reusable
  Silverscript builder APIs?

## Route Commitments

The first implemented model uses deterministic route table/proof receipts plus
one-level route-family packing. Upper states can store a family digest, while
actors inside that family store the expanded fixed route table.

Current chess-like pattern:

```text
upper hidden state: gen__mux_template, gen__mux_routes_digest
family hidden state: gen__mux_template, gen__mux_routes
entry witness: route-family table, or template prefix/suffix for selected target
generated checks: blake2b(table) == digest, or slice selected template from table
generated validation: validateOutputStateWithTemplate(...) or validateOutputState(...)
```

The artifact records the receipts behind this shape: route tables, canonical
route proofs, route-family metadata, and witness recipes. The tx builder can
fill the hidden witnesses from those receipts for tests and prototype tooling.

Larger apps may still need deeper Merkle cuts later, but that should replace the
receipt-planning algorithm behind the same artifact concepts instead of changing
the Argent source model.

Open questions:

- What is the canonical route leaf format?
- Does a leaf commit only to a template hash, or also to actor name, state layout,
  entry name, output handle, and route kind?
- Is there one app-wide route root, one root per actor, or both?
- Should direct self-routes use the same Merkle mechanism or a cheaper path?
- When is a flat packed table preferable to a Merkle tree?
- How are multi-template route groups represented, such as chess
  `blake2b(settle_template || player_template)`?
- Should the compiler auto-select flat vs Merkle based on app size, or should the
  source choose?

## Same-Template Shortcuts

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

## Input And Output Shape

The source wants to say:

```ag
require cov.inputs == [self, opponent];
```

The compiler currently emits exact leader covenant input counts and conservative
delegate minimum counts. That is not the final declared-shape rule.

Covenant shape should be first-class in Argent. The source spelling is still
open, but this should not remain ordinary unchecked user body text.

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

## Body Lowering

The current compiler lowers the Stones subset into plain Silverscript. It handles
terminal `become`, simple locals, `if/else`, state constructors, output-handle
values, consumed-input values, and generated route validation.

This is intentionally not a full Argent typechecker yet. The compiler performs
only enough source analysis to lower the prototype. Silverscript remains the
authority for final helper/body validity where possible.

Open questions:

- How much of Argent expression syntax should be Silverscript-like?
- Should Argent own a real expression AST early, or keep copying Silverscript-like
  helper code through?
- How should state constructors lower into hidden-plus-user state structs?
- How should union outputs be lowered when one handle can target several actors?
- What diagnostics should users get when a route needs a missing template witness?
- How much validation belongs in Argent before handing generated Silverscript to
  `silverc`?

## Exact Continuation Protection

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

## Compiler Obligations

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
