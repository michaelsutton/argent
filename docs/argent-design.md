# Argent Design Notes

Argent is an actor-style frontend for multi-contract Silverscript apps. This
note is a parking lot for design commitments and, more importantly, the parts
still under discussion.

## Settled For Now

- Argent emits plain Silverscript, not Silverscript covenant macros.
- User state is declared once with `state`.
- `actor` owns persistent covenant state.
- `entry` declares callable transition paths.
- `emits` declares authorized output shape.
- `become` is tail-dispatch into successor actor state.
- Typed covenant inputs should hide `readInputStateWithTemplate` boilerplate.
- Prefix/suffix witnesses are generated Silverscript ABI, not Argent source
  surface.
- Every `become` route must be allowed by the entry's `emits` declaration.
- Covenant input/output shape is a first-class Argent concern, even if syntax is
  still pending.
- Named actor flows should use a leader-auth output pattern by default.
- True cov-output N:M transitions are singleton per covenant id per transaction;
  Argent should not fight that limitation by default.

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
__template_player
__template_game
__route_root
```

Ordinary transitions must preserve these exactly. Bootstrap or explicit handoff
paths are the only places where hidden ABI state may be initialized or changed.

Open questions:

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
- Does the context own compiled template witnesses, route roots, launch proof
  data, or all of them?
- How does the builder choose the right route preimage for a union output?
- Should the builder expose actor-level methods, entry-level methods, or both?
- How much validation should happen client-side before building the transaction?
- What is the boundary between generated Argent builder code and reusable
  Silverscript builder APIs?

## Route Commitments

Small apps can use an expanded route table. Larger apps probably need a Merkle
root of template hashes and route metadata.

The general pattern:

```text
hidden state: route_root
entry witness: route leaf + Merkle branch + template prefix/suffix
generated check: leaf belongs to route_root
generated validation: validateOutputStateWithTemplate(...)
```

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

## Input And Output Shape

The source wants to say:

```ag
require cov.inputs == [self, opponent];
```

The compiler currently only emits a loose minimum count check. That is not the
final rule.

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
- Should `cov[n]` and `auth[n]` remain explicit indexes or become named lanes?
- Do we need any source-level escape hatch for explicit cov-output transitions?

## Body Lowering

The current compiler parses structure and extracts `become` routes, but does not
lower ordinary entry bodies yet.

Open questions:

- How much of Argent expression syntax should be Silverscript-like?
- Should helper functions lower by copying their raw bodies, or should Argent own
  a real expression AST early?
- How should state constructors lower into hidden-plus-user state structs?
- How should union outputs be lowered when one handle can target several actors?
- What diagnostics should users get when a route needs a missing template witness?

## Lane Protection

Chess-style player and league lanes show that multi-actor apps need state-lane
discipline, not just template checks.

Open questions:

- Which lane invariants should Argent infer from actor/state declarations?
- Which should remain explicit `require(...)` code?
- Should "same lane, same hidden ABI state" become a reusable generated pattern?
- How should settlement actors prove they are closing exactly the intended live
  lanes?

## Compiler Obligations

Argent-generated code must eventually enforce:

- exact covenant input shape where declared
- exact authorized output shape where declared
- hidden ABI state preservation
- typed foreign input template checks
- route commitment membership checks
- successor state validation with the chosen template
- no `become` route outside the entry's declared `emits` set

Anything not generated must be obvious in source and reviewable as application
logic.
