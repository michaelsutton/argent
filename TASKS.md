# Argent Compiler Task Plan

This file turns the current ICC and Open Lattice sketches into an implementation
sequence. The order is intentional: every task should be independently
reviewable and end-to-end testable, and each task should be at least one clean
commit. Larger tasks may deserve a PR with a few commits.

## Architectural North Star

Argent should have two separate runtime worlds:

```text
compile time:
  Argent source -> generated Silverscript -> silverscript-lang -> portable Argent artifact JSON

transaction time:
  portable Argent artifact JSON + UTXOs + user intent -> transaction
```

The compiler may depend on `silverscript-lang`. The transaction builder must not.

The current Silverscript `CompiledContract` JSON is not the artifact boundary we
want. It contains compiler-shaped data such as AST nodes and helper APIs that
consume `Expr` and `TypeRef`. Argent needs a smaller portable artifact that
contains only runtime facts:

- script bytes;
- template prefix, suffix, state span, and template hash;
- actor, state, field, entrypoint, and route metadata;
- structural type descriptors, not raw Silverscript type strings;
- hidden witness recipes for template proofs, observed lanes, generic actor
  witnesses, and expanded digest state;
- enough metadata for a small builder library to construct transactions without
  linking compiler crates.

The builder still needs a Silverscript-compatible ABI and state codec subset. It
should not parse Silverscript source. It should deserialize structural type JSON
and implement the push/encode/decode rules required by generated contracts.

## End-to-End Standard

Every feature task below should have a positive and negative end-to-end test:

```text
Argent source
  -> generated Silverscript
  -> compiled scripts
  -> portable artifact JSON
  -> artifact-only builder constructs tx
  -> txscript execution accepts the valid tx
  -> txscript execution rejects at least one malformed tx
```

During the early tasks it is acceptable for tests to use `silverscript-lang` as a
fixture generator. The builder code under test must not depend on it.

## Guardrails

- Do not let the portable builder depend on compiler AST, `Expr`, `TypeRef`, or
  raw Silverscript source parsing.
- Store structured types in the artifact. Keep a display string only for
  diagnostics.
- Version the artifact from the first commit. Add a schema version and compiler
  version, and reject unknown incompatible versions.
- Treat template hash calculation as consensus-sensitive: the hash is
  `blake2b(prefix || suffix)` and must exclude all state bytes.
- Keep covenant state fixed-size where scripts need byte offsets. Variable user
  data belongs behind a fixed digest field.
- Do not let route metadata and generated Silverscript drift. They must be
  derived from the same compiler model in one pass.
- Do not expose hidden compiler machinery as user entrypoint arguments.
- Prefer explicit failure tests for wrong template hash, wrong output order,
  wrong covenant id lane, wrong hidden witness, bad digest preimage, and swapped
  generic actor template.

## Task List

### 1. Define Portable Artifact Schema

Status: done.

Create a versioned artifact model in Argent, separate from compiler internals.
This can start as one module and later move to a small crate.

Minimum contents:

- app name and artifact version;
- actor list;
- per-actor script bytes;
- per-actor template prefix, suffix, state span, and template hash;
- structural state fields;
- structural entrypoint args;
- output handles;
- hidden witness declarations;
- route metadata for current `become` paths.

The structural type model should cover the subset currently emitted by Argent:
`int`, `bool`, `byte`, fixed bytes, dynamic bytes where allowed, fixed arrays,
dynamic arrays where allowed, and structs.

End-to-end test:

- Build `examples/tickets.ag`.
- Emit artifact JSON.
- Deserialize it with a test that imports no compiler AST types.
- Assert script/template/state metadata is present and stable in a snapshot.

Obstacle to handle:

- Existing Silverscript ABI exposes type names as strings. The artifact should
  lower them into structured JSON before the builder sees them.

### 2. Compile Generated Silverscript During Argent Build

Status: done.

Teach `argentc build` to optionally compile each generated `.sil` actor through
`silverscript-lang` at compile time. The output should still include the plain
generated `.sil` files for audit.

End-to-end test:

- Build `examples/tickets.ag` and `examples/stones/app.ag`.
- Verify every generated actor compiles.
- Verify each artifact actor has script bytes and a template hash.

Obstacle to handle:

- Constructor arguments for generated template fields are circular if they are
  treated as final template hashes too early. Start with the existing flat
  template-field bootstrap model, then record exactly which constructor args are
  hidden template inputs.

### 3. Project `CompiledContract` Into Portable Artifact

Status: done.

Add a projection layer:

```text
CompiledContract + Argent model -> PortableActorArtifact
```

This layer is allowed to read `CompiledContract`, AST field declarations, and
ABI entries. Its output must not contain those types.

End-to-end test:

- Compile a small actor.
- Extract prefix and suffix from `state_layout`.
- Reconstruct `script == prefix || state_bytes || suffix` for the initial state.
- Verify `template_hash == blake2b(prefix || suffix)`.

Obstacle to handle:

- State field order is consensus-significant. The projection must record field
  order exactly as generated, including hidden template fields.

### 4. Implement Artifact-Only ABI And State Codec

Status: done.

Implement a small runtime codec driven only by the portable type descriptors.
This codec should encode:

- entrypoint arguments into sigscript stack pushes;
- state values into the push-only state script segment;
- structs by declared field order;
- arrays and fixed byte arrays exactly like generated Silverscript expects.

End-to-end test:

- For fixture contracts, compare artifact-codec sigscripts with
  `CompiledContract::build_sig_script`.
- Decode a compiled redeem script state segment and re-encode it byte-for-byte.

Obstacle to handle:

- The current compiler helper accepts AST literals. The artifact codec needs its
  own runtime value representation, for example JSON values or a small
  `ArtifactValue` enum.

### 5. Split Argent Artifact From Sil ABI Artifact

Separate the coordination metadata owned by Argent from the bytecode ABI
metadata owned by the generated Sil contract layer.

The split should make the current artifact look conceptually like:

```text
Argent artifact
  actors, routes, consumes, emits, become metadata, hidden witness recipes

Sil ABI artifact
  script bytes, entry ABI, selector, state layout, type descriptors,
  state field order, prefix/suffix/template hash, codec contract
```

End-to-end test:

- Build `examples/tickets.ag`.
- Deserialize the outer Argent artifact and inner Sil ABI artifact without
  importing compiler AST types.
- Use the Sil ABI artifact with the artifact-only codec to reproduce the same
  sigscript and state roundtrip coverage from task 4.
- Assert Argent route metadata refers to inner Sil ABI actor ids instead of
  duplicating bytecode ABI fields.

Obstacle to handle:

- This is a boundary cleanup, not a new source feature. Keep JSON migration
  straightforward while making the future replacement path clear: if
  Silverscript later emits its own portable artifact, Argent should be able to
  wrap or reference that inner artifact instead of projecting `CompiledContract`
  itself.

### 6. Build Minimal Artifact-Only Transaction Harness

Create the first reusable builder surface that consumes only artifact JSON. It
should build P2SH signature scripts, covenant outputs, and populated test
transactions for one actor.

End-to-end test:

- Use `examples/tickets.ag`.
- Build a valid redeem transaction from artifact JSON only.
- Execute it in txscript.
- Mutate one sigscript arg or output state and assert txscript rejects.

Obstacle to handle:

- Tests may still generate fixture artifacts through the compiler. The builder
  module under test must not import compiler crates.

### 7. Represent Current `consumes` / `emits` / `become` Routes In Artifact

Promote the current route model into builder metadata. The artifact should know:

- leader input actor;
- consumed peer handles and expected actor templates;
- emitted output handles and order;
- which terminal `become` path maps to which output handles;
- hidden prefix/suffix/template witnesses required by each path.

End-to-end test:

- Use the Stones example.
- Build a valid multi-actor transition from artifact metadata.
- Reorder outputs and assert rejection.
- Substitute a wrong peer template and assert rejection.

Obstacle to handle:

- Route metadata must be emitted from the same validated model that emits
  Silverscript. Avoid a second ad hoc route parser in the builder.

### 8. Add Same-Template Output Shortcut

Generate the cheaper same-template validation path where the output is known to
preserve the active actor template. Keep the conservative
`validateOutputStateWithTemplate` path for foreign actors and peers.

End-to-end test:

- Add a self-transition fixture.
- Verify the generated Silverscript uses the same-template path.
- Verify the valid tx passes and a changed-template output fails.

Obstacle to handle:

- Same actor name is not always enough. For observed or generic lanes, preserve
  the concrete runtime template identity, not just the source-level interface.

### 9. Introduce Template Plan Receipts

Produce a machine-checkable receipt for the template plan used by the generated
contracts and artifact. The first version may be flat and unoptimized.

End-to-end test:

- Build Tickets or Stones.
- Verify the receipt recomputes all template hashes and route witness recipes.
- Assert artifact route metadata references receipt ids, not duplicated ad hoc
  values.

Obstacle to handle:

- Later Merkle cuts should replace flat template fields without changing the
  transaction builder's public shape. Design the receipt as a plan, not as a dump
  of current implementation details.

### 10. Implement Concrete `observes` Lanes

Implement the ICC sketch pattern from `examples/icc/minter_proxy_observer.ag`:

```text
observes asset by self.kcc20_covid {
    inputs { proxy: MinterProxy; }
    outputs { proxy: MinterProxy; recipient: KCC20; }
}
```

The compiler should lower this to covenant-id lane reads and output checks
without requiring the observing actor to own the foreign app.

End-to-end test:

- Compile the minter/proxy observer sketch.
- Build a mint transaction where `Minter` observes the asset lane.
- Valid tx passes.
- Wrong `kcc20_covid`, missing proxy input, or wrong recipient output fails.

Obstacle to handle:

- Observed lane output order must be deterministic and artifact-visible. Do not
  expose raw auth/cov indexes in user syntax unless diagnostics need them.

### 11. Hide Template Witnesses For Observed Lanes

Make the builder fill observed-lane prefix/suffix/template witnesses from the
artifact and live UTXOs. User code should provide semantic state transitions,
not template plumbing.

End-to-end test:

- The minter observer test should build from user args plus selected UTXOs.
- The caller should not pass template prefix/suffix args manually.
- Corrupt a hidden witness in the builder test and assert rejection.

Obstacle to handle:

- Input reads need prefix and suffix lengths plus hash. Output validation needs
  actual prefix and suffix bytes. The artifact must say which witness shape each
  generated call expects.

### 12. Implement Open Actor Interface Syntax

Add source syntax for preserving an unknown concrete actor template behind a
known state header:

```text
observes agent_lane by self.occupant_agent_covid {
    inputs {
        agent: actor<AgentCapsule> as T;
    }

    outputs {
        agent: T;
    }
}
```

`T` is scoped to the containing `observes` clause. It binds the input's concrete
runtime template and makes that exact template available to corresponding output
checks.

End-to-end test:

- Create two concrete agents with the same `AgentCapsule` header and different
  templates.
- A cell action can read either agent through `actor<AgentCapsule> as T`.
- The output must preserve the same concrete `T`.
- Swapping the output to the other concrete agent template fails.

Obstacle to handle:

- The cell can verify header physics and template preservation. It cannot prove
  arbitrary foreign strategy determinism. Keep this distinction visible in docs
  and diagnostics.

### 13. Implement Generic `T(next_state)` Become

Lower:

```text
require agent_lane.outputs become {
    agent <- T(next_agent);
};
```

This means "serialize `next_agent` into the preserved runtime template captured
as `T`", not "construct a known actor named T".

End-to-end test:

- The open-agent cell test should pass with a valid preserved-template output.
- It should fail if the output state is valid but the template is not the input's
  captured template.

Obstacle to handle:

- `T` needs a hidden witness bundle: prefix, suffix, template hash, and state
  layout information. The builder must bind this bundle to the observed input,
  not to a user-provided arbitrary template.

### 14. Implement Fixed Capability Header Preservation

Add a reusable way for observed/open actors to declare which header fields are
immutable under a transition and which fields the observing physics may mutate.

For the Open Lattice fixture, the cell wants to preserve fields such as:

- `world_id`;
- `agent_id`;
- capability digest;
- species/generation policy fields, unless a specific evolution entry allows
  changing them.

It may mutate fields such as:

- position;
- energy;
- `custom_data_digest`.

End-to-end test:

- A cell move preserves immutable header fields.
- A tx that changes capabilities through `move` fails.
- A separate explicit upgrade/evolution entry may update the cell lock and
  capability digest if declared.

Obstacle to handle:

- If an agent changes its template or capabilities outside the game lane, the
  cell lock should remain unchanged and the agent should become unable to act in
  that cell until a game-approved resync path updates the lock.

### 15. Implement `state extends` For Header Views

Allow concrete agent states to extend a shared header state:

```text
state ForagerState extends AgentCapsule {
    ...
}
```

The generated concrete actor owns the full concrete state. Interface reads
through `actor<AgentCapsule>` expose only the header view.

End-to-end test:

- A `Forager` actor with `ForagerState extends AgentCapsule` compiles.
- A `Cell` observes it as `actor<AgentCapsule>`.
- Header fields decode correctly from the concrete state.

Obstacle to handle:

- Header offsets must be stable and artifact-visible. Do not rely on source
  field names alone; record byte/push positions and type descriptors.

### 16. Implement `expand <digest_field> as <State>`

Support fixed digest-backed substate:

```text
state ForagerState extends AgentCapsule {
    expand custom_data_digest as ForagerMemory;
}
```

The stored covenant state still contains only `custom_data_digest`. The builder
supplies a hidden preimage for `ForagerMemory`; the compiler verifies the hash
and exposes memory fields as a flattened source-level view.

End-to-end test:

- Valid memory preimage opens and can be read by contract code.
- Bad preimage fails.
- Mutating a memory field reserializes memory and updates
  `custom_data_digest`.
- The entrypoint ABI does not expose the memory preimage as a user arg.

Obstacle to handle:

- The digest preimage serialization must use the same artifact codec as state
  encoding. Otherwise expanded memory and stored state will drift.

### 17. Make `closed_strategy.ag` A Fully Compiling Cell-Led Fixture

Keep a closed-world fixture that does not require open actor generics. It should
exercise the cell-led action pattern with concrete `Cell` and `Agent` actors.

End-to-end test:

- Compile `examples/open_lattice/closed_strategy.ag`.
- Build a valid move.
- Verify source cell, target cell, and agent outputs.
- Fail on occupied target, wrong source occupant, or invalid agent authorization.

Obstacle to handle:

- Current closed sketch uses placeholders where real covenant id/template data
  should be. Replace placeholders only when the artifact/builder can support the
  actual lane identity cleanly.

### 18. Make `binding_sketch.ag` A Compiling Open-Agent Fixture

After observed lanes, generic actors, header views, and digest expansion exist,
turn the sketch into a real compiler fixture.

End-to-end test:

- Compile a cell plus at least one concrete `Forager` agent.
- Move the agent through the cell as `actor<AgentCapsule> as T`.
- Preserve `T`, mutate allowed header fields, and update digest-backed memory.
- Fail on swapped template, bad capability digest, bad memory preimage, and
  illegal physics.

Obstacle to handle:

- This fixture combines most hard features. Do not start here. It should be the
  integration proof that the smaller features were designed correctly.

### 19. Add Chunk Or Cell-Birth Board Authority

Once the open-agent hot path is stable, add the scalable board creation model.
Prefer either:

- chunk UTXOs that own rectangular patches; or
- cell UTXOs born through a chunk-birth authority.

End-to-end test:

- Birth an empty neighboring cell once.
- Reject duplicate birth of the same coordinate.
- Move into a born empty cell.

Obstacle to handle:

- Absence is not locally provable. Expansion needs a positive object that
  records which coordinates have been born.

### 20. Add Optional Intent UTXO Layer

Add a strategy-intent layer only after direct cell-led actions work.

The intent pattern is:

```text
plan:
  spend Agent(state_n)
  create Agent(state_n_plus_1)
  create Intent(action, neighborhood_hash, expiry)

execute:
  spend Intent
  spend Agent + Cells
  create updated Agent + Cells
```

End-to-end test:

- Agent can publish one intent from one state.
- Anyone can execute it if the local neighborhood still matches.
- A stale neighborhood or expired intent fails.

Obstacle to handle:

- Intent binding commits to one chosen action. It still does not prove the
  strategy contract could not have chosen another legal action.

## Suggested Implementation Boundaries

The first practical code split should be:

```text
src/artifact.rs
  portable schema and serde

src/artifact_emit.rs
  projection from Argent compiler model and CompiledContract

src/codec.rs
  compiler-free runtime value encoding and decoding

src/builder.rs
  artifact-only transaction construction helpers
```

These can remain modules while unstable. Once the API is useful, split the
runtime pieces into a small crate whose dependency tree is easy to port:

```text
argent-artifact
  serde-only schema and codec

argent-builder
  artifact + tx construction helpers

argentc
  parser, compiler model, Silverscript generation, artifact emission
```

The dependency rule should be enforced by code review and tests:

```text
argentc -> silverscript-lang: allowed
argent-artifact -> silverscript-lang: forbidden
argent-builder -> silverscript-lang: forbidden
```

## Near-Term Cut

The first valuable milestone is tasks 1 through 6. That gives Argent a real
artifact boundary and proves that a transaction can be built without compiler
runtime types.

The second milestone is tasks 7 through 11. That turns existing Argent routing
and the minter observer sketch into artifact-driven ICC transactions.

The third milestone is tasks 12 through 18. That unlocks the Open Lattice open-agent
game pattern.
