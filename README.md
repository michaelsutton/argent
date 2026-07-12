# Argent

Argent is an actor-style language for writing Kaspa covenant applications that
compile to plain Silverscript.

Argent source describes the application state, actors, entrypoints, coordinated
inputs and outputs, observed covenants, and successor actors. The compiler emits
auditable `.sil` files plus a portable artifact consumed by `argent-runtime`.

Argent is still evolving, but the main pieces are present: compiler, generated
Silverscript, portable artifacts, runtime transaction building, route families,
actor enums, ICC, open observed actors, and virtual-slot state expansion.

## Quick start

Run the standard local check loop:

```sh
./check.sh
```

Regenerate tracked example outputs and run the full check loop:

```sh
./check.sh --full
```

Build one app manually:

```sh
cargo run -- build examples/tickets.ag --out examples/build/tickets
cargo run -- build examples/stones/app.ag --out examples/build/stones
cargo run -- build examples/icc/kcc20_asset.ag --out examples/build/icc_kcc20_asset
cargo run -- build examples/icc/minter.ag --out examples/build/icc_minter
cargo run -- build examples/open_icc/agent.ag --out examples/build/open_icc_agent
cargo run -- build examples/open_icc/core.ag --out examples/build/open_icc_core
```

Generated outputs include:

- `artifact.json`: the portable Argent artifact
- `manifest.json`: build metadata
- `sil/*.sil`: generated Silverscript contracts

Generated `.sil` files compile as ordinary Silverscript. Argent does not use
Silverscript covenant macros.

## Language at a glance

```rust
state TicketState {
    byte[32] owner;
    int value;
}

actor Ticket owns TicketState {
    entry transfer(next_owner: byte[32]) emits one Ticket {
        TicketState next = {
            owner: next_owner,
            value: value,
        };

        become Ticket(next);
    }
}

app Tickets {
    actor Ticket;
}
```

Argent actors are not async actors with mailboxes or message queues. They are
covenant objects that get consumed and recreated by transactions. The shared
idea with actor models is state ownership: an actor's code is the only
authority that can consume and mutate that actor's state.

Core terms:

- `state` defines a persistent covenant state layout.
- `actor` defines one contract template that owns a state layout.
- `entry` defines a callable transition path.
- `delegate` defines a non-leading check in a coordinated transition.
- `consumes` names peer covenant inputs in the same transaction.
- `emits` declares the authorized output handles for an entrypoint.
- `become` is the terminal transition into successor actor state.
- `observes` declares a foreign covenant view for ICC.
- `actor_type<State>` identifies a runtime-selected actor implementation
  compatible with `State`.
- `actor enum` defines a closed set of runtime-selected actor targets.
- `virtual` slots and `state X expands Base` let concrete actors bind private
  digest-backed memory while preserving a shared base state layout.

## Examples

- [examples/tickets.ag](examples/tickets.ag): tiny single-file issuer/ticket app
- [examples/stones](examples/stones): small coordinated game with league,
  player, game, and settle actors
- [examples/toy_chess](examples/toy_chess/app.ag): actor enums and
  route-family selector lowering
- [examples/icc](examples/icc): closed ICC between a minter and asset app
- [examples/open_icc](examples/open_icc): open observed actors and virtual-slot
  agent state

## Runtime

`argent-runtime` is the artifact-only consumer surface. It has no compiler
dependency. It loads compiled artifacts, fills hidden witness material, builds
covenant UTXOs and outputs, composes artifact bundles, and constructs P2SH
signature scripts for tests and client tooling.

Classic single-app flow:

```rust
let builder = TxBuilder::new(&artifact)?;

let input_state = ticket_state(owner, value);
let output_state = ticket_state(next_owner, value);

// The covenant UTXO being spent.
let input_utxo = builder.covenant_utxo("Ticket", input_state.clone(), value, 0, false, Some(covenant_id))?;

// The successor covenant output this entry authorizes.
let output = builder.covenant_output("Ticket", output_state, value, 0, covenant_id)?;

let sigscript = builder.p2sh_signature_script(
    "Ticket",
    "transfer",
    input_state,
    args![next_owner],
)?;

// ... compose tx
```

The runtime API is Argent-specific while the language settles. The lower-level
Silverscript ABI and artifact boundaries are split into small crates so they can
be kept portable. Multi-app ICC uses `ArtifactBundle`, while the basic path is
single-artifact `TxBuilder::new`.

## Why Argent

Kaspa covenants make it possible to build applications out of multiple
coordinated UTXOs, but hand-written covenant systems quickly accumulate
mechanical obligations: template hashes, state serialization, prefix/suffix
witnesses, output ordering, route commitments, observed covenant ids, and
cross-contract state reads.

Argent makes those relationships source-level. Actors own state. Entries name
the peer inputs they consume, the outputs they emit, the foreign covenants they
observe, and the actors those outputs become. The compiler checks that the
declared state-machine edges are well formed, then emits the Silverscript that
performs the low-level validation.

Generated contracts stay as plain `.sil` files, and the artifact records the
runtime recipe needed to build transactions against them.

## How it works

The compiler parses `.ag` source into an actor/state model and lowers each actor
to one Silverscript contract. Source state fields become the contract state
layout. Compiler-generated fields and hidden entry arguments carry template
receipts, route-family tables, observed-covenant witnesses, and expanded-state
preimages.

`become` routes lower to output validation. Exact continuations can use cheaper
script-public-key checks. Foreign or runtime-selected actors use template
prefix/suffix witnesses or route-family tables. `observes` lowers to covenant
input/output checks against another app. `virtual` slots lower to fixed digest
fields, with concrete actors providing hidden preimages when they expand those
slots into structured memory.

The portable artifact records the runtime recipe for all of this: script bytes,
state layouts, type descriptors, route receipts, observed covenant metadata,
hidden witness recipes, artifact ids, and interface fingerprints.
`argent-runtime` consumes that artifact directly; it does not depend on compiler
AST types.

## Current maturity

Argent is an active language and compiler project. Syntax and JSON schema
changes are still expected while the system settles. It has not been audited.

What is useful today:

- compiling `.ag` apps to auditable `.sil`
- building tracked example transactions through `argent-runtime`
- closed and open ICC examples
- route-family and actor-enum examples
- virtual-slot expanded state for open-agent style apps

What is still being built:

- launch and bootstrap tooling
- app-level dependency syntax and qualified source references
- stronger diagnostics and typechecking
- generated app-specific builder APIs
- broader hardening and negative-test coverage

Design notes can be found in [docs/argent-design.md](docs/argent-design.md).
ICC semantics can be found in [docs/icc-semantics.md](docs/icc-semantics.md).
