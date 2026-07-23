# Argent

Argent is an actor-based, multi-contract and multi-app language and compiler for
building Kaspa covenant applications. It compiles `.ag` source to plain,
auditable Silverscript contracts plus portable artifacts consumed by
`argent-runtime`.

An Argent app describes transaction-wide state transitions over covenant UTXOs.
Actors own typed state, entries consume and emit one or more actors, and
`become` defines the successor actors created by the transaction.
Inter-Covenant Communication (ICC) extends the same model across independently
compiled apps, allowing several covenant actors to inspect and constrain one
atomic transition.

The compiler and runtime handle the underlying covenant plumbing: state
layouts, template commitments, route families, output validation, observed
covenants, virtual state expansion, and hidden witness material. Application
code stays at the level of actors, state, and transitions.

Argent is still evolving, but the main pieces are present: compiler, generated
Silverscript, portable artifacts, runtime transaction building, multi-actor
routes, actor enums, closed and open ICC, and virtual-slot state expansion.

```text
.ag source
    |
    v
Argent compiler
    |
    +-- plain .sil contracts
    |
    +-- portable artifact
              |
              v
       argent-runtime
              |
              v
   atomic multi-actor Kaspa tx
```

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

When one source file declares multiple apps, select the app to build by name:

```sh
cargo run -- build contracts.ag --app DexCore --out build/dex-core
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
    entry transfer(byte[32] next_owner, sig owner_sig, pubkey owner_pk) emits one Ticket {
        require(blake2b(owner_pk) == owner);
        require(checkSig(owner_sig, owner_pk));

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

Argent uses type-first syntax for declarations and callable parameters.
Bindings put the local name on the left. See
[Surface syntax conventions](docs/argent-design.md#surface-syntax-conventions)
for the rules and examples.

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
- `spawns` declares a genesis covenant output group and binds its generated
  covenant id. A spawn target can be an actor in the selected app or an
  `actor_type<State>` value.
- `actor_type<State>` identifies a runtime-selected actor implementation
  compatible with `State`.
- `actor enum` defines a closed set of runtime-selected actor targets.
- `virtual` slots and `state X expands Base` let concrete actors bind private
  digest-backed memory while preserving a shared base state layout.

## Examples

- [examples/tickets.ag](examples/tickets.ag): tiny single-file issuer/ticket app
- [examples/spawns.ag](examples/spawns.ag): constrained genesis covenant launch
  with a complete two-output group
- [examples/stones](examples/stones): small coordinated game with league,
  player, game, and settle actors
- [examples/toy_chess](examples/toy_chess/app.ag): actor enums and
  route-family selector lowering
- [examples/icc](examples/icc): closed ICC between a minter and asset app
- [examples/open_icc](examples/open_icc): open observed actors and virtual-slot
  agent state

For client-side examples, see
[argent-playground](https://github.com/michaelsutton/argent-playground). It is a
separate Rust project that depends on a neighboring Argent checkout and shows
complete app compilation and transaction-building flows through
`argent-runtime`.

## Runtime

`argent-runtime` is the artifact-only consumer surface. It has no compiler
dependency. It loads compiled artifacts, fills hidden witness material, builds
covenant UTXOs, composes artifact bundles, and builds complete transactions
from concrete actor inputs and outputs.

Classic single-app flow:

```rust
let builder = TxBuilder::new(&artifact)?;

let input_state = state! { count: 2 };
let output_state = state! { count: 5 };

// The covenant UTXO being spent.
let input_utxo = builder.covenant_utxo(
    "Counter",
    input_state.clone(),
    value,
    0,
    false,
    Some(covenant_id),
)?;

let context = TxContext::new()
    .actor_input(
        "Counter",
        input_state,
        EntryCall::new("bump").args(args![3]),
        outpoint,
        input_utxo,
        0, // sequence
    )
    .actor_output(
        "Counter",
        output_state,
        CovenantBinding::new(0, covenant_id),
        value,
    );

let tx = builder.build(&context)?;
```

Each input declares its sequence. Lock time, lane and gas, and payload can be
set fluently on `TxContext`; their defaults produce a native transaction.

The runtime API is Argent-specific while the language settles. The lower-level
Silverscript ABI and artifact boundaries are split into small crates so they can
be kept portable. Multi-app ICC uses `ArtifactBundle`; the transaction context
is otherwise the same for single- and multi-app transactions.

## Why Argent

Kaspa covenants make it possible to build applications from several stateful
UTXOs whose transitions compose atomically in one transaction. But hand-written
multi-contract systems quickly accumulate mechanical obligations: state
serialization, template hashes, route commitments, prefix/suffix witnesses,
output ordering, observed covenant ids, and cross-contract state reads.

Argent makes the application graph source-level. Actors own state. Entries
declare the peer actors they consume, the outputs they emit, the foreign
covenants they observe, and the successor actors those outputs become. The
compiler checks the declared state-machine edges and emits the Silverscript that
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
Subtle generated-code security arguments are documented in [SECURITY.md](SECURITY.md).

## Contributing

Run `./check.sh --full` before submitting changes. Open design questions and
implementation sketches are collected in [docs/followups.md](docs/followups.md);
they are useful starting points for discussion and contributions.
