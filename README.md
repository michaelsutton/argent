# Argent

Argent is an experimental actor-style frontend for Silverscript covenant
contracts.

This repository is a very early research prototype. It is not production-ready,
not audited, and the language syntax, generated ABI, and compiler internals are
unstable, with no guarantee that development will continue or that this becomes
more than an experiment.

The goal is to make it easier to build multi-contract covenant systems as
closed, well-formed state machines. Argent source describes the application
actors, state, transition shape, and tail-dispatch intent, while the compiler
generates plain Silverscript for route plumbing, template propagation, typed
foreign-state reads, and successor-state validation.

For a tiny screenshot-friendly example, see [examples/tickets.ag](examples/tickets.ag),
a single-file app with `Issuer` and `Ticket` actors. The larger current app is
[examples/stones](examples/stones), a small two-player game with `League`,
`Player`, `StonesGame`, and `StonesSettle` actors.

Design notes and open questions live in
[docs/argent-design.md](docs/argent-design.md).

## Status

What works today:

- multi-file `.ag` parsing
- shared `state`, `const`, and helper `fn` declarations
- `actor` declarations that own one state layout
- `entry` and `delegate` declarations
- `consumes` covenant-peer declarations
- named `emits` output handles
- terminal `become` routes
- generated plain Silverscript for the Stones app
- generated hidden template fields in state objects
- generated `readInputStateWithTemplate` calls for consumed actors
- generated `validateOutputStateWithTemplate` calls for successor actors
- same-template `validateOutputState` shortcuts for exact continuations
- portable artifact JSON with an inner Sil ABI artifact
- artifact-driven transaction-building helpers for tests and prototypes
- template table/proof receipts and one-level route-family commitments

What is still early or missing:

- no launch proof tooling yet
- no generated app-specific transaction builder API yet
- no optimized template tree-cut algorithms yet
- no stable ABI
- no full Argent typechecker
- minimal diagnostics
- no security claims

## Prototype compiler

Build the Stones example:

```sh
cargo run -- build examples/stones/app.ag --out build/stones
```

Build the tiny Tickets example:

```sh
cargo run -- build examples/tickets.ag --out build/tickets
```

The generated artifacts are written under `build/stones`:

- `build/stones/artifact.json`
- `build/stones/manifest.json`
- `build/stones/sil/League.sil`
- `build/stones/sil/Player.sil`
- `build/stones/sil/StonesGame.sil`
- `build/stones/sil/StonesSettle.sil`

The generated Silverscript is intended to compile as ordinary Silverscript. No
Silverscript covenant macros are used.

## Core Ideas

- `state` defines reusable covenant state layouts.
- `actor` defines a contract template that owns one state layout.
- `entry` defines a leader transition path.
- `delegate` defines a non-leader check in a coordinated transition.
- `consumes` names other covenant actor inputs in the same transaction group.
- `emits` declares the authorized output shape for an entrypoint.
- `become` is a terminal tail-dispatch primitive into successor actor state.

Argent is trying to hide the route logic and mechanical safety checks that make
multi-contract Silverscript flows hard to write by hand, while still emitting
inspectable, plain Silverscript.
