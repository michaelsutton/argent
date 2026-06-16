# Argent

Argent is an experimental actor-style frontend for Silverscript covenant
contracts.

The current goal is to explore a small source language where multi-contract
apps are written as persistent actors. A compiler can later lower those actors
to plain Silverscript contracts by generating template commitments, route
tables, output validation, and foreign-state reads.

The current app sketch is [examples/stones](examples/stones), a small two-player
game with `League`, `Player`, `StonesGame`, and `StonesSettle` actors.

Design notes and open questions live in
[docs/argent-design.md](docs/argent-design.md).

## Prototype compiler

`argentc` currently parses the multi-file app graph, builds an actor/state AST,
extracts `become` routes, and emits plain Silverscript skeletons plus a manifest.

```sh
cargo run -- build examples/stones/app.ag --out build/stones
```

The generated Silverscript includes:

- hidden template-table constructor fields for every actor in the app
- full hidden-plus-user state structs for cross-template reads and writes
- typed foreign input reads via `readInputStateWithTemplate`
- auth output shape checks
- extracted `become` route notes showing the future `validateOutputStateWithTemplate`
  calls

The next compiler pass is body lowering: turning Argent expressions and state
constructors into concrete Silverscript state objects and route validations.

Core ideas to test:

- `state` declarations define reusable covenant state layouts.
- `actor` declarations define contract templates that own one state layout.
- `entry` declarations define callable covenant entrypoints.
- `become` is a tail-dispatch primitive that emits the next actor state.
- `emits` declares the allowed output shape for an entrypoint.
