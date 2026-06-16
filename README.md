# Argent

Argent is an experimental actor-style frontend for Silverscript covenant
contracts.

The current goal is to explore a small source language where multi-contract
apps are written as persistent actors. A compiler can later lower those actors
to plain Silverscript contracts by generating template commitments, route
tables, output validation, and foreign-state reads.

The first tiny sketch lives in [examples/counter.ag](examples/counter.ag). A
larger multi-input, multi-output sketch lives in
[examples/settle.ag](examples/settle.ag). These are not meant to compile yet;
they are concrete playgrounds for the syntax and lowering model.

The first full multi-file app sketch is [examples/stones](examples/stones), a
small two-player game with `League`, `Player`, `StonesGame`, and `StonesSettle`
actors.

Core ideas to test:

- `state` declarations define reusable covenant state layouts.
- `actor` declarations define contract templates that own one state layout.
- `entry` declarations define callable covenant entrypoints.
- `become` is a tail-dispatch primitive that emits the next actor state.
- `emits` declares the allowed output shape for an entrypoint.
