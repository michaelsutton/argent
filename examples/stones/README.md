# Stones

Stones is the first full Argent app prototype.

This example is intentionally small. Its job is to exercise the multi-actor
compiler path without burying the reader in game logic.

Rules: two players share a pile of stones. On each turn, the current player
takes `1..max_take` stones. The player who takes the last stone wins.

Actors:

- `League` registers player accounts.
- `Player` accounts start games and later delegate settlement.
- `StonesGame` owns the live game state.
- `StonesSettle` turns a terminal game ticket into player-account updates.

Transaction graph:

```text
League
  register_player
    -> League + Player

Player + Player
  start_game / accept_start
    -> Player + Player + StonesGame

StonesGame
  take
    -> StonesGame
    -> StonesSettle

StonesSettle + Player + Player
  settle / settle / settle
    -> Player + Player
```

Build:

```sh
cargo run -- build examples/stones/app.ag --out examples/build/stones
```

Generated artifacts:

```text
examples/build/stones/artifact.json
examples/build/stones/manifest.json
examples/build/stones/sil/League.sil
examples/build/stones/sil/Player.sil
examples/build/stones/sil/StonesGame.sil
examples/build/stones/sil/StonesSettle.sil
```

Compiler features exercised today:

- multi-file imports
- shared state layouts
- named actor templates
- leader and delegate entries
- `consumes` peer actor inputs
- named `emits` output handles
- owner and side-to-move signature checks
- typed covenant peer reads through `readInputStateWithTemplate`
- single-output `become`
- multi-output atomic `become`
- read-only output handles such as `next.value`
- ordinary `require(...)` checks for output value policy
- generated hidden template fields
- generated successor validation through `validateOutputStateWithTemplate`

Still intentionally missing:

- generated transaction builder
- launch proof artifact
- route commitment tree
- same-template `validateOutputState` shortcut
- stable ABI
- mature diagnostics
