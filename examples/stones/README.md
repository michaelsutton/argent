# Stones

Stones is the first full Argent app sketch.

Rules: two players share a pile of stones. On each turn, the current player
takes `1..max_take` stones. The player who takes the last stone wins.

The app exists to keep game logic small while exercising a real multi-actor
covenant system:

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
  settle / delegate_settle / delegate_settle
    -> Player + Player
```

Compiler features this example should eventually exercise:

- multi-file imports
- shared state layouts
- named actor templates
- owner and side-to-move signature checks
- typed foreign covenant inputs
- single-output `become`
- multi-output atomic `become`
- read-only output handles such as `next.value`
- ordinary `require(...)` checks for output value policy
