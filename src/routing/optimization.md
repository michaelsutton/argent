# Routing Optimization Opportunities

This file records cases where route planning is correct but inefficient. Each
entry states an opportunity and the behavior that an optimization must keep.

## Keep separate cuts for one-way dependencies

**Opportunity:** Keep separate cuts for actors that have asymmetric route
needs.

**Description:** Weak-component classification ignores emit direction. It can
put two same-state actors in one cohort when only the source actor needs the
target actor. The equal cohort cut then gives the target actor an unused source
template. A directional rule can keep separate cuts. It must still give equal
cuts to selector variants and to actors that share an open family table.

**Example:** In `tests/fixtures/emit/capsule_route_context/app.ag`,
`ReserveAsset` emits `WalletAsset`. `WalletAsset` does not emit `ReserveAsset`.
The current cohort makes `WalletAsset.sil` store an unused `ReserveAsset`
template.

```text
route:             ReserveAsset -> WalletAsset
current cohort:   {ReserveAsset,   WalletAsset}

current cuts:      ReserveAsset = {ReserveAsset, WalletAsset}
                   WalletAsset  = {ReserveAsset, WalletAsset}

target cuts:       ReserveAsset = {WalletAsset}
                   WalletAsset  = {}
```

## Pack common external dependencies

**Opportunity:** Replace concrete external templates that are common to a
family with one branch digest.

**Description:** A family can depend on the same external actors in every cut.
If it needs the concrete templates only when it leaves the family, a helper
branch can store one digest in the family cuts. An exit transition opens the
branch. A return transition packs it.

A user-provided forest hint can define the helper branch. The hint must group
only the commitment leaves. It must not make the external actors a cohort or
give them equal state layouts.

**Example:** In `argent-playground/chess`, each `GameState` actor in the
`ChessMux` family stores the `Player` and `ChessSettle` templates. Each template
is 32 bytes. The actors need the concrete templates only when they leave the
game family.

```text
Player -> ChessMux family <-> move actors
  ^              |
  |              v
  +--------- ChessSettle
```

```text
current root:  [Player] [ChessSettle] [ChessMux family]
game cut:      [Player] [ChessSettle] [open ChessMux family]

target root:   [Player+Settle branch] [ChessMux family]
game cut:      [Player+Settle digest] [open ChessMux family]

Player+Settle branch: [Player] [ChessSettle]
```

A settlement transition opens the helper branch. A transition back to the game
packs it.

## Contract cohort dependencies

**Opportunity:** Avoid the quadratic set of synthetic edges for a large
cohort.

**Description:** Commitment planning currently adds a complete directed clique
for each cohort in a cloned dependency graph. This gives the correct dependency
propagation, but a cohort of N actors adds N * (N - 1) edges.

The planner can instead contract each cohort or use a separate dependency
graph. The replacement must give the same needs to all cohort members and to
all upstream emitters.
