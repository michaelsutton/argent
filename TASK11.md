# Task 11 Hardening

Temporary checklist for finishing basic template merklization before the PR.

## Route Families

- Support multiple direct route families over the same owned state.
- Keep family ids deterministic by the selected anchor actor.
- Preserve the one-level packing rule: upper states may hold family digests,
  while family states hold one expanded fixed route table.
- Add tests for disconnected same-state route clusters.

## Route Receipts

- Clean up legacy route-tree/opening terminology where it leaks into the
  current one-level route-family model.
- Keep proof/opening names only where the artifact is actually describing a
  receipt proof.
- Add a guard test for accidental nested route-family table leaves.

## Toy Chess E2E

- Assert the generated Sil shape directly:
  `League`/`Player` carry `Mux` plus `mux_routes_digest`; `Mux` carries the
  fixed worker table.
- Assert upper layers do not expose `Pawn` or `Knight` template leaves.
- Add builder-level positive coverage through the toy chess route pattern.
- Add negative coverage for wrong route-family table, wrong receipt proof, and
  wrong selected worker template.

## Branch Scope

- Finish Task 11 hardening in this branch.
- Do typed template handles next as Task 15 if it stays tightly connected to
  mux/family routing.
- Leave concrete `observes`, artifact bundles, and open actor syntax for the
  next branch.
