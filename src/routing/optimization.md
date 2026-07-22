# Routing Optimization

This is a non-normative backlog of concrete cases where the routing model is
correct but plausibly over-constrained or unnecessarily expensive. Each entry
records the example and the invariant an optimization must preserve. Cases
about graph classification include ASCII drawings of both the route graph and
the undesirable selection.

## Avoid a cohort for a one-way same-state pair

Example: `tests/fixtures/emit/capsule_route_context/app.ag`.
`ReserveAsset` can emit `WalletAsset`, while `WalletAsset` only continues as
itself. Because both actors own `ReserveAssetState`, the weak component
heuristic currently makes them a cohort. Their equal cut therefore contains
both actor templates, so generated `WalletAsset.sil` carries the unused
`ReserveAsset` template.

The non-self emit graph is one-way:

```text
+--------------+       emit       +-------------+
| ReserveAsset | ---------------->| WalletAsset |
+--------------+                  +-------------+
```

Weak connectivity erases that direction and over-selects the whole component
as one cohort:

```text
+---------------- current cohort ----------------+
| +--------------+             +-------------+   |
| | ReserveAsset | ----------- | WalletAsset |   |
| +--------------+             +-------------+   |
+------------------------------------------------+

current cuts:  ReserveAsset = { ReserveAsset, WalletAsset }
               WalletAsset  = { ReserveAsset, WalletAsset }

useful cuts:   ReserveAsset = { WalletAsset }
               WalletAsset  = { }
```

A sharper cohort heuristic could keep distinct cuts for this one-way case.
`ReserveAsset` would retain the `WalletAsset` template needed by `withdraw`,
while `WalletAsset` would carry neither peer template. Any such rule must still
give selector variants and actors sharing an open family table identical cuts.

## Contract cohort dependencies

Commitment planning currently adds a complete directed clique to each cohort
in a cloned dependency graph. This is simple and gives the right propagation:
an emitter entering any cohort member inherits every member and every member's
outgoing dependencies. It materializes quadratic synthetic edges, however.

Replace the clique with cohort contraction or a dedicated dependency graph if
the extra structure becomes worthwhile. The optimized form must preserve the
same needs for cohort members and every upstream emitter.
