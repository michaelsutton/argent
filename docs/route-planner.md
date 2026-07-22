# Route Planning

Argent actors may own the same source-level state while needing different
runtime route commitments. An actor should carry enough information to
authenticate every actor it may emit, but storing every reachable template
individually would make state large and couple compiler emission to one fixed
grouping strategy.

The route planner represents those commitments as a forest. Related templates
can be grouped under an ordered, hash-committed table, and each actor receives
a cut through that forest: a compact mix of concrete templates and packed
table commitments. Moving from one actor to another becomes a structural cut
transition—retain common nodes, open packed families, and pack families that
the target no longer needs open.

The design separates three concerns:

1. Graph classification proposes families and actors that should share a cut.
2. Commitment planning constructs the forest, computes actor cuts, and derives
   transitions without knowing about Argent syntax or SIL.
3. Compiler lowering turns those cuts and transitions into state fields,
   witnesses, hashes, and output validation.

The family and cohort rules below are an initial grouping policy. They can be
replaced or optimized without changing the commitment or compiler boundary,
provided the stated invariants continue to hold.

## Terms

- An **actor** is one route-template leaf.
- A **domain** is the compiler-ordered set of actors that own one declared
  Argent state.
- An **emit edge** `A -> B` means an entry of `A` may create `B`. Emit needs
  propagate transitively.
- A **consume edge** `A -> B` means an entry of `A` reads `B`. The `B` template
  is a direct need of `A`; `B`'s outgoing needs do not propagate through this
  edge.
- A **component** is a weakly connected component of the emit graph restricted
  to one domain. Emit direction is ignored only for this classification.
- A **gate** is a component member with an incoming emit edge from outside the
  component. The source may be in another domain.
- A **cohort** is a set of actors constrained to carry one identical
  commitment cut and therefore one identical generated SIL state layout.
- A **family** is one branch in the commitment forest. Its children are the
  actors stored in one ordered route table. The component may also contain
  direct actors stored outside that table.
- A **cut** is a partial selection of forest nodes with no selected node above
  or below another selected node. Unneeded forest roots may be absent.
- A **cut transition** says which selected nodes are retained and which family
  branches must be opened or packed when routing from one actor to another.
- A **state body** is a generated, user-fields-only SIL struct used while adding
  the route fields for one concrete target actor. It is a compiler transport
  type, not a planner node or cut.

Some API names require a more precise interpretation:

- `RouteFamily.actors` is the complete component, while the commitment family
  is only `table_actors`.
- Artifact `entry_actors` are exactly the component actors stored directly,
  i.e. `actors - table_actors`. They normally coincide with graph gates, but a
  selector may place a gate in the table.
- `representative_actor` only gives a deterministic family identity. It does
  not have to be direct and has no special position in the commitment tree.
- A declared Argent state is not necessarily one runtime layout. Actors owning
  the same state can have different generated route fields.

## Planner inputs and classification policy

The compiler builds a `RouteGraph` for the selected app, one state domain per
declared actor state, and selector requirements for actor-enum values used as
route selectors. Dynamic and fixed enum routes are expanded to their possible
concrete targets for dependency planning.

For each domain, `route_plan` finds weak emit components using only edges whose
two endpoints are in that domain. Gate detection consults the full graph so it
can see inbound edges from other domains.

The initial classification policy is deliberately simple:

1. Every component with at least two actors becomes a cohort.
2. A selector requirement always creates a family. Its enum order is the table
   prefix. Remaining non-gate, non-prefix actors follow in compiler order.
   Selected gates remain in the prefix.
3. Without a selector, a component is a family candidate only when it has at
   least three members and at least two non-gate table actors.
4. Direct family actors are computed as `component members - table actors`,
   not from gates alone.
5. The representative is the first gate in compiler order, or the first member
   for a gate-less component.

Selector requirements must name one known domain, use a source and variants in
one component, contain at least two distinct variants, and agree on one prefix
order when multiple selectors affect the same component.

An actor-enum declaration itself is validated to contain actors that own the
same state. Only an enum used as a selector becomes a planner requirement; an
otherwise-unused enum does not independently merge cohorts. Making every enum
declaration impose cohort equality is a separate policy choice.

## Commitment planning

The commitment planner has no Argent AST or SIL knowledge. It receives the
route graph plus ordered families and cohorts.

Forest construction is deterministic. Each table is one branch whose children
follow table order. Actors outside tables are root leaves. A branch occupies
the root position of its lexically earliest child, independently of the order
in which family constraints were supplied. Compiler lowering supports
one-level family branches; the forest and transition structures can represent
nesting.

Dependency planning happens on a clone of the route graph. Every cohort is
made into a synthetic directed clique on that clone, then ordinary needs are
computed: emit targets contribute themselves and their transitive needs, while
consume targets contribute only themselves. The clique is essential to
propagation. If `A -> B`, `B` shares a cohort with `C`, and `C -> D`, then `A`
must inherit `D` as well. These synthetic edges are not source routes and do
not create compiler route transitions.

Needs are translated into cuts as follows:

- A needed standalone actor selects its leaf.
- A needed family actor normally selects the packed family branch.
- An actor's directly consumed family members are exposed. Opening one member
  exposes the complete table because a valid cut cannot select a branch and
  one of its descendants together.
- A cohort receives one shared cut from its equalized needs. The complete
  cohort and the union of its direct consumes are exposed in that cut.
- Directness does not propagate upstream: an emitter may carry a packed branch
  and open it when entering a consumer whose cut contains concrete templates.

Every planned actor gets one valid partial cut. `cut_transition(source,
target)` derives the target from the source using retained nodes, parent-first
opens, and child-first packs. Missing coverage is rejected.

## Compiler lowering

The compiler translates selected cut nodes into two leaf forms:

- `Actor(A)` becomes a concrete template field.
- `Family(F)` becomes the digest of an ordered family table.

Actors in a route-family component use the open local representation: their
direct component actors remain individual fields and their table actors are
stored in the table. Other family needs remain packed digests. Actors outside
a component can also hold an opened foreign family as individual templates;
this occurs for direct consumes.

Only real non-self emit pairs receive compiler transitions:

- Opening adds the family-table preimage as an entry witness and verifies it
  against the source digest. If the route target is in the table, its concrete
  template is sliced from that witness for `validateOutputStateWithTemplate`.
- Packing hashes the local table when the source owns it. If the source holds
  an opened foreign family as individual templates, emission concatenates
  those templates in canonical table order and hashes that preimage.
- Retained fields are copied without re-materializing commitments.

Route fields are actor-local. If all selected actors owning a declared state
have the same fields, the ordinary named SIL state struct is their common
layout. If their cuts differ, Argent can emit actor-qualified layouts and a
user-fields-only state body. The state body is retained when a source value must
remain neutral between multiple target layouts. A local used only by exactly
one concrete route is materialized directly in that target's layout at its
original declaration point. Packing is edge-specific; in this straight-line
case the compiler can compute the digest there without an intermediate state
body.

The compiler also retains a conservative state dependency calculation for
unqualified and dynamic state values. It aggregates template needs by declared
state and propagates them over state-to-state routes. Actor-qualified routes use
the commitment planner; the state-wide result is a fallback layout, not an
alternative commitment plan.

## Invariants at the boundary

- Route-plan actors exactly cover the selected app.
- Every domain actor belongs to the graph, and components partition a domain.
- Families and cohorts are individually disjoint.
- Family tables contain at least two distinct actors and preserve their
  canonical order; direct actors are the exact component complement.
- Cohort members have equal dependency needs, one equal valid cut, and direct
  access to every cohort member and direct consume target.
- Cohort-introduced needs propagate to every upstream emitter.
- Every real route transition is derivable from its source cut.
- Compiler family witnesses and hashes are driven by cut transitions, not by
  state membership or a one-time union heuristic.
- Generated constructor fields, runtime-state roles, SIL state fields, and
  artifact route receipts all describe the same actor cut.
- Selector variants use one table order and one cut transition.

## Limits and reference cases

The heuristic is one-level and intentionally coarse. In particular, every
nontrivial weak component becomes a cohort, and cohort propagation uses a
quadratic synthetic clique. Concrete optimization cases and the
invariants they must preserve live in
[`src/routing/optimization.md`](../src/routing/optimization.md).

Pinned generated examples provide compiler traces:

- `examples/build/toy_chess` shows the common-layout case: `Player` opens the
  Board family directly without a state body.
- `examples/build/route_state_bodies/sil/Lobby.sil` and `Mux.sil` show straight-line
  opening and packing materialized directly, without redundant state bodies.
- `examples/build/route_state_body_choice/sil/Lobby.sil` shows the necessary
  neutral state body case: one `BoardState` local routes either to an open Mux
  layout or directly to Spectator's empty cut.
- `examples/build/route_state_bodies/sil/Archive.sil` shows a selected gate template
  being sliced from an opened foreign table.

`./check.sh --full` regenerates these outputs and compiles every generated SIL
contract before running the workspace tests and lints.
