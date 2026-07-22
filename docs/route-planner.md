# Route Planning

An Argent actor must authenticate each actor that it can emit. The compiler
could store each reachable actor template. This would make state large and
would bind code generation to one grouping policy.

The route planner groups templates in a commitment forest. Each actor gets a
cut through this forest. A cut contains concrete templates and packed branch
digests. A route transition can keep, open, or pack these nodes.

The design has three parts:

1. Graph classification defines families and cohorts.
2. Commitment planning builds the forest, cuts, and transitions.
3. Compiler lowering generates SIL fields, witnesses, hashes, and checks.

The current family and cohort rules are an initial policy. A later policy can
replace them if it keeps the planner invariants.

## Terms

- An **actor** is one route-template leaf.
- A **domain** is the ordered set of actors that own one declared Argent state.
- An **emit edge** `A -> B` means that an entry in `A` can create `B`. Emit
  needs propagate through this edge.
- A **consume edge** `A -> B` means that an entry in `A` reads `B`. `A` needs
  the `B` template, but it does not inherit the outgoing needs of `B`.
- A **component** is a weakly connected part of the emit graph in one domain.
  Classification ignores edge direction.
- A **gate** is a component actor that has an incoming emit edge from outside
  the component.
- A **cohort** is a set of actors that have the same cut and the same generated
  SIL state layout.
- A **family** is one forest branch. Its children form one ordered route table.
  Some component actors can remain outside this table.
- A **cut** is a partial selection of forest nodes. It cannot select both an
  ancestor and its descendant. It can omit unused roots.
- A **cut transition** defines the nodes to keep, open, or pack for one route.
- A **state body** is a generated SIL struct that contains only user fields.
  The compiler uses it before it adds route fields for a target actor. It is
  not a planner node.

The following API names need more detail:

- `RouteFamily.actors` contains the complete component.
- `RouteFamily.table_actors` contains the actors in the family table.
- Artifact `entry_actors` contains `actors - table_actors`. These actors are
  usually gates. A selector can put a gate in the table.
- `representative_actor` gives the family a stable identity. It has no special
  position in the forest and does not have to be a direct actor.
- One declared Argent state can have more than one generated runtime layout.

## Inputs and graph classification

The compiler supplies three inputs:

- a `RouteGraph` for the selected app;
- one ordered domain for each declared actor state;
- selector requirements for actor-enum values used as route selectors.

The compiler expands fixed and dynamic enum routes to their concrete targets.
This gives the planner the complete dependency graph.

For each domain, `route_plan` finds weak emit components. It uses only edges
whose endpoints are in that domain. It uses the complete graph to find gates,
so an edge from another domain can define a gate.

The current policy is:

1. A component with at least two actors becomes a cohort.
2. A selector requirement always creates a family. The enum order is the
   table prefix. Other non-gate actors follow in compiler order. A selected
   gate stays in the prefix.
3. A component without a selector becomes a family only if it has at least
   three actors and at least two non-gate table actors.
4. Direct family actors are `component actors - table actors`.
5. The representative is the first gate in compiler order. A component with
   no gate uses its first actor.

A selector requirement must satisfy these rules:

- The source and all variants are in one known domain and one component.
- It has at least two distinct variants.
- All selectors for one component use the same prefix order.

All actors in an actor enum must own the same declared state. An enum creates a
planner requirement only when code uses it as a selector. An unused enum does
not create or merge cohorts. A policy can change this rule later.

## Commitment planning

The commitment planner has no Argent AST or SIL data. It receives the graph,
families, and cohorts.

### Forest construction

Forest construction is deterministic. Each family table becomes one branch.
The branch children follow the table order. An actor outside a table becomes a
root leaf. A branch takes the root position of its earliest child. The order of
the family constraints does not change this position.

The planner data model supports nested branches. Compiler lowering currently
supports only one-level family tables.

### Dependency propagation

The planner clones the route graph. It adds a complete directed clique for
each cohort to this clone. It then computes ordinary route needs:

- An emit target contributes itself and all its transitive needs.
- A consume target contributes only itself.

The cohort clique is part of dependency propagation. For example, assume
`A -> B`, `B` shares a cohort with `C`, and `C -> D`. The clique makes `B`
inherit the outgoing needs of `C`. Therefore, `A` also needs `D`.

The clique edges are synthetic. They do not define source routes or compiler
transitions.

### Cut construction

The planner converts needs to cuts:

- A needed actor outside a family selects its leaf.
- A needed family actor normally selects the packed family branch.
- A direct consume of a family actor opens the complete family table. A valid
  cut cannot contain both a branch and one of its children.
- All actors in a cohort get one cut from their combined needs.
- A cohort cut opens the complete cohort and all direct consume targets.

Direct access does not propagate upstream. An emitter can keep a packed branch
and open it when it enters an actor that needs concrete templates.

Each planned actor gets one valid partial cut. `cut_transition(source, target)`
derives the target cut from the source cut. It keeps common nodes, opens
parents before children, and packs children before parents. Planning fails if
the source cut cannot derive the target cut.

## Compiler lowering

The compiler lowers each selected cut node to one field:

- `Actor(A)` becomes a concrete actor-template field.
- `Family(F)` becomes the digest of the ordered family table.

An actor in a route-family component uses an open local representation. Its
direct component actors remain separate fields. Its table actors stay in the
route table. Other families remain packed. A direct consume can also make an
actor hold an open foreign family as separate templates.

The compiler creates transitions only for real, non-self emit edges:

- **Open:** The entry witness supplies the table preimage. SIL verifies the
  preimage against the source digest. If the target is in the table, SIL slices
  its template from this witness for `validateOutputStateWithTemplate`.
- **Pack:** A local family hashes its route table. An open foreign family first
  concatenates its templates in table order and then hashes the result.
- **Keep:** The compiler copies a retained field.

Route fields are actor-local. Actors that own one declared state can still have
different route fields. If all layouts are equal, they use the normal named SIL
state struct. If layouts differ, the compiler can generate actor-qualified
layouts and a user-fields-only state body.

A state body keeps a source value independent of its possible target layouts.
The compiler does not need it when a local has exactly one concrete route. In
that case, the compiler generates the target layout at the original declaration
and computes edge-specific packed digests there.

The compiler also computes conservative needs for unqualified and dynamic
state values. It combines needs by declared state and propagates them through
state-to-state routes. This result is a fallback layout. It does not replace
the actor-specific commitment plan.

## Boundary invariants

- Route-plan actors exactly match the selected app.
- Every domain actor is in the graph. Components partition each domain.
- Families do not overlap. Cohorts do not overlap.
- A family table contains at least two distinct actors in canonical order.
- Direct family actors are the exact complement of the table actors.
- Cohort actors have equal needs, cuts, and generated layouts.
- A cohort cut gives direct access to all cohort actors and direct consume
  targets.
- Cohort needs propagate to every upstream emitter.
- Every real route transition is derivable from its source cut.
- Cut transitions define family witnesses and hashes.
- Constructor fields, runtime roles, SIL fields, and artifact receipts describe
  the same actor cut.
- Selector variants use one table order and one cut transition.

## Current limits and reference cases

The current heuristic is coarse and creates only one-level families. Each
component with at least two actors becomes a cohort. Cohort propagation uses a
quadratic synthetic clique. [Routing Optimization Opportunities](../src/routing/optimization.md)
records specific improvements and their required behavior.

Pinned generated examples show important compiler cases:

- `examples/build/toy_chess` shows a common layout. `Player` opens the Board
  family without a state body.
- `examples/build/route_state_bodies/sil/Lobby.sil` and `Mux.sil` show direct
  opening and packing without redundant state bodies.
- `examples/build/route_state_body_choice/sil/Lobby.sil` shows a required
  neutral state body. One `BoardState` local routes to the open Mux layout or
  to the empty Spectator cut.
- `examples/build/route_state_bodies/sil/Archive.sil` shows a selected gate
  template sliced from an open foreign table.

`./check.sh --full` regenerates these files. It compiles all generated SIL
contracts. It then runs the workspace tests and lints.
