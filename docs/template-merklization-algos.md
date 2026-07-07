# Template Merklization Algorithms

This document sketches the compiler algorithms for replacing Argent's flat
template table with a Merkleized template commitment structure.

The goal is not only to reduce template plumbing. The goal is to make the app
template topology a compiler-owned object that can be:

- lowered into plain Silverscript checks,
- consumed by a future transaction builder,
- and explained by a reproducible audit receipt.

This document is self-contained. It describes the abstract input actor graph,
the derived output structure, and the first non-degenerate planning policy:
build the full template tree, but use a uniform cut for all actors before
attempting actor-specific optimization.

## Problem

Argent actors can route to other actors:

```ag
become ticket <- Ticket(next_ticket);
```

The generated Silverscript must prove that the output is locked by the expected
target contract template and expected target state.

The current prototype carries a flat set of template hash fields in every actor
state:

```sil
byte[32] template_issuer;
byte[32] template_ticket;
byte[32] template_player;
...
```

This is correct but crude. Chess showed a better manual pattern: pack subsets of
template hashes under commitments and open only the relevant subset when a route
needs it.

The compiler problem is:

1. Given an abstract actor graph, build a deterministic template commitment tree.
2. Decide which cut of that tree each actor carries in state.
3. For each route, produce the witness recipe needed to open the target template
   from the source actor's cut.
4. Generate Silverscript that checks those openings and preserves the target
   actor's expected cut.
5. Emit artifacts that make transaction construction and audit practical.

## Formal Model

The algorithms operate on an abstract actor graph, not directly on parser data.
The parser and semantic validator are responsible for producing this graph.

### Input: Actor Graph

Let:

```text
G = (V, E, P, M)
```

where:

- `V` is a finite set of actor vertices.
- `E` is a finite set of directed route edges.
- `P` is a finite set of terminal paths.
- `M` is metadata for app name, entries, output handles, auth indices, and source
  locations.

A vertex `v in V` is:

```text
v = (actor_name, state_type, template_symbol)
```

Definitions:

```text
name(v)      = actor_name
state(v)     = source state type owned by v
template(v)  = symbolic template hash for v
```

An edge `e in E` is:

```text
e = (src, dst, entry, output, path)
```

where:

```text
src(e)    in V              // actor executing the entry
dst(e)    in V              // actor targeted by become
entry(e)  in Entries(src)   // source entry
output(e) in OutputHandles  // emitted output handle
path(e)   in P              // terminal path containing this edge
```

A terminal path `p in P` is:

```text
p = (src, entry, [e_0, e_1, ..., e_k])
```

where all edges in the path share the same source actor and entry:

```text
forall e in routes(p):
    src(e) = src(p)
    entry(e) = entry(p)
    path(e) = p
```

`M` includes the source-level emit shape:

```text
emit(src, entry) =
    none
  | one { allowed_targets }
  | named { output_handle -> (auth_index, allowed_targets) }
```

The graph is well-formed iff:

```text
forall e in E:
    src(e), dst(e) in V
    output(e) is allowed by emit(src(e), entry(e))
    dst(e) is in the allowed target set for output(e)

forall p in P:
    routes(p) is non-empty
    routes(p) covers every required emitted output exactly once
    p is terminal in the source control-flow graph
```

The rest of this document assumes `G` is well-formed.

### Template Tree

Given `G`, define one template leaf per actor:

```text
leaf(v) = H("argent.template.leaf" || app_name || name(v) || template(v))
```

Binding `name(v)` prevents a proof of "some template in the app" from being
misused as a proof of a specific actor's template.

A template tree is:

```text
T = (N, root, kind, child, parent, hash)
```

where:

- `N` is the set of Merkle tree nodes.
- `root in N` is the root node.
- `kind(n)` is `leaf(v)`, `pair(left, right)`, or `promoted(child)`.
- `child(n)` gives the ordered children of `n`.
- `parent(n)` gives the parent of `n`, except for `root`.
- `hash(n)` is the hash expression for `n`.

Hash definitions:

```text
hash(leaf(v)) =
    H("argent.template.leaf" || app_name || name(v) || template(v))

hash(pair(l, r)) =
    H("argent.template.node" || hash(l) || hash(r))

hash(promoted(c)) =
    H("argent.template.promoted" || hash(c))
```

The first implementation sorts leaves by actor name. Future implementations may
cluster leaves by graph structure, but ordering must remain deterministic and
recorded in the audit receipt.

Useful relations:

```text
descendant(x, y)  := x is equal to y or below y in T
covers(y, x)      := descendant(x, y)
leaf_of(v)        := the unique leaf node for actor v
```

### Cut

A cut is an antichain of template tree nodes:

```text
C = { n_0, n_1, ..., n_m } where n_i in N
```

For the first implementation, cuts are full frontiers:

```text
forall v in V:
    exists exactly one n in C such that covers(n, leaf_of(v))
```

Later actor-specific optimizations may use partial cuts, but those require
additional expansion rules and are intentionally out of scope for the first
implementation.

Every actor carries a compiler-assigned cut in its state. The cut is stored as
one field per cut node:

```sil
byte[32] template_cut_0;
byte[32] template_cut_1;
...
```

### Route Opening

For each edge `e`, an opening proves that the target actor's template leaf is
under a node carried by the source actor.

```text
O(e) = (anchor, leaf, steps)
```

where:

```text
leaf   = leaf_of(dst(e))
anchor in C(src(e))
covers(anchor, leaf)
steps  = path from leaf upward to anchor
```

Each step is:

```text
step = (sibling, direction)
direction in { current_is_left, current_is_right, promoted }
```

The transaction builder provides the sibling hash values. The compiler knows the
shape and emits the verifier code.

### Output: Template Plan

The algorithms produce a template plan:

```text
Pi = (G, T, C, O, R)
```

where:

- `G` is the input actor graph.
- `T` is the template tree.
- `C: V -> Cut(T)` assigns each actor its carried cut.
- `O: E -> Opening(T)` assigns each route edge its opening.
- `R` is receipt and builder metadata derived from the same plan.

In code-shaped terms:

```rust
struct TemplatePlan {
    graph: ActorGraph,
    template_tree: TemplateTree,
    actor_cuts: BTreeMap<ActorId, Cut>,
    route_openings: BTreeMap<RouteId, RouteOpening>,
    receipt: AuditReceipt,
    builder: BuilderArtifact,
}
```

### Plan Validity

A template plan `Pi = (G, T, C, O, R)` is valid iff:

```text
1. G is well-formed.

2. T has exactly one leaf for every v in V.

3. For every v in V, C(v) is a full cut of T.

4. For every e in E:
       let o = O(e)
       o.leaf = leaf_of(dst(e))
       o.anchor in C(src(e))
       covers(o.anchor, o.leaf)
       o.steps is exactly the path from o.leaf to o.anchor in T

5. R is derived only from (G, T, C, O).
```

The generated system must then enforce:

1. every route target template leaf is opened from the source actor's carried
   cut;
2. every target output is validated with the opened target template hash and the
   expected target state;
3. every target state carries the compiler-assigned cut for the target actor;
4. cut fields are immutable across state transitions unless the compiler emits a
   checked cut transformation;
5. the launch/genesis proof initializes all cut fields correctly from the app
   template tree;
6. route witnesses may reveal committed tree structure, but cannot introduce an
   uncommitted template.

## First Policy

The first serious implementation should not be root-only. It should build the
full Merkle tree and use a simple uniform cut.

Policy:

```text
Template tree: full canonical binary tree over all actors.
Cut policy: uniform frontier at a chosen depth or maximum width.
Actor cuts: every actor carries the same cut.
Optimization: none.
```

For example, with four actors:

```text
root
|-- cut_0
|   |-- League
|   `-- Player
`-- cut_1
    |-- StonesGame
    `-- StonesSettle
```

Every actor state carries:

```sil
byte[32] template_cut_0;
byte[32] template_cut_1;
```

A route to `Player` opens `Player` from `template_cut_0`.
A route to `StonesGame` opens `StonesGame` from `template_cut_1`.

This exercises the full machinery while postponing the hard actor-specific cut
optimization.

## Algorithm 1: Extract The Actor Graph

Input: validated Argent AST.
Output: well-formed actor graph `G = (V, E, P, M)`.

```text
ExtractActorGraph(ast):
    V := {}
    E := {}
    P := {}
    M := empty metadata

    for each actor declaration A in the selected app:
        v := fresh vertex
        name(v) := A.name
        state(v) := A.state
        template(v) := symbol("template_" + snake(A.name))
        V := V union {v}

    for each actor declaration A:
        src := vertex named A.name

        for each entry q in A.entries:
            M.emit(src, q) := lower_emit_shape(q.emits)

            for each terminal route set S in q.terminal_route_sets:
                p := fresh path
                src(p) := src
                entry(p) := q
                routes(p) := []
                P := P union {p}

                for each route r in S:
                    e := fresh edge
                    src(e) := src
                    dst(e) := vertex named r.actor
                    entry(e) := q
                    output(e) := r.output
                    path(e) := p

                    E := E union {e}
                    routes(p).append(e)

    G := (V, E, P, M)
    assert WellFormedActorGraph(G)
    return G
```

The graph validator is intentionally part of this algorithm's contract:

```text
WellFormedActorGraph(G):
    for each e in E:
        assert src(e) in V
        assert dst(e) in V
        assert output(e) is declared by M.emit(src(e), entry(e))
        assert dst(e) is allowed by output(e)

    for each p in P:
        assert routes(p) is not empty
        assert all e in routes(p) have src(e) = src(p)
        assert all e in routes(p) have entry(e) = entry(p)
        assert handles(routes(p)) exactly covers outputs(M.emit(src(p), entry(p)))
```

This validation is the graph-level version of the current `emits` /
terminal-`become` coverage checks.

## Algorithm 2: Build The Canonical Template Tree

Input: actor graph `G = (V, E, P, M)`.
Output: template tree `T = (N, root, kind, child, parent, hash)`.

```text
BuildTemplateTree(G):
    leaves := []

    for each v in sort_by_name(V):
        n := fresh tree node
        kind(n) := leaf(v)
        hash(n) := H("argent.template.leaf" || M.app_name || name(v) || template(v))
        leaves.append(n)

    level := leaves

    while length(level) > 1:
        next := []

        for i in range(0, length(level), 2):
            if i + 1 < length(level):
                l := level[i]
                r := level[i + 1]
                n := fresh tree node
                kind(n) := pair(l, r)
                child(n) := [l, r]
                parent(l) := n
                parent(r) := n
                hash(n) := H("argent.template.node" || hash(l) || hash(r))
                next.append(n)
            else:
                c := level[i]
                n := fresh tree node
                kind(n) := promoted(c)
                child(n) := [c]
                parent(c) := n
                hash(n) := H("argent.template.promoted" || hash(c))
                next.append(n)

        level := next

    root := level[0]
    return T
```

The promoted-node rule is a first-draft odd-level policy. It avoids fake
duplicate leaves. If we later prefer explicit padding leaves, that policy should
replace this algorithm and be reflected in the audit receipt.

## Algorithm 3: Choose A Uniform Cut

Input: template tree `T`, uniform cut policy.
Output: a full cut `C*`.

```text
UniformCutPolicy =
    Depth(d)
  | MaxWidth(w)
```

Depth policy:

```text
ChooseUniformCut(T, Depth(d)):
    C := {}

    Visit(root(T), 0):
        if depth = d or kind(node) is leaf:
            C := C union {node}
            return

        for each child in child(node):
            Visit(child, depth + 1)

    return C
```

Max-width policy:

```text
ChooseUniformCut(T, MaxWidth(w)):
    C := { root(T) }

    while exists expandable n in C and |C| - 1 + |child(n)| <= w:
        choose expandable n in C with largest covered leaf count
        C := (C - {n}) union child(n)

    return C
```

For the first implementation, `Depth(1)` is a good default for apps with at
least four actors. Very small apps naturally collapse to root or leaves.

## Algorithm 4: Assign Cuts

Input: actor graph `G`, uniform cut `C*`.
Output: actor cut function `C: V -> Cut(T)`.

```text
AssignUniformCuts(G, C*):
    for each v in V:
        C(v) := C*

    return C
```

This is intentionally simple. It still establishes the state encoding and route
opening model needed for later optimization.

Future optimized policy:

```text
AssignOptimizedCuts(G, T):
    SCC := strongly_connected_components(V, E)
    clusters := cluster_by_scc_and_route_weights(SCC, G)
    return choose_actor_specific_frontiers(clusters, G, T)
```

## Algorithm 5: Plan Route Openings

Input: actor graph `G`, template tree `T`, cut function `C`.
Output: route opening function `O: E -> Opening(T)`.

```text
PlanRouteOpenings(G, T, C):
    O := empty map

    for each e in E:
        target_leaf := leaf_of(dst(e))

        candidates := {
            n in C(src(e))
            where covers(n, target_leaf)
        }

        assert |candidates| = 1
        anchor := the single node in candidates

        steps := PathToAncestor(T, target_leaf, anchor)

        O(e) := (anchor, target_leaf, steps)

    return O
```

The path helper is purely structural:

```text
PathToAncestor(T, leaf, anchor):
    steps := []
    current := leaf

    while current != anchor:
        p := parent(current)

        if kind(p) = pair(left, right):
            if current = left:
                steps.append((sibling = right, direction = current_is_left))
            else:
                steps.append((sibling = left, direction = current_is_right))
        else if kind(p) = promoted(child):
            steps.append((sibling = none, direction = promoted))

        current := p

    return steps
```

For a uniform full cut, every route has exactly one valid anchor. For
actor-specific cuts, the planner must either choose cuts that cover outgoing
targets or add explicit cut expansion witnesses.

## Algorithm 6: Verify The Template Plan

Input: candidate template plan `Pi = (G, T, C, O, R)`.
Output: success or compiler error.

```text
VerifyTemplatePlan(Pi):
    assert WellFormedActorGraph(G)

    for each v in V:
        assert exists exactly one n in N such that kind(n) = leaf(v)

    for each v in V:
        assert IsFullCut(T, C(v))

    for each e in E:
        o := O(e)

        assert o.leaf = leaf_of(dst(e))
        assert o.anchor in C(src(e))
        assert covers(o.anchor, o.leaf)
        assert o.steps = PathToAncestor(T, o.leaf, o.anchor)

    assert ReceiptDerivedFrom(R.receipt, G, T, C, O)
    assert BuilderDerivedFrom(R.builder, G, T, C, O)
```

Full-cut check:

```text
IsFullCut(T, C_v):
    for each pair a,b in C_v:
        assert not covers(a, b)
        assert not covers(b, a)

    for each leaf l in leaves(T):
        assert exists exactly one n in C_v such that covers(n, l)
```

This verifier is not merely documentation. The implementation should include an
internal equivalent and run it before emitting Silverscript or artifacts.

## Algorithm 7: Build The Template Plan

Input: well-formed actor graph `G`, uniform cut policy.
Output: template plan `Pi = (G, T, C, O, R)`.

```text
BuildTemplatePlan(G, policy):
    T := BuildTemplateTree(G)
    C_star := ChooseUniformCut(T, policy)
    C := AssignUniformCuts(G, C_star)
    O := PlanRouteOpenings(G, T, C)
    R := PlanArtifacts(G, T, C, O)

    Pi := (G, T, C, O, R)
    VerifyTemplatePlan(Pi)
    return Pi
```

`PlanArtifacts` groups route openings by entry and terminal path, then derives
the audit receipt and builder artifact from the same plan:

```text
PlanArtifacts(G, T, C, O):
    for each entry q:
        for each p where entry(p) = q:
            path_plan(p) := [ O(e) for e in routes(p) ]

    receipt := BuildAuditReceipt(G, T, C, O)
    builder := BuildBuilderArtifact(G, T, C, O)
    return (receipt, builder, path_plans)
```

## Lowering: Actor State Cut Fields

For each actor, emit one field per cut node.

Source state:

```ag
state TicketState {
    byte[32] owner;
    int serial;
}
```

Generated Silverscript state:

```sil
struct TicketState {
    byte[32] template_cut_0;
    byte[32] template_cut_1;
    // ----------- template cut fields above; source state below
    byte[32] owner;
    int serial;
}
```

For the current actor's own contract arguments:

```sil
contract Ticket(
    byte[32] init_template_cut_0,
    byte[32] init_template_cut_1,
    byte[32] init_owner,
    int init_serial
) {
    byte[32] template_cut_0 = init_template_cut_0;
    byte[32] template_cut_1 = init_template_cut_1;
    ...
}
```

## Lowering: Route Opening Check

For a route:

```ag
become ticket <- Ticket(next_ticket);
```

The template plan route opening says:

```text
target leaf: Ticket
opened from: template_cut_0
proof: [Issuer sibling leaf]
```

Generated entry params include the route witness:

```sil
byte[32] ticket_template;
byte[] ticket_prefix;
byte[] ticket_suffix;
byte[32] ticket_merkle_sibling_0;
```

Generated check:

```sil
byte[32] ticket_leaf = blake2b(
    bytes("argent.template.leaf") +
    bytes("Tickets") +
    bytes("Ticket") +
    ticket_template
);

byte[32] issuer_leaf = ticket_merkle_sibling_0;

byte[32] opened_cut = blake2b(
    bytes("argent.template.node") +
    issuer_leaf +
    ticket_leaf
);

require(opened_cut == template_cut_0);
```

Then validate the target output:

```sil
TicketState full_next_ticket = {
    template_cut_0: template_cut_0,
    template_cut_1: template_cut_1,
    // ----------- template cut fields above; source state below
    owner: next_ticket.owner,
    serial: next_ticket.serial
};

validateOutputStateWithTemplate(
    ticket_output_idx,
    full_next_ticket,
    ticket_prefix,
    ticket_suffix,
    ticket_template
);
```

The exact Sil syntax may differ. The important generated obligations are:

1. open target template from carried cut,
2. inject the target actor's assigned cut into target state,
3. validate output state with the opened template.

## Lowering: Multi-Output Terminal Path

For:

```ag
become {
    issuer <- Issuer(next_issuer);
    ticket <- Ticket(next_ticket);
};
```

The template plan contains two route openings under the same terminal path.

The emitter should share proof material when possible:

```rust
fn lower_terminal_path(path_plan: TerminalPathPlan) {
    let openings = path_plan.routes.map(|route| route.opening);
    let shared = find_shared_merkle_steps(openings);

    emit_shared_opening_checks(shared);

    for route in path_plan.routes {
        emit_route_opening_check(route);
        emit_validate_output_state(route);
    }
}
```

For the first implementation, proof sharing can be skipped. The template plan should still
represent paths explicitly so sharing can be added without changing source
semantics.

## Audit Receipt

The audit receipt is a human-readable and machine-readable explanation of the
template plan. It should be reproducible from source and compiler version.

Suggested JSON shape:

```json
{
  "app": "Tickets",
  "compiler": {
    "name": "argentc",
    "version": "0.1.0"
  },
  "template_tree": {
    "hash_domains": {
      "leaf": "argent.template.leaf",
      "node": "argent.template.node"
    },
    "root": "template_root",
    "nodes": [
      {
        "id": "cut_0",
        "kind": "pair",
        "children": ["Issuer", "Ticket"]
      }
    ]
  },
  "cut_policy": {
    "kind": "uniform",
    "reason": "first implementation policy",
    "nodes": ["cut_0"]
  },
  "actors": [
    {
      "actor": "Issuer",
      "carries_cut": ["cut_0"],
      "cut_reasons": [
        {
          "kind": "UniformPolicy",
          "detail": "all actors carry the same cut"
        }
      ],
      "entries": [
        {
          "entry": "issue",
          "emits": ["issuer", "ticket"],
          "terminal_paths": [
            {
              "path": 0,
              "routes": [
                "issuer -> Issuer",
                "ticket -> Ticket"
              ],
              "coverage": "complete"
            }
          ]
        }
      ]
    }
  ],
  "route_openings": [
    {
      "route": "Issuer.issue.path0.ticket",
      "source": "Issuer",
      "target": "Ticket",
      "opened_from": "cut_0",
      "proof_shape": ["Issuer sibling leaf"]
    }
  ]
}
```

The receipt must explain every non-trivial compiler choice. Prefer structured
reasons over prose that can drift.

```rust
enum CutReason {
    UniformPolicy,
    SelfTemplate,
    OutgoingRoute { entry: EntryId, output: OutputHandle, target: ActorId },
    SuccessorCut { target: ActorId, node: TreeNodeId },
    CycleGroup { group: usize },
}
```

The first implementation mostly uses `UniformPolicy`. Later optimized planners
should emit richer reasons.

## Builder Artifact

The builder artifact is the transaction-construction companion to generated
Silverscript.

It should let a user provide only real entry arguments while the artifact
supplies hidden compiler machinery:

- target template hashes,
- template prefix/suffix witnesses,
- Merkle opening witnesses,
- target cut field values,
- output handle to auth index mapping,
- expected terminal path metadata.

Suggested shape:

```rust
struct BuilderArtifact {
    app: String,
    actors: Vec<ActorAbi>,
    template_tree: TemplateTreeArtifact,
    routes: Vec<RouteWitnessRecipe>,
}

struct ActorAbi {
    actor: ActorId,
    entries: Vec<EntryAbi>,
}

struct EntryAbi {
    entry: EntryId,
    user_params: Vec<ParamAbi>,
    hidden_params: Vec<HiddenParamAbi>,
    outputs: Vec<OutputAbi>,
    terminal_paths: Vec<TerminalPathAbi>,
}

struct RouteWitnessRecipe {
    route: RouteId,
    target_template_hash: TemplateHashRef,
    prefix_suffix: PrefixSuffixRef,
    merkle_steps: Vec<MerkleWitnessRef>,
}
```

The audit receipt explains the plan. The builder artifact executes the plan.
Both are derived from the same template plan.

## Future Optimization Algorithms

Once the uniform cut implementation is stable, actor-specific cuts can be added.

Potential optimization pipeline:

```rust
fn optimize_cuts(graph: &ActorGraph, tree: &TemplateTree) -> BTreeMap<ActorId, Cut> {
    let sccs = strongly_connected_components(graph);
    let route_weights = estimate_route_weights(graph);
    let clusters = cluster_templates(sccs, route_weights);
    let tree = rebuild_tree_from_clusters(clusters);

    for actor in graph.actors {
        let required = required_leaves_for_actor(actor, graph);
        let pass_forward = required_cut_nodes_for_successors(actor, graph);
        let candidates = candidate_frontiers(tree, required, pass_forward);
        actor_cuts[actor] = choose_lowest_cost_cut(candidates);
    }

    actor_cuts
}
```

Possible cost model:

```text
cost(actor cut) =
    state_field_weight * carried_cut_fields
  + witness_weight * expected_route_opening_steps
  + code_weight * generated_verifier_size
```

Inputs to the cost model:

- strongly connected components,
- route frequency hints,
- terminal path fanout,
- expected witness sizes,
- contract byte-size limits,
- transaction mass impact.

Important future optimizations:

1. Strongly connected actors should usually live near each other in the tree.
2. Multi-output terminal path targets should share proof material when possible.
3. Terminal/cold actors can stay behind larger commitments.
4. Acyclic regions may not need to preserve all cuts forever.
5. Foreign observed apps may expose only a root or published cut, not full local
   tree structure.

## Open Questions

1. What exact hash domains and encodings should be used?
2. Should odd tree levels promote nodes or use explicit padding leaves?
3. Should the first uniform cut use depth, max width, or a target byte budget?
4. How much proof sharing should the first emitter attempt?
5. Should target cut injection be explicit in generated Sil structs or hidden by
   helper functions?
6. How should launch/genesis proofs expose the initial template tree and cuts?
7. Should the manifest, audit receipt, and builder artifact be one file or three
   separate files?

## First Implementation Checklist

1. Add graph extraction from current AST entries and terminal route sets.
2. Add `TemplateTree` and canonical tree construction.
3. Add uniform cut planning.
4. Add `TemplatePlan` as the central lowering plan.
5. Emit cut fields instead of flat `template_*` fields.
6. Emit route opening witness params.
7. Emit route opening checks before `validateOutputStateWithTemplate`.
8. Preserve target cut fields in generated target states.
9. Emit audit receipt.
10. Emit builder artifact skeleton.
11. Confirm `tickets` and `stones` compile and generated Sil is explainable by
    the receipt.
