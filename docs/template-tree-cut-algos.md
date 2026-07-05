# Template Tree And Actor Cut Algorithms

This note isolates the two pure planning problems behind template
merklization:

1. map an actor graph `G` to a template commitment tree `T`;
2. select a carried cut `C(v)` for each actor vertex `v`.

It intentionally ignores lowering, Silverscript syntax, transaction builders,
and optimality heuristics. The goal is only to state the problem correctly and
give a simple correct baseline.

## Input

Let the actor graph be:

```text
G = (V, E)
```

where:

- `V` is a finite set of actor vertices;
- `E` is a finite set of directed route edges.

A vertex `v in V` is:

```text
v = (actor_name, template_symbol)
```

An edge `e in E` is:

```text
e = (src, dst)
```

where `src(e), dst(e) in V`. The edge means that `src(e)` may create an output
which becomes `dst(e)`.

Terminal paths and output handles are important for source validation, but they
are not needed for these two pure algorithms once `G` is already known to be a
valid route graph.

## Template Tree

Each actor has one template leaf:

```text
leaf(v) = H("argent.template.leaf" || actor_name(v) || template_symbol(v))
```

A template tree is a rooted binary Merkle tree:

```text
T = (N, root, child, parent, hash)
```

where leaves are exactly `{ leaf(v) | v in V }`.

Define:

```text
covers(a, b) := node b is equal to node a or below node a in T
```

So `covers(a, b)` means the hash of `a` commits to the hash of `b`.

## Cut

A cut is an antichain of tree nodes:

```text
Cut(T) = { n_0, n_1, ..., n_k }
```

with no cut node below another cut node:

```text
forall a,b in Cut(T):
    a != b => not covers(a, b) and not covers(b, a)
```

An actor cut assignment is:

```text
C : V -> Cut(T)
```

`C(v)` is the set of template commitment nodes carried in actor `v`'s state.

## Authentication Predicate

The important relation is whether a carried cut can authenticate a tree node.

For the first implementation, the useful case is opening downward from a carried
node:

```text
CanOpen(C_v, n) :=
    exists a in C_v such that covers(a, n)
```

If `CanOpen(C_v, n)` holds, a witness can reveal the Merkle path from `n` up to
`a`, and the script can verify that `n` is committed by the actor's carried cut.

Later implementations may also support deriving an ancestor from multiple
finer cut nodes, but the first planner does not need that case.

## Valid Cut Assignment

The cut assignment must satisfy two obligations for every route edge:

```text
forall e in E, where e = (u -> v):
    1. CanOpen(C(u), leaf(v))
    2. forall n in C(v): CanOpen(C(u), n)
```

The first obligation lets `u` prove the target actor template for the output.

The second obligation lets `u` initialize the exact cut that `v` is supposed to
carry in its new state. Without this, the output could carry arbitrary template
commitments even if the target template itself is correct.

This is the core correctness condition for actor cuts.

## Algorithm 1: Build Template Tree

This baseline tree builder is deterministic and intentionally not optimized.

Input:

```text
G = (V, E)
```

Output:

```text
T
```

Algorithm:

```text
BuildTemplateTree(G):
    leaves := []

    for each v in V sorted by actor_name(v):
        leaves.append(leaf(v))

    level := leaves

    while |level| > 1:
        next := []

        for i = 0; i < |level|; i += 2:
            if i + 1 < |level|:
                left := level[i]
                right := level[i + 1]
                parent := H("argent.template.node" || hash(left) || hash(right))
                child(parent) := [left, right]
                next.append(parent)
            else:
                child := level[i]
                parent := H("argent.template.promoted" || hash(child))
                child(parent) := [child]
                next.append(parent)

        level := next

    root := level[0]
    return T
```

Any deterministic tree is valid as long as every actor has exactly one leaf.
Better tree shapes are optimization choices, not correctness requirements.

## Algorithm 2: Select Actor Cuts

This baseline cut selector uses one uniform frontier for every actor.

Input:

```text
G = (V, E)
T
depth d
```

Output:

```text
C : V -> Cut(T)
```

Algorithm:

```text
SelectUniformCuts(G, T, d):
    F := FrontierAtDepth(T.root, d)

    for each v in V:
        C(v) := F

    assert ValidCutAssignment(G, T, C)
    return C
```

Frontier construction:

```text
FrontierAtDepth(node, d):
    if d = 0 or node is a leaf:
        return { node }

    out := {}
    for each c in child(node):
        out := out union FrontierAtDepth(c, d - 1)

    return out
```

Validator:

```text
ValidCutAssignment(G, T, C):
    for each edge e in E:
        u := src(e)
        v := dst(e)

        assert CanOpen(C(u), leaf(v))

        for each n in C(v):
            assert CanOpen(C(u), n)
```

For a uniform frontier, the second condition is trivial because `C(u) = C(v)`.
The first condition holds because a frontier covers every leaf exactly once.

## Optimization Problem

The real compiler problem is to find a low-cost valid cut assignment:

```text
minimize cost(T, C)
subject to ValidCutAssignment(G, T, C)
```

Possible cost terms:

```text
cost(T, C) =
    carried_state_bytes(C)
  + expected_route_witness_bytes(G, T, C)
  + generated_verifier_code_size(G, T, C)
```

The baseline algorithms above do not optimize this objective. They only define
the structure and correctness constraints that optimized planners must preserve.
