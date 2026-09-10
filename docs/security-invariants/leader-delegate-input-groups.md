# Leader and delegate input groups

Argent lets several inputs from the same covenant participate in one
transaction. They may form one coordinated transition, where a leader consumes
other actors and their delegate entries approve the coordination. They may also
be independent transitions that are only batched together. This document
defines how Argent secures the coordinated case without unnecessarily
restricting the independent case.

The argument relies on one key property of
[KIP-20](https://github.com/kaspanet/kips/blob/master/kip-0020.md): every
covenant continuation output names exactly one authorizing input. KIP-20 also
exposes the complete input and continuation-output groups for a covenant ID,
and the continuation outputs authorized by each input. Genesis outputs are
separate from these continuation groups.

*Same-covenant batching* means spending several inputs with the same covenant
ID while each input independently authorizes and validates its own continuation
outputs.

> A key challenge: actor authentication identifies another input's contract,
> but not the entrypoint it selected. The design must therefore account for
> every entrypoint that can execute within an authenticated actor contract.

## Design principles

- Use the narrowest consensus opcode that expresses each rule.
- Restrict batching only where the restriction is required for delegation.
- Prefer `OpAuthOutputCount` and `OpAuthOutputIdx` over their covenant-wide
  equivalents when either view is sufficient. The authorization view takes an
  input index instead of a 32-byte covenant ID and naturally separates
  independent transitions in one batch. Use the covenant-wide view only when a
  rule needs the complete covenant continuation group.

## Model

- `c` is the active covenant ID.
- `I(c)` is the ordered list of transaction input indices carrying `c`.
- `O(c)` is the set of continuation outputs carrying `c`. Genesis outputs are
  not members of `O(c)`.
- For `i ∈ I(c)`, `A(i)` is the set of outputs in `O(c)` authorized by
  transaction input `i`.
- Every continuation output has one authorizer. Therefore `A(i) ⊆ O(c)`, and
  `A(i)` and `A(j)` are disjoint for distinct inputs `i` and `j`.
- `m(e)` is the minimum number of current-covenant continuations permitted by
  ordinary entry `e`.
- An *actor contract* is one actor's compiled Silverscript contract. It can
  contain several entrypoints.
- An *ordinary entry* is declared with `entry` and may authorize continuations.
- A *delegate entry* is declared with `delegate`. It names its leader actor as
  its first consume and authorizes no continuations.
- A *leader actor* is an actor named as the leader by any delegate.
- A *delegate-capable actor* declares at least one delegate entry.
- A *coordinated leader entry* is an ordinary entry with a `consumes` clause.
- The *leader input* is `l = I(c)[0]`.
- A *delegate input* `d` occupies a nonzero consumed position whose actor
  declares a delegate for the leader actor.
- A *zero-capable entry* has `m(e) = 0`.

## Compiler rules

1. **Rule 1 — Actor identity.** Every cross-actor input position authenticates
   its expected actor contract. In-app actor frames are unambiguous under the
   [template identity invariant](template-frame-identity.md).
2. **Rule 2 — Delegate shape.** A delegate authenticates its declared leader
   actor at `I(c)[0]`, rejects execution at `I(c)[0]`, requires `A(d) = ∅`, and
   cannot use `become` or `spawns`.
3. **Rule 3 — Input-group closure.** Every coordinated leader entry executes at
   `I(c)[0]`, covers the complete `I(c)` group with its resolved `consumes`
   cardinalities, and authenticates every consumed actor. Every ordinary entry
   of a leader actor also closes its input group; without `consumes`, it
   requires `|I(c)| = 1`.
4. **Rule 4 — Authorized-output integrity.** Every ordinary entry enforces the
   resolved cardinality of `A(i)` and validates every successor in `A(i)`.
5. **Rule 5 — Continuation closure.** Every coordinated leader input `l`
   requires:

   ```text
   |O(c)| = |A(l)|
   ```

   Generated Silverscript expresses this as:

   ```text
   OpCovOutputCount(c) == OpAuthOutputCount(l)
   ```

   ***[NOT IMPLEMENTED]***

6. **Rule 6 — Zero-continuation position.** An otherwise-batchable,
   consumes-free ordinary entry on a delegate-capable actor requires its active
   input `i` to equal `I(c)[0]` when `m(e) = 0`. This includes `emits none`,
   zero-minimum output ranges, and spawn-only entries.

   Generated Silverscript expresses this as:

   ```text
   OpCovInputIdx(c, 0) == this.activeInputIndex
   ```

   ***[NOT IMPLEMENTED]***

## Security properties

1. **Property 1 — Leader integrity.** A successful delegated transition has a
   coordinated ordinary entry of the declared leader actor at `I(c)[0]`.
2. **Property 2 — Input closure.** Every input in the coordinated covenant group
   belongs to the leader's declared `consumes` shape and has the expected actor
   contract.
3. **Property 3 — Continuation ownership.** The leader authorizes every output
   in `O(c)`. No consumed input creates a parallel continuation.
4. **Property 4 — Delegate-position integrity.** An ordinary entry cannot replace
   a delegate. A successful delegate position executes an outputless delegate
   which authenticates the leader actor.
5. **Property 5 — Spawn compatibility.** Genesis outputs created by `spawns`
   remain valid because they are outside `O(c)` and every `A(i)`.
6. **Property 6 — Minimal batching restriction.** Continuation closure does not
   restrict independent batches. Rule 6 requires an otherwise-batchable,
   zero-capable entry to execute first, but does not require it to be the only
   input in its covenant group.
7. **Property 7 — Actor-level scope.** Delegation authenticates actor contracts,
   not entrypoint dispatch tags. Compatible leader or delegate entries on the
   same actor remain intentionally indistinguishable.

## Proofs

### Claim 1: the leader owns the continuation group

For the coordinated leader input `l`, Rule 5 gives:

```text
|O(c)| = |A(l)|
```

By definition, `A(l) ⊆ O(c)`. The sets are finite and have the same size, so:

```text
A(l) = O(c)
```

This proves **Property 3**. Genesis outputs do not participate in either set,
which also proves **Property 5**.

### Claim 2: an ordinary entry cannot occupy a delegate position

Consider an ordinary entry selected at a delegate position:

- If it has `consumes`, Rule 3 requires it to execute at `I(c)[0]`.
- If it is consumes-free and `m(e) > 0`, Rule 4 gives it at least one output in
  `A(i)`. That output is not in the disjoint `A(l)`, which contradicts Claim 1.
- If it is consumes-free and `m(e) = 0`, Rule 3 already isolates it when its
  actor is also a leader actor. Otherwise, Rule 6 requires it to execute at
  `I(c)[0]`. Neither case permits execution at a nonzero delegate position.

All cases fail. This proves the ordinary-entry exclusion in **Property 4**.

### Claim 3: the leader and delegates form one closed group

Assume a delegate executes. Rule 2 makes it authenticate the leader actor at
`I(c)[0]` and prevents a delegate from occupying that position. Because the
leader actor has a delegate, its consumes-free ordinary entries require
`|I(c)| = 1` under Rule 3. They cannot execute with the delegate. The successful
entry at `I(c)[0]` must therefore be a coordinated ordinary entry of the leader
actor.

Conversely, assume a coordinated leader entry executes with a declared delegate
position. Rule 3 authenticates the actor contract at that position. Claim 2
excludes every ordinary entry on that actor. A delegate for another leader
fails Rule 2. The successful entry must therefore be an outputless delegate
which authenticates this leader actor.

Rule 3 also rejects every wrong, extra, or undeclared input. This proves
**Property 1**, **Property 2**, and **Property 4**.

## Batching and scope

Rule 5 applies only to coordinated leader entries, whose input groups are
already closed by Rule 3. It does not affect a transaction that batches only
independent ordinary entries. Those entries continue to enumerate and validate
their own `A(i)` sets through the cheaper authorization-output opcodes.

A continuing ordinary entry on a delegate-capable actor also remains batchable.
If it replaces a delegate in a coordinated transition, its nonempty `A(i)`
violates Claim 1. A zero-capable entry could otherwise look like an outputless
delegate, so Rule 6 requires it to lead its covenant group. It may still share
that group with other entries that remain batchable, but two entries subject to
Rule 6 cannot both occupy its first position. This proves **Property 6**.

The remaining limit is intentional. If several delegate entries on one actor
trust the same leader actor, any one of them may be selected. Two coordinated
entries on the leader actor can also be indistinguishable when they accept the
same input shape. An application that needs entry-specific authorization must
encode it in state or transaction checks, or use separate actor contracts.
This is **Property 7**.

The artifact records the actor and delegate relationships used to derive these
rules. The runtime transaction builder can report group-shape violations before
constructing signature scripts. Runtime checks provide early diagnostics; the
generated Silverscript checks enforce the security properties.
