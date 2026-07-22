# Security

This document records subtle security arguments behind Argent's generated
checks. It states the assumptions, claims, and short proofs that are easy to
lose when reading the compiler or generated Sil in isolation. It is not a
substitute for an audit of an application or its generated contracts.

## Single-actor direct input state reads

A single-actor application can consume another input of the same actor without
a template witness. The compiler uses `readInputState` only when the selected
application has one actor and that actor consumes its own type.

The covenant input group is closed to the application contract. Therefore,
each input in that group has the same generated contract template. The direct
read can use the current contract layout safely.

This exception must not apply to a multi-actor application. A matching source
actor name or state layout is not enough. Another actor contract can be in the
same covenant input group. In that case, the compiler must keep the template
witness and use `readInputStateWithTemplate`.

## Leader and delegate input groups

Delegate entries participate in a same-covenant transition without authorizing
outputs of their own. They must authenticate the actor coordinating the
transition, but they cannot safely determine which entrypoint another input
selected from that input's signature script. Argent therefore protects
delegation at actor granularity.

The first consumed actor in a delegate's `consumes` clause is its statically
declared leader actor. An actor named this way by any delegate is a *leader
actor*. Its artifact records the delegate entries that trust it under
`leader_for`. Each actor lowers to one Sil contract.

### Assumptions

1. Consensus provides a deterministic transaction-order index for every input
   sharing a covenant ID.
2. Every transaction input independently executes its selected contract
   entrypoint.
3. `readInputStateWithTemplate` authenticates the input's P2SH template before
   decoding its state, under the collision resistance of the template hash.
4. `OpCovInputCount` and `OpCovInputIdx` expose the consensus-derived covenant
   input group.

### Claim 1: a delegate cannot occupy the leader position

A generated delegate requires its active input not to equal covenant input
zero. Therefore a successful delegate is never the first input in its covenant
group.

### Claim 2: a delegate authenticates its leader actor's contract

A generated delegate reads covenant input zero using the template of its first
consumed actor. A transaction using another contract at that position fails
template validation. The delegate therefore trusts the generated contract of
the named leader actor, not an unauthenticated entrypoint selector.

### Claim 3: covenant input zero executes a leader entry

Every delegate rejects execution at covenant input zero. Since every input must
execute successfully, the authenticated leader actor at input zero must
execute one of its leader entries.

### Claim 4: a leader actor rejects undeclared same-covenant inputs

Every leader entry of a leader actor requires:

```text
OpCovInputCount(covenant_id) == 1 + declared_consumes
```

An entry with no `consumes` actors consequently requires exactly one input in
its covenant group. An entry with declared consumes also verifies that it is
input zero and reads each declared actor at its assigned covenant position.
Adding an undeclared delegate or any other same-covenant input changes the count
and fails the leader script.

### Result

A successful delegated transition has a leader entry of the authenticated
leader actor at covenant input zero. That entry fixes the complete
same-covenant input count, while each delegate independently authenticates the
leader actor's generated contract and rejects the leader position. An unrelated
standalone entry of the same actor cannot unknowingly carry additional
delegates.

### Leader-actor batching restriction

The restriction applies to the whole leader actor because all of its entries
share one generated contract and another input's entrypoint selector is not
safely introspectable. Once any delegate names an actor as its leader, every
leader entry of that actor closes its same-covenant input group, including
otherwise independent 1:N entries.

This does not prevent the transaction from containing ordinary inputs or inputs
with other covenant IDs. `consumes`-free leader entries of non-leader actors
retain ambient same-covenant batching. The artifact lists the delegate
declarations that cause the restriction in `leader_for`, and the runtime
transaction builder reports violations before constructing signature scripts.
This runtime check is fail-fast diagnostics; the generated Sil check is the
security boundary.

## Genesis spawns

Scripts cannot enumerate the genesis outputs authorized by an input. Argent
therefore passes each spawn clause the global indices of its declared outputs
as untrusted witnesses. The active input outpoint and every selected output's
value and script bytes are read directly from the transaction.

### Assumptions

1. Consensus derives a genesis covenant ID from the authorizing input outpoint
   and the complete output group carrying that ID, ordered by global output
   index.
2. Spawned Argent actors use the version-0 P2SH layout validated by the
   generated output checks.
3. The keyed covenant-ID hash is collision resistant.

### Claim 1: a spawn clause authenticates its complete genesis group

The generated script reconstructs the consensus preimage from the active input
outpoint, the statically declared output count, and the witnessed output
indices and transaction-derived output data. It requires the resulting ID to
equal the covenant ID of the first selected output.

Consensus derives that output's ID from its complete genesis group. Under hash
collision resistance, the witnessed sequence must therefore be exactly that
complete ordered group. Omitting, adding, reordering, duplicating, or replacing
an output changes the preimage. Checking the remaining selected outputs'
covenant IDs would add no further proof.

### Claim 2: one genesis group cannot satisfy two spawn clauses

For multiple clauses, Argent requires their first witnessed output indices to
be strictly increasing. A complete genesis group has one fixed first output, so
the same group cannot satisfy two clauses, and source declaration order is
bound to transaction group order.

### Scope

The checks authenticate every declared spawn group because the application may
grant authority to the resulting covenant IDs. Additional undeclared genesis
groups are allowed: their covenant IDs receive no authority from the declaring
entry.
