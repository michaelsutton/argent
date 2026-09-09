# Leader and delegate input groups

Delegate entries participate in a same-covenant transition without authorizing
outputs of their own. They must authenticate the actor coordinating the
transition, but they cannot safely determine which entrypoint another input
selected from that input's signature script. Argent therefore protects
delegation at actor granularity.

The first consumed actor in a delegate's `consumes` clause is its statically
declared leader actor. An actor named this way by any delegate is a *leader
actor*. Its artifact records the delegate entries that trust it under
`leader_for`. Each actor lowers to one Sil contract.

## Assumptions

1. Consensus provides a deterministic transaction-order index for every input
   sharing a covenant ID.
2. Every transaction input independently executes its selected contract
   entrypoint.
3. `readInputStateWithTemplate` authenticates the input's P2SH template before
   decoding its state, under the collision resistance of the template hash.
4. `OpCovInputCount` and `OpCovInputIdx` expose the consensus-derived covenant
   input group.

## Claim 1: a delegate cannot occupy the leader position

A generated delegate requires its active input not to equal covenant input
zero. Therefore a successful delegate is never the first input in its covenant
group.

## Claim 2: a delegate authenticates its leader actor's contract

A generated delegate reads covenant input zero using the template of its first
consumed actor. A transaction using another contract at that position fails
template validation. The delegate therefore trusts the generated contract of
the named leader actor, not an unauthenticated entrypoint dispatch tag.

## Claim 3: covenant input zero executes a leader entry

Every delegate rejects execution at covenant input zero. Since every input must
execute successfully, the authenticated leader actor at input zero must
execute one of its leader entries.

## Claim 4: a leader actor rejects undeclared same-covenant inputs

Every leader entry of a leader actor requires:

```text
OpCovInputCount(covenant_id) == 1 + declared_consumes
```

An entry with no `consumes` actors consequently requires exactly one input in
its covenant group. An entry with declared consumes also verifies that it is
input zero and reads each declared actor at its assigned covenant position.
Adding an undeclared delegate or any other same-covenant input changes the count
and fails the leader script.

## Result

A successful delegated transition has a leader entry of the authenticated
leader actor at covenant input zero. That entry fixes the complete
same-covenant input count, while each delegate independently authenticates the
leader actor's generated contract and rejects the leader position. An unrelated
standalone entry of the same actor cannot unknowingly carry additional
delegates.

## Leader-actor batching restriction

The restriction applies to the whole leader actor because all of its entries
share one generated contract and another input's selected entrypoint is not
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
