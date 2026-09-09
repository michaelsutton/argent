# Argent security invariants

This document records subtle security arguments behind Argent's generated
checks. It states the assumptions, claims, and short proofs that are easy to
lose when reading the compiler or generated Sil in isolation. It is not a
substitute for an audit of an application or its generated contracts.

## Artifact verification trust boundary

Artifact verification checks consistency between the schema, Silverscript
ABI, template plan, compiled frames, and declared artifact identity. It assumes
the artifact was produced by supported Argent and Silverscript compilers and
may rely on compiler-enforced representation invariants, such as fixed-size
runtime state fields.

Verification does not recompile the recorded source or attest compiler
provenance. An attacker can replace bytecode and related metadata together.
Consumers must obtain an artifact from a trusted build or compare its computed
identity with a separately trusted identity. Verification should not reproduce
parts of compilation only to reject representations that the supported
compilers cannot emit.

## In-app actor template identity

A covenant ID defines a closed app domain. Generated template readers
distinguish actors within that app. Each actor is identified by its template
hash and physical state length, but two actor frames can still accept the same
complete redeem script.

The actor frames must partition the valid app scripts: each valid script must
belong to exactly one actor. Argent conservatively rejects two in-app actors
when their complete script lengths are equal, their prefixes are comparable,
and their suffixes are comparable. The compiler checks final compiled frames,
and artifact verification repeats the check.

The complete definition and security argument are in
[Template-frame identity](template-frame-identity.md).

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

Delegate entries authenticate a coordinating actor without authorizing outputs
of their own. Argent closes coordinated same-covenant input groups because an
input cannot safely determine which entrypoint another input selected.

The complete argument is in
[Leader and delegate input groups](leader-delegate-input-groups.md).

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
