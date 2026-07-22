# Entry effect ranges

## Purpose

Argent entry clauses describe an ordered transaction shape. Each declared
handle currently describes one input or one output. Some protocols need a
bounded number of items of the same actor type. A range lets one handle
describe that ordered group.

The compiler can lower a range to a Sil array and a bounded `for` loop. The
transaction sets the actual length. A compile-time upper bound limits the
generated script.

This feature is possible with the current Sil backend. It is not only a parser
change. It affects entry body types, transaction locations, artifact metadata,
hidden witnesses, and runtime resolution.

## Recommended source model

Use the current singleton form for one item:

```ag
consumes {
    owner: Account;
}
```

Use a cardinality suffix for a range:

```ag
const int MAX_ACCOUNTS = 8;

consumes {
    accounts: Account[1..=MAX_ACCOUNTS];
}
```

The lower and upper bounds are inclusive. Both bounds must be compile-time
integers. A range handle is an array in the entry body.

The same form applies to all ordered entry sections:

```ag
entry rebalance(next_states: AccountState[])
consumes {
    accounts: Account[1..=MAX_ACCOUNTS];
}
emits {
    next: Account[1..=MAX_ACCOUNTS];
} {
    require(accounts.length == next_states.length);
    become next <- Account(next_states);
}
```

An emitted range uses one bulk `become` route. The route state expression is
an array. The compiler validates one output for each array item.

Observed and spawned ranges use the same rule:

```ag
observes assets by self.asset_id {
    inputs {
        previous: Asset[1..=MAX_ASSETS];
    }
    outputs {
        next: Asset[1..=MAX_ASSETS];
    }
}

spawns batch by batch_id {
    outputs {
        items: Item[1..=MAX_ITEMS];
    }
}
```

Keep `emits one` as a singleton form. A ranged emit must use the named block
form because the body needs a range handle.

## Terms

- A **singleton** has cardinality one.
- A **range** has a compile-time minimum and maximum.
- The **actual length** is the item count in one transaction.
- A **range handle** is the shared source name for the items.
- A **section** is one ordered list, such as `consumes`, `emits`, or one
  `observes.inputs` list.
- A **template constant** is a value that fixes generated code and the actor
  template hash. It is not actor state and it is not an entry argument.

Do not use *range* for an actor union. An actor union selects a type. A range
selects a number of items.

## Semantic rules

The following rules apply to each range:

1. The transaction supplies the actual length.
2. The generated script requires `minimum <= actual length <= maximum`.
3. The generated script covers every item exactly once and in transaction
   order.
4. Every item has the actor type that the declaration permits.
5. Every input state read uses the required template check.
6. Every output state and template is validated.
7. The upper bound is part of the actor template. State cannot change it.
8. A bulk route state array has the same length as its output range.

The first version must not use a consume range in a delegate. A delegate's
covenant group can contain peer delegates that its clause does not name. The
complete group count therefore does not give the consume range length. A later
version needs an explicit partition length for this case. The first `consumes`
item must always remain a singleton because it names the leader actor.

A spawn clause must have a minimum total cardinality of at least one. An empty
genesis group has no output from which the script can prove its covenant ID. A
range in that clause can have a minimum of zero when a singleton output keeps
the clause nonempty.

## First-version boundary

Allow at most one range in each section. Singleton items can occur before and
after the range.

This rule makes the range length derivable from the complete section item
count:

```text
actual range length = group count - singleton count
```

For a leader `consumes` section, the section item count is
`OpCovInputCount(cov_id) - 1`. It excludes the active leader input. Auth output
and observed section counts use their complete group counts.

The compiler can then calculate every item location without a length witness.
For a range in the middle, the fixed prefix and fixed suffix determine its
start and end.

Two ranges in one section need extra partition data. The total group count does
not show where the first range ends. A later version can add named partition
lengths to the transaction context and hidden ABI. Do not add that mechanism
before a use case needs it.

The first version must also require one fixed actor type for all items in a
range. Defer these forms:

- one actor-enum selector for each item;
- one open `actor_type` value for each item;
- different actor types inside one range.

A later version can support one shared selector or one shared open actor type
for the complete range. Per-item selectors are a separate feature.

## Compile-time bounds

The first version should accept integer literals and existing top-level
`const int` values as bounds. Argent must evaluate them and require:

```text
0 <= minimum <= maximum
```

Sil already treats a contract constant as a compile-time loop bound. This is
enough for the first version.

Sil also treats constructor arguments as compile-time constants. Argent can
later add configurable template constants and emit them as non-state Sil
constructor arguments. The artifact must record their resolved values. A
change to such a value changes the compiled template and its hash.

Do not use a source state field as a range bound. Argent currently compiles
state constructor arguments with placeholder values when it builds a template.
A state field is also mutable. It cannot safely control loop unrolling or
transaction shape.

## Sil lowering

### Consumes

For this declaration:

```ag
consumes {
    accounts: Account[1..=MAX_ACCOUNTS];
}
```

the leader prelude has this shape:

```sil
int account_count = OpCovInputCount(cov_id) - 1;
require(account_count >= 1);
require(account_count <= MAX_ACCOUNTS);

Gen__AccountState[] accounts;
int[] account_input_indices;
for (i, 0, account_count, MAX_ACCOUNTS) {
    int input_idx = OpCovInputIdx(cov_id, 1 + i);
    account_input_indices = account_input_indices.append(input_idx);
    accounts = accounts.append(readInputStateWithTemplate(
        input_idx,
        account_prefix_len,
        account_suffix_len,
        account_template
    ));
}
```

The compiler rewrites `accounts[i].value` to the transaction input at
`account_input_indices[i]`. The existing single-actor direct-read optimization
can apply to each loop item when its current security rule applies.

### Emits

For a ranged output, the generated code checks the output count and the state
array length. It then validates each output:

```sil
int next_count = next_states.length;
require(next_count >= 1);
require(next_count <= MAX_ACCOUNTS);
require(OpAuthOutputCount(this.activeInputIndex) == next_count);

for (i, 0, next_count, MAX_ACCOUNTS) {
    int output_idx = OpAuthOutputIdx(this.activeInputIndex, i);
    validateOutputStateWithTemplate(
        output_idx,
        next_states[i],
        account_prefix,
        account_suffix,
        account_template
    );
}
```

The exact validation builtin still depends on the current route rules. A same
template route can use `validateOutputState`. A route that can reuse an input
template can use `validateOutputStateWithInputTemplate`. This reuse is valid
only when the matching input range cannot be empty. Otherwise, use a shared
output template witness.

### Observes

The compiler derives each actual length from `OpCovInputCount` or
`OpCovOutputCount`. It materializes observed input states in a bounded loop. It
also validates observed output state arrays in a bounded loop.

The runtime must change its observed context from one item per handle to one or
many items per handle. Fixed actor ranges can share one template witness.

Input-template reuse needs a clear rule. The first implementation should use a
shared output template witness for an observed output range. A later
optimization can reuse one matching observed input when the input range cannot
be empty.

### Spawns

A ranged spawn needs one dynamic array of global output indices. The runtime
already knows the complete named `spawn::<clause>` group, so it can supply this
array without a new user-facing group API.

The generated script must:

1. Check the index array length against the range bounds.
2. Check that the indices are in strictly increasing order.
3. Rebuild the canonical genesis covenant-ID preimage in a bounded loop.
4. Check the derived covenant ID against a selected group output.
5. Validate the actor state and template at every selected output.

This preserves the current complete-group proof. It also supports unrelated
transaction outputs between spawn group members.

## Compiler architecture

Add cardinality to the semantic model. Do not expand a range into its maximum
number of singleton declarations.

One common model can serve all four clauses:

```text
Cardinality
  One
  Range { minimum, maximum }

Effect item
  name
  actor expression
  cardinality
  declaration position
```

Each lowering stage must use an ordered location plan. A location plan gives a
singleton index or a range start and actual length. It must be separate from
actor route planning.

The route graph does not need multiplicity. Add one graph relation for a range:

- a consume range adds one consume relation;
- an emit range adds one emit relation;
- a fixed-actor spawn range adds one emit relation;
- an observe range adds no app route relation.

The commitment forest and cut transitions therefore stay unchanged.

The body lowerer needs explicit range bindings. Its current text replacement
is not sufficient for indexed expressions such as `accounts[i].value` or
`remote.inputs.assets[i].state`. Add token-aware indexed access lowering. A
full expression type checker is not required for the first version.

Add structured `for` statement support to the Argent body lowerer. Users need
loops to calculate totals and build successor state arrays. Keep bulk `become`
terminal and outside a user loop. This keeps terminal route analysis simple.

## Artifact and runtime changes

The Argent artifact must record cardinality for every consume, emit output,
observed item, and spawn output. It must record declaration position instead
of assuming that every item has one fixed transaction index.

This is an Argent artifact schema change. Increment the schema version. The Sil
ABI schema only needs a change if a required array type is not represented by
its current `DynamicArray` and `Struct` forms.

Add range subjects and purposes for hidden parameters only where they are
needed. A ranged spawn needs an output-index array. A homogeneous range must
share template witnesses. It must not receive one template witness for each
possible item.

The runtime must:

- partition an ordered group into singleton items and its one range;
- validate actor metadata for every ranged item;
- expose observed ranges as ordered vectors;
- resolve a ranged spawn to an ordered output-index array;
- encode hidden arrays through the existing Sil ABI array support;
- report minimum, maximum, and actual lengths in errors.

The transaction builder does not need a new range-group API while each section
has at most one range. Transaction order and the fixed items determine the
partition.

## Implementation plan

### 1. Prove the backend shapes

Add hand-written Sil tests for:

- a foreign input state array read in a bounded loop;
- an auth output state array validated in a bounded loop;
- an observed covenant input and output range;
- a genesis covenant-ID preimage built from an index array.

Use constructor constants in one backend test. This confirms that a bound is
part of the compiled template and not its state span.

### 2. Add cardinality and bound evaluation

- Parse `Actor[min..=max]` in entry clauses.
- Add one shared cardinality type to the AST and semantic model.
- Evaluate integer literals and `const int` references.
- Reject invalid bounds and more than one range in a section.
- Reject consume ranges in delegate entries.
- Keep singleton syntax and behavior unchanged.

### 3. Add ordered location plans

- Plan singleton and range locations for covenant inputs, auth outputs,
  observed groups, and spawn groups.
- Use the plan for count checks and generated index expressions.
- Add unit tests for a range before, between, and after singleton items.

### 4. Add body array support

- Register range handles and their source state types.
- Lower `.length`, indexed state access, and indexed `.value` access.
- Lower indexed observed access such as
  `remote.inputs.assets[i].state`.
- Lower state arrays for route targets that contain hidden route fields.
- Add structured `for` statements with compile-time maxima.
- Add bulk range routes and terminal coverage checks.

### 5. Implement consumes and emits

- Generate bounded input reads and output validations.
- Preserve delegate leader rules.
- Preserve route transition and template-witness selection.
- Add one pinned generated Sil fixture and runtime tests with several valid
  lengths and both invalid bounds.

This is the best first usable slice. It proves the common model before ICC and
genesis rules add more cases.

### 6. Implement observes

- Generate ranged observed input and output loops.
- Add vector entries to observed runtime contexts.
- Update hidden template resolution and observed output field witnesses.
- Add closed-ICC runtime tests first. Add shared open actor types later.

### 7. Implement spawns

- Add the ranged spawn index-array witness.
- Generate the dynamic canonical preimage.
- Update spawn artifact verification and runtime group resolution.
- Add direct generated-Sil security tests for missing, duplicate, reordered,
  and substituted indices.

### 8. Stabilize the interfaces

- Increment the Argent artifact schema version.
- Document the transaction order rules.
- Pin representative artifacts and generated Sil.
- Run `./check.sh --full` and the Argent Playground checks.
- Measure script size and charged operations at each supported maximum.

## Test matrix

Each clause needs tests for these lengths:

```text
minimum - 1
minimum
one middle value
maximum
maximum + 1
```

Use `minimum - 1` only when the minimum is greater than zero. Use a middle
value only when one exists.

Also test:

- zero length when the minimum is zero;
- a range between two singleton items;
- a wrong actor at the first, middle, and last range position;
- a wrong state at the first, middle, and last range position;
- a multi-actor app with foreign templates;
- a singleton app to prevent leakage of its direct-read optimization;
- route-family opening and packing inside a ranged emit;
- interleaved global output indices for a ranged spawn;
- artifact rejection for malformed cardinality or range witness metadata;
- unchanged generated Sil for entries that use only singletons.

## Effort and risk

The parser and route-graph work is small. The full feature is large because it
crosses the compiler and runtime boundary.

| Part | Size | Main reason |
| --- | --- | --- |
| Syntax, bounds, and semantic model | Small to medium | A shared model is direct, but bounds need compile-time evaluation. |
| Ordered location planning | Medium | Every section must use the same partition rules. |
| Body arrays and loops | Large | Current lowering is mostly scalar and uses text replacement. |
| Consumes and emits | Medium to large | These establish the common input and output model. |
| Observes | Large | Observed contexts and witnesses are scalar today. |
| Spawns | Large and security-sensitive | The canonical genesis proof must use a runtime index array. |
| Route planner | Small | Multiplicity does not change graph topology. |
| Artifact and runtime | Medium to large | Cardinality and vector contexts are new public data. |

A safe consumes-and-emits slice is approximately 8 to 12 focused commits. All
four clauses, runtime support, pinned Sil, and adversarial tests are
approximately 18 to 25 focused commits.

The main technical risk is script growth. Sil unrolls the loop maximum. A large
maximum repeats state reads, template checks, and output validation code. The
implementation must measure script size and operation cost before it selects
default or documented maximum values.

## Recommendation

Implement consumes and emits first. Use one homogeneous range per section and
top-level `const int` bounds. Keep the route planner unchanged apart from its
input adapter. Add observes after the body and location models are stable. Add
spawns last because their proof is the most security-sensitive.

Do not add configurable constructor constants in the first range commit.
Existing source constants already give Sil a compile-time loop bound. Add
template configuration only when an app must compile the same source with
different maxima.
