# Open Lattice Binding Sketch

This is a design sketch for a cooperative / evolutionary local-physics game.
It is intentionally earlier than a production Argent app.

The core rule is:

```text
Cells apply physical transitions.
Agents authorize their own strategy state.
```

The source cell should be the leader input for a player action. The cell owns
the local physics: occupancy, movement, resource bounds, and the game-recognized
agent lock. The agent is co-spent as a foreign/open contract that authorizes its
own transition and carries any user strategy state behind a fixed header.

## Board Sizing

A viral world should not launch as a small fixed board unless the season is
explicitly scoped as a demo. There are two sane scalable shapes:

1. Chunked board

   A chunk UTXO owns a rectangular patch, for example 16x16 or 32x32 cells.
   Hot gameplay spends one or two chunks plus agent/strategy objects. Expansion
   mints neighboring chunks through a slow frontier path.

2. Cell board with chunk-birth authority

   Each live or empty cell is still a UTXO, but cells are only instantiated from
   a chunk authority UTXO. The chunk tracks which local slots have been born, so
   the game can create empty cells lazily without duplicate coordinates.

The second shape is closer to the pure local-cell story. The first shape is
probably cheaper and more practical for a public mainnet game.

Avoid a single global board UTXO. If there is a registry, keep it out of the
per-action hot path.

## Strategy Binding

There are three different meanings of "binding":

1. Bound to a contract

   The cell state names the occupying agent covenant id and the accepted
   template/capability hashes. Every action must co-spend that agent lineage.
   This is enforceable.

2. Bound to a linear strategy state

   Each action spends the current agent UTXO and creates exactly one successor
   agent UTXO. User strategy state lives inside the agent template or behind the
   `custom_data_digest`. This prevents the in-game agent from forking inside a
   recognized world transition.

3. Bound to one deterministic action

   The strategy code allows exactly one action for a visible neighborhood. This
   is not enforceable by generic physics for arbitrary user contracts. It must be
   enforced by one of:

   - a small on-chain strategy DSL whose evaluator is the contract;
   - a published strategy template accepted by the league;
   - a ZK proof against a committed program/state;
   - social/indexer classification: "this strategy authorized many actions".

The kernel can require agent authorization and enforce physics. It cannot prove
that an arbitrary foreign agent template had no other valid entrypoint unless
the strategy language or template itself gives that property.

## Foreign Agent Capability Header

There is another useful pattern between "fixed Agent body" and "fully arbitrary
foreign agent":

```text
foreign agent contract =
  arbitrary prefix
  standard physics header
  arbitrary extension state / code
```

The physics covenant can read the standard header from the foreign input's
revealed redeem script / sigscript bytes at agreed offsets. It can then use
those fields as hard capabilities:

- `world_id`
- `agent_id`
- `species_id`
- `strategy_covid` / `strategy_id`
- `capability_bits`
- `move_range`
- `max_attack`
- `max_share`
- `generation`
- `custom_data_digest`

Keep the state fixed-size. Do not put variable-size custom data directly in the
agent state: the pushdata framing makes variable state hard to read and rewrite
safely. Instead, put a digest in the header:

```text
custom_data_digest = hash(serialized_custom_data)
```

The custom payload lives one level deeper: in transaction witness data, off-chain
storage, a later intent/strategy object, or a future generated serializer. The
game kernel only sees and preserves or updates the digest.

For concrete agent authors, this wants a state-view expansion:

```text
state AgentCapsule {
    byte[32] world_id;
    byte[32] agent_id;
    byte[32] capabilities_digest;
    byte[32] custom_data_digest;
    int x;
    int y;
    int energy;
}

state ForagerMemory {
    int hunger;
    int mood;
    byte[32] target_agent_id;
}

state ForagerState extends AgentCapsule {
    expand custom_data_digest as ForagerMemory;
}
```

`expand custom_data_digest as ForagerMemory` means:

- the stored covenant state still contains only `custom_data_digest`;
- the transaction builder supplies a hidden opening witness for `ForagerMemory`;
- the compiler verifies `hash(serialize(ForagerMemory)) == custom_data_digest`;
- fields such as `hunger`, `mood`, and `target_agent_id` are available as a
  flattened source-level view;
- when those fields are mutated, the compiler serializes the new `ForagerMemory`
  value and writes the new digest back to `custom_data_digest`.

This keeps the generic game ABI fixed while letting each concrete agent use
well-typed private strategy memory.

For continuity, the action should force the agent covenant id to behave like a
singleton in that transaction:

```text
agent_covid = input_covenant_id(agent_input)
require cov_input_count(agent_covid) == 1
require cov_output_count(agent_covid) == 1
agent_output = cov_output_idx(agent_covid, 0)
```

Then the physics covenant verifies that the output for that singleton preserves
the immutable capability header, or changes it only through a specific allowed
mutation/evolution rule.

One caveat: standard P2SH-style outputs do not expose raw state bytes directly.
To check the output header, the physics script needs either:

- enough prefix/suffix/extension witness data to recompute the output
  script-public-key from the proposed next redeem script; or
- a standard descriptor/envelope that lets it rebuild the expected successor
  script from the preserved header and known opaque bytes.

This pattern is very good for bounding what a foreign agent can physically do.
It does not prove the foreign contract is deterministic or that it did not
authorize many possible legal actions. It binds capabilities, not strategy
uniqueness.

In Argent terms this wants generics / interface bounds:

```text
observes agent_lane by self.occupant_agent_covid {
    inputs {
        agent: actor<AgentCapsule> as T;
    }

    outputs {
        agent: T;
    }
}
```

The important part is not the concrete actor name. It is the same unknown actor
type `T` on both sides. The cell can read and rewrite the `AgentCapsule`, while
the generated verifier preserves the runtime template identity of `T`.

The cell should store the game lock, not only an agent name:

```text
occupant_agent_covid
occupant_template_hash
occupant_caps_hash
```

If the foreign agent performs a non-game transition that changes its template or
capabilities, the cell lock remains unchanged. The agent is still alive as a
covenant lineage, but it no longer matches the game-recognized envelope and
cannot act until a game-approved upgrade/resync transition updates the lock.

## Intent UTXO Variant

For public crankability, it may be useful to split strategy choice from world
execution, but this should be an optional layer rather than the normal hot path:

```text
plan:
  spend Agent(step/custom_digest)
  create Agent(step + 1/new_custom_digest)
  create Intent(action, neighborhood_hash, expiry)

execute:
  spend Intent
  spend Agent + local Cell objects
  create updated Agent + Cell objects
```

This makes the agent strategy state linear. An agent cannot publish two
different accepted intents from the same state because the first accepted plan
transaction spends the agent UTXO. Anyone can later execute the published intent
if the neighborhood still matches.

This still does not prove that the strategy code had only one possible intent.
It proves that the player committed to one intent before the world transition.
For many game modes, that may be the right practical meaning of "binding".

## Suggested V0

Season 0 should target the simplest useful interface:

- world objects: `Cell`, `Agent`;
- actions: `Move`, `Harvest`, `Share`, `Reproduce`, `Die`;
- source cell is the leader input;
- agent and neighboring cells are co-spent;
- user strategy state lives in the agent template or `custom_data_digest`;
- indexer derives map, leaderboard, and species pages;
- no inline ZK in the hot path.

This is enough to demonstrate custom behavior and bounded composability without
turning the first release into a whole game engine.
