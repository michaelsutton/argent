# Open ICC Lattice

This example is a small cooperative-game fixture built out of two covenant apps:

- `core.ag` defines the shared `AgentCapsule` capsule and cells that observe an
  agent by covenant id and apply local physics.
- `agent.ag` imports `core.ag` and defines independently deployed agent actors
  that satisfy the shared capsule view or bind its virtual slots.

The core idea is:

```text
Cells apply physical transitions.
Agents authorize their own strategy state.
```

The cell does not know which concrete agent template it is controlling. It stores
an `actor_type<AgentCapsule>` handle and uses it in the `observes` clause:

```rust
observes remote by self.occupant_agent_covid {
    inputs {
        agent: self.occupant_agent_type;
    }

    outputs {
        agent: self.occupant_agent_type;
    }
}
```

At runtime that handle may point to `Agent`, `Forager`, or another app-specific
actor whose stored state satisfies the shared `AgentCapsule` capsule layout.

## State Model

`AgentCapsule` lives in the core app. It is the fixed capability header the cell
can reason about, and concrete agent apps import it:

```rust
state AgentCapsule {
    byte[32] world_id;
    byte[32] agent_id;
    byte[32] species_id;

    covid controller_id;
    byte[32] capabilities_digest;
    virtual strategy;

    int x;
    int y;
    int energy;
    int generation;
}
```

`Forager` binds the virtual slot to structured strategy state:

```rust
state ForagerStrategy {
    int hunger;
    int mood;
}

state ForagerState expands AgentCapsule {
    strategy: ForagerStrategy;
}
```

Forager code accesses strategy fields through the slot namespace:

```rust
ForagerState next_agent = {
    world_id: world_id,
    agent_id: agent_id,
    species_id: species_id,
    controller_id: controller_id,
    capabilities_digest: capabilities_digest,
    strategy: ForagerStrategy {
        hunger: strategy.hunger + 1,
        mood: strategy.mood,
    },
    x: next_x,
    y: next_y,
    energy: next_energy,
    generation: generation,
};
```

The generated Sil stores only the `strategy` digest. The runtime supplies a
packed hidden preimage for `ForagerStrategy`; the contract verifies the digest
and the compiler rewrites slot mutations back into a new digest.

## Runtime Naming

The runtime builder keeps four names separate:

```text
remote      observe name local to Cell entries
open_agent  attached artifact app alias
agent       observed input/output handle inside the observes clause
Forager     concrete actor in the attached app
```

```rust
let bundle = ArtifactBundle::new(&core_artifact)?
    .with_app("open_agent", &agent_artifact)?;

let context = TxContext::new()
    .actor_input("Cell", cell_state, "advance", cell_outpoint, cell_utxo)
    .actor_input(
        "open_agent::Forager",
        forager_state,
        EntryCall::new("step").args(args![next_x, next_y, next_energy]),
        agent_outpoint,
        agent_utxo,
    )
    .actor_output("Cell", next_cell_state, cell_binding, cell_value)
    .actor_output("open_agent::Forager", next_forager_state, agent_binding, agent_value);

let tx = TxBuilder::from_bundle(&bundle)?.build(&context)?;
```

The observe name and handles remain compiler-level coordinates. The runtime
resolves them from the concrete actors and covenant ids in the transaction
context.
