# Open ICC Lattice

This example is a small cooperative-game fixture built out of two covenant apps:

- `core.ag` defines the shared `AgentState` capsule and cells that observe an
  agent by covenant id and apply local physics.
- `agent.ag` imports `core.ag` and defines independently deployed agent actors
  that satisfy or expand the shared state view.

The core idea is:

```text
Cells apply physical transitions.
Agents authorize their own strategy state.
```

The cell does not know which concrete agent template it is controlling. It stores
an `actor<AgentState>` handle and uses it in the `observes` clause:

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
actor whose stored state satisfies the shared `AgentState` capsule layout.

## State Shape

`AgentState` lives in the core app. It is the fixed capability header the cell
can reason about, and concrete agent apps import it:

```rust
state AgentState {
    byte[32] world_id;
    byte[32] agent_id;
    byte[32] species_id;

    covid controller_id;
    byte[32] capabilities_digest;
    byte[32] custom_data_digest;

    int x;
    int y;
    int energy;
    int generation;
}
```

`Forager` extends that header through a digest-backed source view:

```rust
state ForagerState expands AgentState {
    expand custom_data_digest as ForagerMemory;
}
```

Forager code uses memory fields directly:

```rust
ForagerState next_agent = {
    world_id: world_id,
    agent_id: agent_id,
    species_id: species_id,
    controller_id: controller_id,
    capabilities_digest: capabilities_digest,
    hunger: hunger + 1,
    mood: mood,
    target_agent_id: target_agent_id,
    x: next_x,
    y: next_y,
    energy: next_energy,
    generation: generation,
};
```

The generated Sil still stores only `custom_data_digest`. The runtime supplies a
packed hidden preimage for `ForagerMemory`; the contract verifies the digest and
the compiler rewrites mutations back into a new digest.

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

let observed = BTreeMap::from([(
    "remote".to_string(),
    ObservedCovenantContext::from_app("open_agent")
        .input("agent", "Forager", agent_utxo, forager_state)
        .output("agent", "Forager", next_forager_state),
)]);
```

The observe name is not an app identity. It is the local coordinate used by the
entry being invoked.
