# Open ICC Baseline

This example is the smallest real open-ICC shape:

- `agent.ag` is an independently deployed open-agent covenant app.
- `core.ag` is a controller/cell covenant app that observes the agent app.

The agent preserves its capability header and requires the controller covenant
to be co-spent. The core app reads the observed agent state and enforces one
physics step over it:

```text
energy -> energy - 1
```

The core cell stores the observed covenant id and an `actor<AgentState>` handle.
The `observes` clause constrains both the input and output to that stored
handle:

```rust
agent: self.agent_type;
```

and validates the output through the same handle:

```rust
agent <- self.agent_type(next_state);
```

This fixture is the baseline that later open-agent header views and
digest-backed custom data should grow from.

Runtime naming has four distinct layers:

```text
remote      observe name local to Cell::advance
open_agent  attached artifact app alias
agent       observed input/output handle inside the observes clause
Agent       concrete actor in the attached app
```

The runtime builder keeps those layers separate:

```rust
let bundle = ArtifactBundle::new(&core_artifact)?
    .with_app("open_agent", &agent_artifact)?;

let observed = BTreeMap::from([(
    "remote".to_string(),
    ObservedCovenantContext::from_app("open_agent")
        .input("agent", "Agent", agent_utxo, agent_state)
        .output("agent", "Agent", next_agent_state),
)]);

let agent_outputs = builder.observed_outputs(
    "Cell",
    "advance",
    "remote",
    observed.get("remote").unwrap(),
    values,
    1,
    agent_covenant_id,
)?;
```

The observe name is not an app identity. It is only the coordinate used by the
entry being invoked.
