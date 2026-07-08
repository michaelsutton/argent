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
