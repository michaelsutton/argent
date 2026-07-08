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

This fixture intentionally uses only existing features: `observes`, `covid`,
artifact bundles, and observed input/output validation. It is the baseline that
later open-agent header views, generic actor bindings, and digest-backed custom
data should grow from.
