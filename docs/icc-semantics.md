# ICC Semantics

This document defines the intended source-level semantics for Argent
Inter-Covenant Communication (ICC).

ICC is a covenant-to-covenant delegation pattern. One covenant can make its own
transition depend on another covenant being spent in the same transaction. That
other covenant can enforce policy, inspect state, or authorize a special path
which the first covenant is not allowed to take alone.

The core idea is not "call another contract" in the usual imperative sense.
Both covenants are spent by the same transaction. Each covenant verifies its own
transition, and ICC gives them a shared language for saying "my transition is
valid only when that other transition is also present and shaped as expected."

Conceptually:

```text
same transaction

    [delegator input A]              [authority input C]
       requires C to be                 checks the transition
       present                          it is authorizing
              \                              /
               \                            /
                tx succeeds only if both pass
```

Argent uses two complementary language features for this:

- `id.co_spent()` proves that a covenant id participates in the transaction.
- `observes` lets one actor name the foreign covenant inputs and outputs it
  expects to inspect or constrain.

The important semantic point is that presence is not the same thing as
authorization scope. If covenant A only checks that covenant C is present, then
A knows C was validly spent, but A does not automatically know what C intended
to authorize. Sound ICC comes from coupling both sides intentionally: the
delegating side requires the authority to be present, and the authority side
tracks, binds to, or observes the delegated transition it is authorizing.

The authority side does not always need to inspect the entire delegated
transition on-chain. If the authority covenant requires an owner signature, that
signature can approve the full transaction. In that shape, the authority may use
signature validation as the coupling mechanism, or combine a signature with
targeted on-chain checks for the specific state fields it cares about.

This pattern also supports one-way dependencies. The delegator can depend only
on an authority covenant id, while the authority knows the delegator's state or
contract interface well enough to authorize it. That lets a general delegating
contract stay independent of each concrete authority implementation, as long as
the authority explicitly accepts responsibility for the delegated transition.

## Observes

An `observes` clause declares a foreign covenant view for one entrypoint.

```rust
observes asset by self.asset_covid {
    inputs {
        proxy: MinterProxy;
    }

    outputs {
        proxy: MinterProxy;
        recipient: KCC20;
    }
}
```

The name after `observes` is a local handle for this foreign covenant view. The
expression after `by` evaluates to the observed covenant id. The `inputs` and
`outputs` blocks declare the observed transition shape that this entrypoint
expects.

Within the entry body, the observer can read named observed input state:

```rust
MinterProxyState prev_proxy = asset.inputs.proxy.state;
```

and can require named observed outputs to become specific actors:

```rust
require asset.outputs become {
    proxy <- MinterProxy(next_proxy);
    recipient <- KCC20(next_recipient);
};
```

At the source level, this means:

- `asset.inputs.proxy` is the observed input named `proxy`
- `asset.outputs.proxy` is the observed output named `proxy`
- `MinterProxy(next_proxy)` means the observed output must become `MinterProxy`
  with `next_proxy` as its state
- all declared observed outputs must be covered by the observed `become` block

The source program should describe the relationship between the covenants, not
the implementation details needed to enforce that relationship.

## Co-spend presence

`.co_spent()` is the source-level way to require a covenant id to be present
in the transaction.

```rust
require(controller_id.co_spent());
```

This is useful on the delegated side. For example, an asset-side proxy can store
the controller covenant id and require that the controller is co-spent before
the proxy accepts a mint transition.

`.co_spent()` is only a presence check. It should be read as "the covenant id
appears as a valid input in this transaction." The rest of the ICC design must
make sure the present covenant is the right authority for the transition.

## Closed ICC

Closed ICC observes concrete actors from a known app artifact.

Example: a mint controller observes the concrete `MinterProxy` and `KCC20`
actors from the KCC20 asset app.

```rust
import "./kcc20_asset.ag";

actor Minter owns MinterState {
    entry mint(...)
    observes asset by self.kcc20_covid {
        inputs {
            proxy: MinterProxy;
        }

        outputs {
            proxy: MinterProxy;
            recipient: KCC20;
        }
    }
    ...
}
```

In closed ICC, actor names inside `observes` are concrete. `MinterProxy` means
the `MinterProxy` actor from the imported asset app. `KCC20` means the concrete
`KCC20` actor from that same app. The observer is compiled against those actors,
and the dependency should remain explicit in the source and artifact interface.

Closed ICC is the right model when the observer is intentionally composed with a
specific known app or protocol.

Closed ICC rules:

- observed actor names refer to concrete actors from known artifacts
- the observer commits to those concrete actor identities
- callers cannot choose a different implementation for those slots
- app dependencies should have stable identity and interface fingerprints
- source code reads and writes observed state through the declared names

The closed KCC mint shape is a typical example:

```text
asset app:
    MinterProxy delegates mint authority to controller id
    KCC20 represents the recipient asset state

controller app:
    Minter observes asset.MinterProxy and asset.KCC20
    Minter enforces issuance policy
    Minter tells the asset-side proxy and recipient what states to become
```

## Open ICC

Open ICC observes an actor chosen outside the observer artifact, constrained by
an interface-like state shape and source-level actor handles.

The useful mental model is dynamic dispatch over covenant templates. The
observer knows the state interface it is willing to work with, but it does not
hard-code every possible implementation.

```rust
state CellState {
    covid agent_covid;
    actor<AgentState> agent_type;
    int tick;
}
```

Here `agent_covid` identifies the observed agent covenant instance, while
`agent_type` is the concrete actor handle the cell has agreed to interact with.

An open ICC entry can then observe that agent:

```rust
entry advance()
observes remote by self.agent_covid {
    inputs {
        agent: self.agent_type;
    }

    outputs {
        agent: self.agent_type;
    }
}
emits {
    cell: Cell;
} {
    AgentState prev_state = remote.inputs.agent.state;

    AgentState next_state = {
        controller_id: prev_state.controller_id,
        caps_digest: prev_state.caps_digest,
        energy: prev_state.energy - 1,
    };

    require remote.outputs become {
        agent <- self.agent_type(next_state);
    };

    CellState next_cell = {
        agent_covid: agent_covid,
        agent_type: agent_type,
        tick: tick + 1,
    };

    become cell <- Cell(next_cell);
}
```

`self.agent_type` is not an actor instance; it is an actor handle value. The
`actor<AgentState>` type says that whatever implementation the handle denotes
must expose the `AgentState` state shape. Using the same handle in the observed
input and output means the observed transition must preserve that implementation
identity while changing only the state the cell authorizes.

When the handle is not already stored or passed by the observer, the entry can
bind a scoped runtime handle with `as`:

```rust
observes remote by self.agent_covid {
    inputs {
        agent: actor<AgentState> as observed_agent;
    }

    outputs {
        agent: observed_agent;
    }
}
```

`observed_agent` is scoped to this `observes` clause and names whatever actor
handle the observed transition carries. That form is useful when the observer
only needs same-implementation preservation, not equality to a handle already
committed in observer state.

Open ICC is the right model when the observer wants to support independently
published agent contracts that share a state ABI or interface discipline.

Open ICC rules:

- `actor<State>` is a first-class actor handle type
- the observer may store or receive an `actor<State>` handle
- observed actors must have a state shape compatible with that actor type
- the observed transition must bind to the same actor handle the observer
  committed to
- the compiler must not silently replace an open actor handle with a concrete
  closed artifact dependency

This is different from ordinary dynamic dispatch in one important way: the
observer does not execute the implementation body. The observed implementation
is a covenant input in the same transaction and validates itself. The observer
only constrains the parts of that transition it cares about.

## Input-Only Open Observation

Sometimes an observer only reads a foreign input and does not constrain a
matching output. In open ICC, this still needs an actor handle. The
compiler should not invent one.

Legal state-carried form:

```rust
state CellState {
    covid agent_covid;
    actor<AgentState> agent_type;
}
```

Legal entry-parameter form:

```rust
entry inspect(agent_type: actor<AgentState>)
observes remote by self.agent_covid {
    inputs {
        agent: self.agent_type;
    }
} {
    AgentState current_state = remote.inputs.agent.state;
    require(current_state.energy >= 0);
}
```

If an open observed input has no matching observed output and no source-level
`actor<State>` handle binding, the program should be rejected.

## Choosing Closed Or Open

Use closed ICC when:

- the observed actor is part of a known app
- the observer is supposed to bind to that exact app interface
- callers should not choose an alternate implementation
- artifact bundles can verify the concrete dependency

Use open ICC when:

- independent actors should be able to plug into the same observer
- the observer only depends on a shared state/interface shape
- the concrete actor handle is part of user or protocol state
- dynamic dispatch over actor implementations is intentional

The compiler should keep these modes distinct. A concrete imported actor should
not accidentally become an open dispatch slot, and an open `actor<State>` handle
should not accidentally become a closed dependency on one implementation.

## Language Surface

Current and expected source-level ICC features:

- `covid`: covenant id value type
- `id.co_spent()`: require the covenant id to be present in the transaction
- `observes <name> by <covid_expr>`: declare an observed covenant view
- `inputs { handle: Actor; }`: name observed inputs
- `outputs { handle: Actor; }`: name observed outputs
- `inputs { handle: self.actor_field; }`: constrain an observed input by a
  stored actor handle
- `outputs { handle: self.actor_field; }`: constrain an observed output by a
  stored actor handle
- `inputs { handle: actor<State> as observed; }`: bind an open observed actor handle
- `outputs { handle: observed; }`: require an output to use the same open actor handle
- `<observe>.inputs.<handle>.state`: read observed input state
- `require <observe>.outputs become { ... };`: constrain observed outputs
- `actor<State>`: first-class actor handle type

These features should let source code express ICC intent without exposing the
implementation machinery used to enforce it.
