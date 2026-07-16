# Transaction Builder Sigscript Resolution

This note describes the semantic transaction data retained by the transaction
builder and the deterministic process for resolving Argent sigscript arguments.
It is pseudocode, not a public API proposal.

## Typed transaction

```python
ActorRef:
    app                 bundled app alias
    actor               actor name within app

EntryCall:
    entry               entry name within actor
    user_args           static values or a callback over the populated tx

TypedInput:
    index               final transaction input index
    outpoint            previous transaction outpoint
    utxo:
        value
        script_public_key
        covenant_id     optional
    actor               optional ActorRef
    source_state        optional concrete source-level actor state
    call                optional EntryCall

TypedOutput:
    index               final transaction output index
    value
    covenant_binding:   optional
        covenant_id
        authorizing_input
    script_public_key
    actor               optional ActorRef
    source_state        optional concrete source-level actor state

TypedTransaction:
    inputs              ordered list of TypedInput
    outputs             ordered list of TypedOutput
```

An Argent input has `actor`, `source_state`, and `call`. An Argent output has
`actor` and `source_state`. Ordinary funding, fee, and change inputs or outputs
may omit Argent metadata.

Input and output order is final before sigscripts are resolved. Covenant
enumeration uses this order, matching `OpCovInputIdx` and `OpCovOutputIdx`.

## Artifact data

```python
Bundle:
    apps[app]                         Artifact
    actors[app, actor]                ActorArtifact
    canonical_templates[app, actor]   Template
    actor_type_handles[app, actor, state]
                                      Template

EntryArtifact:
    actor
    entry
    user_params                       ordered source parameters
    hidden_params                     ordered witness recipes
    observes                          ordered ObserveArtifact list

ObserveArtifact:
    name
    covenant_id_source:
        StateField(field)
        EntryArgument(index)
    inputs                            ordered observed input declarations
    outputs                           ordered observed output declarations

ObservedActorDeclaration:
    handle
    expected_actor:
        Fixed(app import, actor)
        ActorType(value expression, state)
        Binding(name, state)
        Bound(name)
```

The artifact also retains the original covenant expression for display. The
runtime uses `covenant_id_source`; it does not parse source text.

## Metadata validation

Typed metadata is accepted only when it reproduces the raw transaction.

```python
function validate_typed_transaction(tx, bundle):
    for input in tx.inputs where input.actor is present:
        require input.source_state is present
        require input.call is present
        require bundle contains input.actor

        redeem_script = build_redeem_script(
            bundle,
            input.actor,
            input.source_state
        )

        require p2sh(redeem_script) == input.utxo.script_public_key

    for output in tx.outputs where output.actor is present:
        require output.source_state is present
        require bundle contains output.actor

        redeem_script = build_redeem_script(
            bundle,
            output.actor,
            output.source_state
        )

        require p2sh(redeem_script) == output.script_public_key

    for input or output where actor is absent:
        require source_state is absent

    for input where actor is absent:
        require call is absent
```

`build_redeem_script` derives compiler-owned runtime fields and virtual-field
digests from the artifact and source state before encoding the state.

## Observation resolution

Each `observes` clause is resolved from the current input state, its user args,
the complete typed transaction, and the bundle.

```python
function resolve_observations(tx, current_input, entry, lowered_user_args, bundle):
    resolved = empty map
    bindings = empty map

    for observe in entry.observes in declaration order:
        covenant_id = match observe.covenant_id_source:
            StateField(field):
                current_input.source_state[field]
            EntryArgument(index):
                lowered_user_args[index]

        actual_inputs = [
            input
            for input in tx.inputs in transaction order
            where input.utxo.covenant_id == covenant_id
        ]

        actual_outputs = [
            output
            for output in tx.outputs in transaction order
            where output.covenant_binding exists
              and output.covenant_binding.covenant_id == covenant_id
        ]

        require count(actual_inputs) == count(observe.inputs)
        require count(actual_outputs) == count(observe.outputs)

        observed_app = none
        input_handles = empty map
        output_handles = empty map

        for (declaration, input) in zip(observe.inputs, actual_inputs):
            require input.actor is present
            require input.source_state is present

            resolve_observed_actor(
                declaration,
                input.actor,
                current_input.source_state,
                lowered_user_args,
                bindings,
                bundle
            )

            observed_app = require_same_app(observed_app, input.actor.app)
            input_handles[declaration.handle] = input

        for (declaration, output) in zip(observe.outputs, actual_outputs):
            require output.actor is present
            require output.source_state is present

            resolve_observed_actor(
                declaration,
                output.actor,
                current_input.source_state,
                lowered_user_args,
                bindings,
                bundle
            )

            observed_app = require_same_app(observed_app, output.actor.app)
            output_handles[declaration.handle] = output

        resolved[observe.name] = ResolvedObservation(
            covenant_id,
            observed_app,
            input_handles,
            output_handles
        )

    return resolved
```

All actors under one observed covenant id must resolve to one app artifact. The
app identifies the covenant program; the covenant id identifies its instance.

### Observed actor validation

```python
function resolve_observed_actor(
    declaration,
    concrete_actor,
    self_state,
    user_args,
    bindings,
    bundle
):
    require bundle contains concrete_actor

    match declaration.expected_actor:
        Fixed(import, actor):
            expected_actor = resolve_import(bundle, import, actor)
            require concrete_actor == expected_actor
            require imported and exported interfaces match

        ActorType(value_expression, state):
            expected_handle = evaluate(
                value_expression,
                self_state,
                user_args
            )
            actual_handle = bundle.actor_type_handle(concrete_actor, state)
            require actual_handle == expected_handle

        Binding(name, state):
            actual_handle = bundle.actor_type_handle(concrete_actor, state)
            if bindings[name] exists:
                require bindings[name].state == state
                require bindings[name].handle == actual_handle
            else:
                bindings[name] = ActorTypeBinding(state, actual_handle)

        Bound(name):
            require bindings[name] exists
            actual_handle = bundle.actor_type_handle(
                concrete_actor,
                bindings[name].state
            )
            require actual_handle == bindings[name].handle
```

An explicit concrete actor, if a future API accepts one, is only a resolution
hint. It must pass the same checks and cannot override a static actor or an
`actor_type<State>` commitment.

## Template selection

The template needed by a hidden witness depends on both the concrete actor and
the state view declared by the subject.

```python
function template_for_subject(subject, current_input, observations, selectors, bundle):
    match subject:
        Actor(actor):
            concrete_actor = ActorRef(current_input.actor.app, actor)
            return bundle.canonical_template(concrete_actor)

        TemplateSelector(selector):
            concrete_actor = selectors[selector]
            return bundle.canonical_template(concrete_actor)

        ObservedActor(observe, side, handle, open_state):
            member = observations[observe].member(side, handle)
            if open_state exists:
                return bundle.actor_type_template(member.actor, open_state)
            else:
                return bundle.canonical_template(member.actor)
```

The external `actor_type<BaseState>` template may differ from the actor's
canonical in-app template. The observe artifact supplies the required state
view, so the caller does not choose the cut.

## User argument resolution

Transaction-dependent user arguments, including signatures, are built only
after input/output order, outpoints, values, scripts, and covenant bindings are
fixed.

```python
function resolve_user_args(tx, input, entry, bundle):
    source_args = match input.call.user_args:
        Static(values):
            values
        WithTransaction(callback):
            callback(populated_transaction(tx), input.index)

    require count(source_args) == count(entry.user_params)

    lowered_args = empty list
    selectors = empty map

    for (parameter, value) in zip(entry.user_params, source_args):
        if value is Actor(actor_name):
            actor = resolve_actor_name(bundle, input.actor.app, actor_name)
            variant = require_actor_selector_variant(entry, parameter, actor)
            selectors[parameter.name] = actor
            lowered_args.append(variant.index)
        else if parameter is a source State value:
            lowered_args.append(
                lower_source_state_to_runtime_state(bundle, input.actor, value)
            )
        else:
            lowered_args.append(lower_abi_value(parameter.type, value))

    return ResolvedUserArgs(lowered_args, selectors)
```

## Hidden argument resolution

Hidden arguments are resolved in the exact order recorded by the entry
artifact.

```python
function resolve_hidden_arg(
    hidden,
    tx,
    current_input,
    entry,
    observations,
    selectors,
    bundle
):
    match hidden.purpose:
        TemplatePrefixBytes:
            template = template_for_subject(
                hidden.subject,
                current_input,
                observations,
                selectors,
                bundle
            )
            return template.prefix

        TemplateSuffixBytes:
            template = template_for_subject(...)
            return template.suffix

        TemplatePrefixLen:
            template = template_for_subject(...)
            return length(template.prefix)

        TemplateSuffixLen:
            template = template_for_subject(...)
            return length(template.suffix)

        TemplateHash:
            template = template_for_subject(...)
            return template.hash

        RouteTemplateLeaf:
            actor = require_actor_subject(hidden.subject)
            return bundle.canonical_template(current_input.actor.app, actor).hash

        RouteTemplateProof:
            actor = require_actor_subject(hidden.subject)
            return bundle.route_proof(hidden.route_proof_id, actor)

        RouteFamilyTable:
            family = require_route_family_subject(hidden.subject)
            return bundle.route_family_table(family)

        RouteFamilyProof:
            family = require_route_family_subject(hidden.subject)
            return bundle.route_family_proof(hidden.route_proof_id, family)

        StateExpansionPreimage:
            expansion = require_state_expansion_subject(hidden.subject)
            return encode_expansion_preimage(
                bundle,
                current_input.actor,
                current_input.source_state,
                expansion
            )

        ObservedOutputFieldValue:
            field = require_observed_output_field_subject(hidden.subject)
            output = observations[field.observe].outputs[field.handle]
            runtime_state = lower_source_state_to_runtime_state(
                bundle,
                output.actor,
                output.source_state
            )
            return runtime_state[field.field]
```

For a virtual observed output field,
`lower_source_state_to_runtime_state` encodes the concrete field preimage and
returns its digest. The digest is therefore determined by the concrete output
state.

## Sigscript resolution

```python
function resolve_sigscript(tx, input_index, resolved_user_args, bundle):
    input = tx.inputs[input_index]

    require input.actor is present
    require input.source_state is present
    require input.call is present

    actor_artifact = bundle.actor(input.actor)
    entry = actor_artifact.entry(input.call.entry)

    observations = resolve_observations(
        tx,
        input,
        entry,
        resolved_user_args.values,
        bundle
    )

    hidden_args = empty list
    for hidden in entry.hidden_params in artifact order:
        hidden_args.append(
            resolve_hidden_arg(
                hidden,
                tx,
                input,
                entry,
                observations,
                resolved_user_args.selectors,
                bundle
            )
        )

    entry_args = resolved_user_args.values + hidden_args

    abi_sigscript = encode_entry_sigscript(
        bundle,
        input.actor,
        entry,
        entry_args
    )

    redeem_script = build_redeem_script(
        bundle,
        input.actor,
        input.source_state
    )

    require p2sh(redeem_script) == input.utxo.script_public_key

    return p2sh_sigscript(abi_sigscript, redeem_script)
```

## Complete transaction pass

```python
function populate_argent_sigscripts(tx, bundle):
    validate_typed_transaction(tx, bundle)

    populated_tx = populated_transaction_with_empty_sigscripts(tx)
    user_args_by_input = empty map

    for input in populated_tx.inputs where input.actor is present:
        actor_artifact = bundle.actor(input.actor)
        entry = actor_artifact.entry(input.call.entry)
        user_args_by_input[input.index] = resolve_user_args(
            populated_tx,
            input,
            entry,
            bundle
        )

    for input in tx.inputs where input.actor is present:
        input.signature_script = resolve_sigscript(
            tx,
            input.index,
            user_args_by_input[input.index],
            bundle
        )

    execute every Argent input with unlimited script units
    commit each measured compute budget
    require total transaction compute mass <= consensus limit

    return tx
```

Given a complete typed transaction, the entry call's user arguments are the
only caller-provided sigscript values. Observation contexts, concrete template
witnesses, route witnesses, state-expansion preimages, and observed virtual
field digests are derived from transaction metadata and artifacts.
