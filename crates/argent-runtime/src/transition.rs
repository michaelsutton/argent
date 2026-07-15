use std::collections::BTreeMap;

use argent_artifact::{EmitArtifact, EntryArtifact, EntryKindArtifact};
use kaspa_consensus_core::tx::{MutableTransaction, Transaction, TransactionOutpoint, UtxoEntry};

use crate::{
    ArgValue, ArtifactValue, BuilderError, BuilderResult, ObservedCovenantContext, TxBuilder, execute_transaction_with_covenants,
};

/// A transaction produced and verified by [`TransitionBuilder`].
#[derive(Debug)]
pub struct BuiltTransition {
    pub transaction: Transaction,
}

/// Fluent builder for one Argent entry transition.
///
/// The builder orders leader and consumed delegate inputs from the compiled
/// route plan, constructs successor outputs, fills hidden witnesses, and
/// executes the complete transaction.
pub struct TransitionBuilder<'builder, 'artifact> {
    builder: &'builder TxBuilder<'artifact>,
    actor_name: String,
    entry_name: String,
    args: TransitionArgs<'builder>,
    input: Option<TransitionInput>,
    consumed_inputs: Vec<ConsumedTransitionInput>,
    co_spends: Vec<TransitionCoSpend<'builder>>,
    observed: Vec<(String, ObservedCovenantContext)>,
    outputs: Vec<TransitionOutput>,
    expected_state: Option<BTreeMap<String, ArtifactValue>>,
    output_value: Option<TransitionOutputValue>,
}

type TransactionArgsBuilder<'a> = dyn FnOnce(&MutableTransaction<Transaction>, usize) -> Vec<ArgValue> + 'a;

enum TransitionArgs<'a> {
    Static(Vec<ArgValue>),
    WithTransaction(Box<TransactionArgsBuilder<'a>>),
}

#[derive(Clone)]
struct TransitionInput {
    outpoint: TransactionOutpoint,
    utxo: UtxoEntry,
    state: BTreeMap<String, ArtifactValue>,
}

struct ConsumedTransitionInput {
    name: String,
    delegate_entry: String,
    input: TransitionInput,
    args: Vec<ArgValue>,
}

struct TransitionOutput {
    name: String,
    state: BTreeMap<String, ArtifactValue>,
    value: u64,
}

enum TransitionCoSpend<'a> {
    InApp {
        app: String,
        actor: String,
        entry: String,
        input: TransitionInput,
        args: TransitionArgs<'a>,
        output_state: BTreeMap<String, ArtifactValue>,
        output_value: u64,
    },
    Observed {
        observe: String,
        handle: String,
        entry: String,
        outpoint: TransactionOutpoint,
        args: TransitionArgs<'a>,
        output_value: u64,
    },
}

struct PreparedInput<'a> {
    app: Option<String>,
    actor: String,
    entry: String,
    input: TransitionInput,
    args: TransitionArgs<'a>,
}

struct PreparedCoSpends<'a> {
    inputs: Vec<PreparedInput<'a>>,
    outputs: Vec<kaspa_consensus_core::tx::TransactionOutput>,
}

enum TransitionOutputValue {
    Preserve,
    Explicit(u64),
}

impl<'a> TxBuilder<'a> {
    /// Start composing one primary-app entry transition.
    pub fn transition(&self, actor_name: impl Into<String>, entry_name: impl Into<String>) -> TransitionBuilder<'_, 'a> {
        TransitionBuilder {
            builder: self,
            actor_name: actor_name.into(),
            entry_name: entry_name.into(),
            args: TransitionArgs::Static(Vec::new()),
            input: None,
            consumed_inputs: Vec::new(),
            co_spends: Vec::new(),
            observed: Vec::new(),
            outputs: Vec::new(),
            expected_state: None,
            output_value: None,
        }
    }
}

impl<'builder> TransitionBuilder<'builder, '_> {
    /// Supply entry arguments that do not depend on the transaction.
    pub fn args(mut self, args: Vec<ArgValue>) -> Self {
        self.args = TransitionArgs::Static(args);
        self
    }

    /// Build entry arguments from the unsigned, populated transaction.
    ///
    /// The callback also receives this entry's input index. It is intended for
    /// arguments such as transaction signatures.
    pub fn args_with(mut self, build: impl FnOnce(&MutableTransaction<Transaction>, usize) -> Vec<ArgValue> + 'builder) -> Self {
        self.args = TransitionArgs::WithTransaction(Box::new(build));
        self
    }

    /// Supply the live covenant input and its source-level state.
    pub fn input(mut self, outpoint: TransactionOutpoint, utxo: UtxoEntry, state: BTreeMap<String, ArtifactValue>) -> Self {
        self.input = Some(TransitionInput { outpoint, utxo, state });
        self
    }

    /// Supply an entry consume and the delegate entry that validates it.
    pub fn consume(
        mut self,
        name: impl Into<String>,
        delegate_entry: impl Into<String>,
        outpoint: TransactionOutpoint,
        utxo: UtxoEntry,
        state: BTreeMap<String, ArtifactValue>,
        args: Vec<ArgValue>,
    ) -> Self {
        self.consumed_inputs.push(ConsumedTransitionInput {
            name: name.into(),
            delegate_entry: delegate_entry.into(),
            input: TransitionInput { outpoint, utxo, state },
            args,
        });
        self
    }

    /// Supply one named successor output.
    pub fn output(mut self, name: impl Into<String>, state: BTreeMap<String, ArtifactValue>, value: u64) -> Self {
        self.outputs.push(TransitionOutput { name: name.into(), state, value });
        self
    }

    /// Bind an open observed covenant view to a concrete attached app.
    pub fn observe(mut self, name: impl Into<String>, context: ObservedCovenantContext) -> Self {
        self.observed.push((name.into(), context));
        self
    }

    /// Add an independently authorized leader transition from an attached app.
    #[allow(clippy::too_many_arguments)]
    pub fn co_spend_in_app(
        mut self,
        app: impl Into<String>,
        actor: impl Into<String>,
        entry: impl Into<String>,
        outpoint: TransactionOutpoint,
        utxo: UtxoEntry,
        state: BTreeMap<String, ArtifactValue>,
        args: Vec<ArgValue>,
        output_state: BTreeMap<String, ArtifactValue>,
        output_value: u64,
    ) -> Self {
        self.co_spends.push(TransitionCoSpend::InApp {
            app: app.into(),
            actor: actor.into(),
            entry: entry.into(),
            input: TransitionInput { outpoint, utxo, state },
            args: TransitionArgs::Static(args),
            output_state,
            output_value,
        });
        self
    }

    /// Add an attached-app co-spend whose arguments depend on the transaction.
    ///
    /// The callback receives the populated transaction and this co-spend's
    /// input index.
    #[allow(clippy::too_many_arguments)]
    pub fn co_spend_in_app_with(
        mut self,
        app: impl Into<String>,
        actor: impl Into<String>,
        entry: impl Into<String>,
        outpoint: TransactionOutpoint,
        utxo: UtxoEntry,
        state: BTreeMap<String, ArtifactValue>,
        build: impl FnOnce(&MutableTransaction<Transaction>, usize) -> Vec<ArgValue> + 'builder,
        output_state: BTreeMap<String, ArtifactValue>,
        output_value: u64,
    ) -> Self {
        self.co_spends.push(TransitionCoSpend::InApp {
            app: app.into(),
            actor: actor.into(),
            entry: entry.into(),
            input: TransitionInput { outpoint, utxo, state },
            args: TransitionArgs::WithTransaction(Box::new(build)),
            output_state,
            output_value,
        });
        self
    }

    /// Add the concrete transition bound by an open observed covenant context.
    ///
    /// `handle` selects the observed input. Its same-named output is used when
    /// present; otherwise the context must have exactly one output.
    pub fn co_spend_observed(
        mut self,
        observe: impl Into<String>,
        handle: impl Into<String>,
        entry: impl Into<String>,
        outpoint: TransactionOutpoint,
        args: Vec<ArgValue>,
        output_value: u64,
    ) -> Self {
        self.co_spends.push(TransitionCoSpend::Observed {
            observe: observe.into(),
            handle: handle.into(),
            entry: entry.into(),
            outpoint,
            args: TransitionArgs::Static(args),
            output_value,
        });
        self
    }

    /// Add an observed co-spend whose arguments depend on the transaction.
    ///
    /// The callback receives the populated transaction and this co-spend's
    /// input index. Output-handle resolution matches [`Self::co_spend_observed`].
    pub fn co_spend_observed_with(
        mut self,
        observe: impl Into<String>,
        handle: impl Into<String>,
        entry: impl Into<String>,
        outpoint: TransactionOutpoint,
        build: impl FnOnce(&MutableTransaction<Transaction>, usize) -> Vec<ArgValue> + 'builder,
        output_value: u64,
    ) -> Self {
        self.co_spends.push(TransitionCoSpend::Observed {
            observe: observe.into(),
            handle: handle.into(),
            entry: entry.into(),
            outpoint,
            args: TransitionArgs::WithTransaction(Box::new(build)),
            output_value,
        });
        self
    }

    /// Supply the expected source-level successor state.
    pub fn expect(mut self, state: BTreeMap<String, ArtifactValue>) -> Self {
        self.expected_state = Some(state);
        self
    }

    /// Preserve the input value in the successor output.
    pub fn preserve_value(mut self) -> Self {
        self.output_value = Some(TransitionOutputValue::Preserve);
        self
    }

    /// Set the successor output value explicitly.
    pub fn value(mut self, value: u64) -> Self {
        self.output_value = Some(TransitionOutputValue::Explicit(value));
        self
    }

    /// Build the transaction, fill hidden witnesses, and execute all inputs.
    pub fn build(mut self) -> BuilderResult<BuiltTransition> {
        let entry = self.builder.entry(&self.actor_name, &self.entry_name)?;
        if entry.kind != EntryKindArtifact::Leader {
            return Err(self.error("the fluent builder currently supports leader entries only"));
        }
        let mut observed = BTreeMap::new();
        for (name, context) in &self.observed {
            if observed.insert(name.clone(), context.clone()).is_some() {
                return Err(self.error(format!("observe `{name}` was supplied more than once")));
            }
        }

        let input = self.input.as_ref().ok_or_else(|| self.error("an input is required"))?;
        let expected_input_script = self.builder.script_public_key(&self.actor_name, input.state.clone())?;
        if input.utxo.script_public_key != expected_input_script {
            return Err(self.error("the input UTXO does not match the actor and source state"));
        }
        let covenant_id = input.utxo.covenant_id.ok_or_else(|| self.error("the input UTXO has no covenant id"))?;

        let leader_input_index = entry
            .route_plan
            .active_input
            .as_ref()
            .and_then(|input| input.cov_index)
            .ok_or_else(|| self.error("the leader input has no covenant index"))?;
        let leader_authorizing_input = u16::try_from(leader_input_index)
            .map_err(|_| self.error(format!("leader input index {leader_input_index} does not fit the covenant binding")))?;

        let mut consumed_by_name = BTreeMap::new();
        for consumed in &self.consumed_inputs {
            if consumed_by_name.insert(consumed.name.as_str(), consumed).is_some() {
                return Err(self.error(format!("consume `{}` was supplied more than once", consumed.name)));
            }
        }
        if consumed_by_name.len() != entry.route_plan.consumes.len() {
            return Err(self.error("the supplied consumes do not match the entry route"));
        }

        let input_count = entry
            .route_plan
            .consumes
            .iter()
            .filter_map(|consume| consume.cov_index)
            .chain([leader_input_index])
            .max()
            .map_or(0, |index| index + 1);
        let mut prepared_inputs = (0..input_count).map(|_| None).collect::<Vec<Option<PreparedInput<'builder>>>>();

        for route_input in &entry.route_plan.consumes {
            let consumed = consumed_by_name
                .get(route_input.name.as_str())
                .ok_or_else(|| self.error(format!("missing consume `{}`", route_input.name)))?;
            let input_index =
                route_input.cov_index.ok_or_else(|| self.error(format!("consume `{}` has no covenant index", route_input.name)))?;
            let delegate = self.builder.entry(&route_input.actor, &consumed.delegate_entry)?;
            if delegate.kind != EntryKindArtifact::Delegate {
                return Err(self.error(format!("`{}::{}` is not a delegate entry", route_input.actor, consumed.delegate_entry)));
            }
            if !delegate
                .route_plan
                .consumes
                .iter()
                .any(|leader| leader.actor == self.actor_name && leader.cov_index == Some(leader_input_index))
            {
                return Err(self.error(format!(
                    "delegate `{}::{}` does not consume leader `{}`",
                    route_input.actor, consumed.delegate_entry, self.actor_name
                )));
            }
            let expected_script = self.builder.script_public_key(&route_input.actor, consumed.input.state.clone())?;
            if consumed.input.utxo.script_public_key != expected_script {
                return Err(self.error(format!("consume `{}` UTXO does not match actor and source state", route_input.name)));
            }
            if consumed.input.utxo.covenant_id != Some(covenant_id) {
                return Err(self.error(format!("consume `{}` has a different covenant id", route_input.name)));
            }
            let prepared = PreparedInput {
                app: None,
                actor: route_input.actor.clone(),
                entry: consumed.delegate_entry.clone(),
                input: consumed.input.clone(),
                args: TransitionArgs::Static(consumed.args.clone()),
            };
            if prepared_inputs[input_index].replace(prepared).is_some() {
                return Err(self.error(format!("multiple inputs use covenant index {input_index}")));
            }
        }

        let mut output_by_name = BTreeMap::new();
        for output in &self.outputs {
            if output_by_name.insert(output.name.as_str(), output).is_some() {
                return Err(self.error(format!("output `{}` was supplied more than once", output.name)));
            }
        }
        let mut outputs = match &entry.emits {
            EmitArtifact::One { actors } if actors.len() == 1 => {
                if !output_by_name.is_empty() {
                    return Err(self.error("named outputs cannot be used with `emits one`"));
                }
                let expected_state =
                    self.expected_state.as_ref().ok_or_else(|| self.error("an expected successor state is required"))?;
                let output_value = match self.output_value {
                    Some(TransitionOutputValue::Preserve) => input.utxo.amount,
                    Some(TransitionOutputValue::Explicit(value)) => value,
                    None => return Err(self.error("an output value policy is required")),
                };
                vec![self.builder.covenant_output(
                    &actors[0],
                    expected_state.clone(),
                    output_value,
                    leader_authorizing_input,
                    covenant_id,
                )?]
            }
            EmitArtifact::Outputs { outputs } => {
                if self.expected_state.is_some() || self.output_value.is_some() {
                    return Err(self.error("use named outputs instead of `expect` and an output value policy"));
                }
                if output_by_name.len() != outputs.len() {
                    return Err(self.error("the supplied outputs do not match the entry route"));
                }
                let mut route_outputs = outputs.iter().collect::<Vec<_>>();
                route_outputs.sort_by_key(|output| output.auth_index);
                let mut built_outputs = Vec::with_capacity(route_outputs.len());
                for (expected_auth_index, route_output) in route_outputs.into_iter().enumerate() {
                    if route_output.auth_index != expected_auth_index || route_output.actors.len() != 1 {
                        return Err(self.error("the fluent builder currently requires static contiguous named outputs"));
                    }
                    let output = output_by_name
                        .get(route_output.name.as_str())
                        .ok_or_else(|| self.error(format!("missing output `{}`", route_output.name)))?;
                    built_outputs.push(self.builder.covenant_output(
                        &route_output.actors[0],
                        output.state.clone(),
                        output.value,
                        leader_authorizing_input,
                        covenant_id,
                    )?);
                }
                built_outputs
            }
            _ => return Err(self.error("the fluent builder requires statically selected successor actors")),
        };

        let co_spends = std::mem::take(&mut self.co_spends);
        let prepared_co_spends = self.prepare_co_spends(&observed, input_count, co_spends)?;
        outputs.extend(prepared_co_spends.outputs);

        for (input_index, prepared) in prepared_inputs.iter().enumerate() {
            if input_index != leader_input_index && prepared.is_none() {
                return Err(self.error(format!("no input uses covenant index {input_index}")));
            }
        }
        if prepared_inputs[leader_input_index].is_some() {
            return Err(self.error(format!("multiple inputs use covenant index {leader_input_index}")));
        }
        prepared_inputs[leader_input_index] = Some(PreparedInput {
            app: None,
            actor: self.actor_name.clone(),
            entry: self.entry_name.clone(),
            input: input.clone(),
            args: self.args,
        });
        let mut prepared_inputs =
            prepared_inputs.into_iter().map(|input| input.expect("all transition inputs are populated")).collect::<Vec<_>>();
        prepared_inputs.extend(prepared_co_spends.inputs);

        let transaction_inputs =
            prepared_inputs.iter().map(|prepared| TxBuilder::transaction_input(prepared.input.outpoint, Vec::new())).collect();
        let entries = prepared_inputs.iter().map(|prepared| prepared.input.utxo.clone()).collect();
        let transaction = TxBuilder::transaction(transaction_inputs, outputs);
        let populated_transaction = MutableTransaction::with_entries(transaction, entries);
        let resolved_inputs = prepared_inputs
            .into_iter()
            .enumerate()
            .map(|(input_index, prepared)| {
                let PreparedInput { app, actor, entry, input, args: args_builder } = prepared;
                let args = match args_builder {
                    TransitionArgs::Static(args) => args,
                    TransitionArgs::WithTransaction(build) => build(&populated_transaction, input_index),
                };
                (app, actor, entry, input, args)
            })
            .collect::<Vec<_>>();
        let mut transaction = populated_transaction.tx;
        let entries =
            populated_transaction.entries.into_iter().map(|entry| entry.expect("transition input UTXO is populated")).collect();
        for (input_index, (app, actor, entry, input, args)) in resolved_inputs.into_iter().enumerate() {
            transaction.inputs[input_index].signature_script = match app {
                Some(app) => self.builder.p2sh_signature_script_in_app(&app, &actor, &entry, input.state, args)?,
                None if input_index == leader_input_index && !observed.is_empty() => {
                    self.builder.p2sh_signature_script_with_observed_covenants(&actor, &entry, input.state, args, &observed)?
                }
                None => self.builder.p2sh_signature_script(&actor, &entry, input.state, args)?,
            };
        }
        execute_transaction_with_covenants(&mut transaction, entries)?;
        Ok(BuiltTransition { transaction })
    }

    fn prepare_co_spends(
        &self,
        observed: &BTreeMap<String, ObservedCovenantContext>,
        first_input_index: usize,
        co_spends: Vec<TransitionCoSpend<'builder>>,
    ) -> BuilderResult<PreparedCoSpends<'builder>> {
        let mut prepared = PreparedCoSpends { inputs: Vec::with_capacity(co_spends.len()), outputs: Vec::new() };
        for (offset, co_spend) in co_spends.into_iter().enumerate() {
            let input_index = first_input_index + offset;
            let authorizing_input = u16::try_from(input_index)
                .map_err(|_| self.error(format!("co-spend input index {input_index} does not fit the covenant binding")))?;
            match co_spend {
                TransitionCoSpend::InApp { app, actor, entry, input, args, output_state, output_value } => {
                    let co_spend_entry = self.builder.entry_in_app(&app, &actor, &entry)?;
                    self.validate_independent_co_spend(&app, &actor, &entry, co_spend_entry)?;
                    let output_actor = self.single_output_actor(&app, &actor, &entry, co_spend_entry)?;
                    let expected_script = self.builder.script_public_key_in_app(&app, &actor, input.state.clone())?;
                    if input.utxo.script_public_key != expected_script {
                        return Err(
                            self.error(format!("co-spend `{app}:{actor}::{entry}` UTXO does not match actor and source state"))
                        );
                    }
                    let covenant_id = input
                        .utxo
                        .covenant_id
                        .ok_or_else(|| self.error(format!("co-spend `{app}:{actor}::{entry}` UTXO has no covenant id")))?;
                    prepared.outputs.push(self.builder.covenant_output_in_app(
                        &app,
                        &output_actor,
                        output_state,
                        output_value,
                        authorizing_input,
                        covenant_id,
                    )?);
                    prepared.inputs.push(PreparedInput { app: Some(app), actor, entry, input, args });
                }
                TransitionCoSpend::Observed { observe, handle, entry, outpoint, args, output_value } => {
                    let context = observed
                        .get(&observe)
                        .ok_or_else(|| self.error(format!("co-spend references missing observe `{observe}`")))?;
                    let observed_input = context
                        .inputs
                        .get(&handle)
                        .ok_or_else(|| self.error(format!("observe `{observe}` has no input handle `{handle}`")))?;
                    let observed_output = match context.outputs.get(&handle) {
                        Some(output) => output,
                        None if context.outputs.len() == 1 => context.outputs.values().next().expect("one observed output exists"),
                        None if context.outputs.is_empty() => {
                            return Err(self.error(format!("observe `{observe}` has no outputs")));
                        }
                        None => {
                            return Err(
                                self.error(format!("observe `{observe}` has no output handle `{handle}` and has multiple outputs"))
                            );
                        }
                    };
                    let co_spend_entry = self.builder.entry_in_app(&context.app, &observed_input.actor, &entry)?;
                    self.validate_independent_co_spend(&context.app, &observed_input.actor, &entry, co_spend_entry)?;
                    let output_actor = self.single_output_actor(&context.app, &observed_input.actor, &entry, co_spend_entry)?;
                    if output_actor != observed_output.actor {
                        return Err(self.error(format!(
                            "observed co-spend `{observe}.{handle}` emits `{output_actor}`, not `{}`",
                            observed_output.actor
                        )));
                    }
                    let covenant_id = observed_input
                        .utxo
                        .covenant_id
                        .ok_or_else(|| self.error(format!("observed co-spend `{observe}.{handle}` input UTXO has no covenant id")))?;
                    prepared.outputs.push(self.builder.covenant_output_in_app(
                        &context.app,
                        &output_actor,
                        observed_output.state.clone(),
                        output_value,
                        authorizing_input,
                        covenant_id,
                    )?);
                    prepared.inputs.push(PreparedInput {
                        app: Some(context.app.clone()),
                        actor: observed_input.actor.clone(),
                        entry,
                        input: TransitionInput { outpoint, utxo: observed_input.utxo.clone(), state: observed_input.state.clone() },
                        args,
                    });
                }
            }
        }
        Ok(prepared)
    }

    fn validate_independent_co_spend(&self, app: &str, actor: &str, entry: &str, co_spend_entry: &EntryArtifact) -> BuilderResult<()> {
        if co_spend_entry.kind != EntryKindArtifact::Leader {
            return Err(self.error(format!("co-spend `{app}:{actor}::{entry}` is not a leader entry")));
        }
        if !co_spend_entry.consumes.is_empty() || !co_spend_entry.observes.is_empty() {
            return Err(self.error(format!("co-spend `{app}:{actor}::{entry}` is not an independent transition")));
        }
        Ok(())
    }

    fn single_output_actor(&self, app: &str, actor: &str, entry: &str, co_spend_entry: &EntryArtifact) -> BuilderResult<String> {
        match &co_spend_entry.emits {
            EmitArtifact::One { actors } if actors.len() == 1 => Ok(actors[0].clone()),
            EmitArtifact::Outputs { outputs } if outputs.len() == 1 && outputs[0].actors.len() == 1 => {
                Ok(outputs[0].actors[0].clone())
            }
            _ => Err(self.error(format!("co-spend `{app}:{actor}::{entry}` must have one static output"))),
        }
    }

    fn error(&self, message: impl Into<String>) -> BuilderError {
        BuilderError::InvalidTransition { actor: self.actor_name.clone(), entry: self.entry_name.clone(), message: message.into() }
    }
}
