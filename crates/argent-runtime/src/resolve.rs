use std::collections::BTreeMap;

use argent_artifact::{
    CovenantIdSourceArtifact, EntryArtifact, ObserveArtifact, ObservedActorArtifact, SilContractArtifact, SilEntryArtifact,
};
use kaspa_consensus_core::{
    Hash,
    constants::TX_VERSION_TOCCATA,
    subnets::SubnetworkId,
    tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutput},
};
use kaspa_txscript::{pay_to_script_hash_script, pay_to_script_hash_signature_script_with_flags};

use crate::{
    ActorPath, ArgentInput, ArgentOutput, Artifact, ArtifactValue, BuilderError, BuilderResult, ContextInput, ContextOutput,
    ContractRef, EntryArgs, HiddenArgContexts, InputSigScript, ObservedCovenantContext, ObservedInput, ObservedOutput, OrdinaryInput,
    OrdinaryOutput, Side, SpawnedActorContext, TxBuilder, TxContext, covenant_engine_flags, execute_transaction_with_covenants,
};

type ResolvedObservations = BTreeMap<String, ObservedCovenantContext>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResolvedEntryArgs {
    values: Vec<ArtifactValue>,
    template_selectors: BTreeMap<String, String>,
}

/// Artifact-bound working representation of a [`TxContext`].
///
/// Actor paths are resolved once into concrete app, contract, and entry
/// metadata while transaction ordering and transaction-wide fields are
/// preserved. Subsequent passes populate entry arguments, observations, and
/// hidden witnesses before the final signature scripts are assembled.
struct ResolveContext<'artifact, 'context, 'args> {
    inputs: Vec<ResolveInput<'artifact, 'context, 'args>>,
    outputs: Vec<ResolveOutput<'artifact, 'context>>,
    lock_time: u64,
    subnetwork_id: SubnetworkId,
    gas: u64,
    payload: &'context [u8],
}

enum ResolveInput<'artifact, 'context, 'args> {
    Argent(ResolveArgentInput<'artifact, 'context, 'args>),
    Ordinary(&'context OrdinaryInput<'args>),
}

struct ResolveArgentInput<'artifact, 'context, 'args> {
    source: &'context ArgentInput<'args>,
    app: String,
    artifact: &'artifact Artifact,
    contract: &'artifact SilContractArtifact,
    argent_entry: &'artifact EntryArtifact,
    sil_entry: &'artifact SilEntryArtifact,
    args: Option<ResolvedEntryArgs>,
    observations: Option<ResolvedObservations>,
    spawned_actors: Option<BTreeMap<(String, String), SpawnedActorContext>>,
    hidden_args: Option<Vec<ArtifactValue>>,
}

impl<'artifact> ResolveArgentInput<'artifact, '_, '_> {
    fn contract_ref(&self) -> ContractRef<'artifact> {
        ContractRef { artifact: self.artifact, contract: self.contract }
    }
}

enum ResolveOutput<'artifact, 'context> {
    Argent(ResolveArgentOutput<'artifact, 'context>),
    Ordinary(&'context OrdinaryOutput),
}

struct ResolveArgentOutput<'artifact, 'context> {
    source: &'context ArgentOutput,
    app: String,
    artifact: &'artifact Artifact,
    contract: &'artifact SilContractArtifact,
}

impl<'artifact> ResolveArgentOutput<'artifact, '_> {
    fn contract_ref(&self) -> ContractRef<'artifact> {
        ContractRef { artifact: self.artifact, contract: self.contract }
    }
}

impl<'artifact> TxBuilder<'artifact> {
    fn bind_actor(&self, actor: &ActorPath) -> BuilderResult<(String, ContractRef<'artifact>)> {
        let app = actor.app.as_deref().unwrap_or_else(|| self.bundle.primary_alias());
        let artifact = self.bundle.app(app)?;
        Ok((app.to_string(), self.contract_ref_in_artifact(artifact, &actor.actor)?))
    }

    /// Bind every actor path to one canonical app and its verified artifact objects.
    fn bind_context<'context, 'args>(
        &self,
        context: &'context TxContext<'args>,
    ) -> BuilderResult<ResolveContext<'artifact, 'context, 'args>> {
        let mut inputs = Vec::with_capacity(context.inputs.len());
        for input in &context.inputs {
            match input {
                ContextInput::Argent(input) => {
                    let (app, contract_ref) = self.bind_actor(&input.actor)?;
                    let argent_entry = self.entry_ref_in_artifact(contract_ref.artifact, &input.actor.actor, &input.entry.name)?;
                    let sil_entry = contract_ref.contract.entry(&input.entry.name).ok_or_else(|| BuilderError::UnknownEntry {
                        actor: input.actor.to_string(),
                        entry: input.entry.name.clone(),
                    })?;
                    inputs.push(ResolveInput::Argent(ResolveArgentInput {
                        source: input,
                        app,
                        artifact: contract_ref.artifact,
                        contract: contract_ref.contract,
                        argent_entry,
                        sil_entry,
                        args: None,
                        observations: None,
                        spawned_actors: None,
                        hidden_args: None,
                    }));
                }
                ContextInput::Ordinary(input) => inputs.push(ResolveInput::Ordinary(input)),
            }
        }

        let mut outputs = Vec::with_capacity(context.outputs.len());
        for output in &context.outputs {
            match output {
                ContextOutput::Argent(output) => {
                    let (app, contract_ref) = self.bind_actor(&output.actor)?;
                    outputs.push(ResolveOutput::Argent(ResolveArgentOutput {
                        source: output,
                        app,
                        artifact: contract_ref.artifact,
                        contract: contract_ref.contract,
                    }));
                }
                ContextOutput::Ordinary(output) => outputs.push(ResolveOutput::Ordinary(output)),
            }
        }

        Ok(ResolveContext {
            inputs,
            outputs,
            lock_time: context.lock_time,
            subnetwork_id: context.subnetwork_id,
            gas: context.gas,
            payload: &context.payload,
        })
    }

    /// Materialize the unsigned transaction described by `context`.
    ///
    /// All input sigscripts are empty. This is the single transaction view
    /// against which later resolution passes evaluate argument and sigscript
    /// callbacks.
    fn unsigned_transaction(&self, context: &ResolveContext<'artifact, '_, '_>) -> BuilderResult<MutableTransaction<Transaction>> {
        let mut inputs = Vec::with_capacity(context.inputs.len());
        let mut entries = Vec::with_capacity(context.inputs.len());

        for (input_index, input) in context.inputs.iter().enumerate() {
            match input {
                ResolveInput::Argent(input) => {
                    if input.source.utxo.covenant_id.is_none() {
                        return Err(BuilderError::MissingArgentInputCovenantId { input_index, actor: input.source.actor.to_string() });
                    }
                    let expected_script =
                        pay_to_script_hash_script(&self.redeem_script_for_contract(input.contract_ref(), input.source.state.clone())?);
                    if input.source.utxo.script_public_key != expected_script {
                        return Err(BuilderError::ArgentInputScriptMismatch { input_index, actor: input.source.actor.to_string() });
                    }
                    inputs.push(TransactionInput::new_with_compute_budget(
                        input.source.outpoint,
                        Vec::new(),
                        input.source.sequence,
                        0,
                    ));
                    entries.push(input.source.utxo.clone());
                }
                ResolveInput::Ordinary(input) => {
                    inputs.push(TransactionInput::new_with_compute_budget(input.outpoint, Vec::new(), input.sequence, 0));
                    entries.push(input.utxo.clone());
                }
            }
        }

        let mut outputs = Vec::with_capacity(context.outputs.len());
        for output in &context.outputs {
            match output {
                ResolveOutput::Argent(output) => {
                    let script_public_key = pay_to_script_hash_script(
                        &self.redeem_script_for_contract(output.contract_ref(), output.source.state.clone())?,
                    );
                    outputs.push(TransactionOutput::with_covenant(
                        output.source.value,
                        script_public_key,
                        Some(output.source.covenant),
                    ));
                }
                ResolveOutput::Ordinary(output) => {
                    outputs.push(TransactionOutput::with_covenant(output.value, output.script_public_key.clone(), output.covenant));
                }
            }
        }

        let transaction = Transaction::new(
            TX_VERSION_TOCCATA,
            inputs,
            outputs,
            context.lock_time,
            context.subnetwork_id,
            context.gas,
            context.payload.to_vec(),
        );
        Ok(MutableTransaction::with_entries(transaction, entries))
    }

    /// Resolve user-visible entry arguments for every Argent input.
    ///
    /// Resolved values are stored on their corresponding inputs. Hidden
    /// arguments are filled by later passes over the same context.
    fn resolve_context_args(
        &self,
        context: &mut ResolveContext<'artifact, '_, '_>,
        unsigned: &MutableTransaction<Transaction>,
    ) -> BuilderResult<()> {
        for (input_index, input) in context.inputs.iter_mut().enumerate() {
            let ResolveInput::Argent(input) = input else {
                continue;
            };

            let expected_arg_count =
                input.sil_entry.params.len().checked_sub(input.argent_entry.hidden_params.len()).ok_or_else(|| {
                    BuilderError::InvalidTransition {
                        actor: input.source.actor.to_string(),
                        entry: input.source.entry.name.clone(),
                        message: format!(
                            "artifact has {} hidden parameters but the Sil entry has {} total parameters",
                            input.argent_entry.hidden_params.len(),
                            input.sil_entry.params.len()
                        ),
                    }
                })?;
            let source_args = match &input.source.entry.args {
                EntryArgs::Static(args) => args.clone(),
                EntryArgs::WithTransaction(build) => {
                    build(unsigned, input_index).map_err(|source| BuilderError::EntryArgsCallback {
                        input_index,
                        actor: input.source.actor.to_string(),
                        entry: input.source.entry.name.clone(),
                        source,
                    })?
                }
            };
            if source_args.len() != expected_arg_count {
                return Err(silverscript_abi::CodecError::WrongArgumentCount {
                    entry: format!("{}::{}", input.source.actor, input.source.entry.name),
                    expected: expected_arg_count,
                    actual: source_args.len(),
                }
                .into());
            }
            let (values, template_selectors) = self.lower_arg_values(
                &input.source.actor.actor,
                &input.source.entry.name,
                input.sil_entry,
                input.argent_entry,
                source_args,
            )?;
            let values = self.runtime_entry_args(input.artifact, input.contract, input.sil_entry, input.argent_entry, values)?;
            input.args = Some(ResolvedEntryArgs { values, template_selectors });
        }

        Ok(())
    }

    /// Resolve every `observes` declaration from the concrete transaction
    /// inputs and outputs selected by its covenant id.
    fn resolve_context_observations(&self, context: &mut ResolveContext<'artifact, '_, '_>) -> BuilderResult<()> {
        for input_index in 0..context.inputs.len() {
            let ResolveInput::Argent(input) = &context.inputs[input_index] else {
                continue;
            };

            let args = input.args.as_ref().expect("argument resolution precedes observation resolution");
            let mut observations = BTreeMap::new();

            for observe in &input.argent_entry.observes {
                let covenant_id = observed_covenant_id(input.source, args, observe)?;
                let observation = resolve_observation(context, input.source, observe, covenant_id)?;
                observations.insert(observe.name.clone(), observation);
            }

            self.validate_observed_contexts(
                input.artifact,
                &input.source.actor.actor,
                &input.source.entry.name,
                input.argent_entry,
                &observations,
            )?;
            let ResolveInput::Argent(input) = &mut context.inputs[input_index] else { unreachable!() };
            input.observations = Some(observations);
        }

        Ok(())
    }

    /// Resolve each declared spawn from the genesis groups authorized by this input.
    fn resolve_context_spawns(&self, context: &mut ResolveContext<'artifact, '_, '_>) -> BuilderResult<()> {
        for input_index in 0..context.inputs.len() {
            let ResolveInput::Argent(input) = &context.inputs[input_index] else {
                continue;
            };

            let input_covenant_id = input.source.utxo.covenant_id.expect("Argent input covenant id checked before spawn resolution");
            let mut genesis_groups = Vec::new();
            let mut genesis_group_indices = BTreeMap::new();
            for (transaction_index, output) in context.outputs.iter().enumerate() {
                let binding = match output {
                    ResolveOutput::Argent(output) => Some(output.source.covenant),
                    ResolveOutput::Ordinary(output) => output.covenant,
                };
                let Some(binding) = binding else {
                    continue;
                };
                if usize::from(binding.authorizing_input) != input_index || binding.covenant_id == input_covenant_id {
                    continue;
                }
                let group_index = genesis_group_indices.get(&binding.covenant_id).copied().unwrap_or_else(|| {
                    genesis_groups.push((binding.covenant_id, Vec::new()));
                    let index = genesis_groups.len() - 1;
                    genesis_group_indices.insert(binding.covenant_id, index);
                    index
                });
                genesis_groups[group_index].1.push((transaction_index, output));
            }
            let mut spawned_actors = BTreeMap::new();
            // Spawn declarations pair with genesis groups by first output order;
            // handles within a spawn pair with that group's outputs in global order.
            for (spawn_index, spawn) in input.argent_entry.spawns.iter().enumerate() {
                let group = genesis_groups.get(spawn_index).map(|(_, outputs)| outputs);
                for output in &spawn.outputs {
                    let Some((transaction_index, resolved_output)) =
                        group.and_then(|outputs| outputs.get(output.group_index)).copied()
                    else {
                        return Err(BuilderError::MissingSpawnOutput {
                            spawn: spawn.name.clone(),
                            handle: output.name.clone(),
                            group_index: output.group_index,
                        });
                    };
                    let ResolveOutput::Argent(resolved_output) = resolved_output else {
                        return Err(BuilderError::MissingSpawnActorMetadata {
                            spawn: spawn.name.clone(),
                            handle: output.name.clone(),
                            index: transaction_index,
                        });
                    };
                    spawned_actors.insert(
                        (spawn.name.clone(), output.name.clone()),
                        SpawnedActorContext {
                            app: resolved_output.app.clone(),
                            actor: resolved_output.source.actor.actor.clone(),
                            output_index: transaction_index,
                        },
                    );
                }
            }

            let ResolveInput::Argent(input) = &mut context.inputs[input_index] else { unreachable!() };
            input.spawned_actors = Some(spawned_actors);
        }
        Ok(())
    }

    /// Resolve compiler-generated arguments from artifact-local routes and the
    /// concrete observed actors selected by the transaction.
    fn resolve_context_hidden_args(&self, context: &mut ResolveContext<'artifact, '_, '_>) -> BuilderResult<()> {
        for input in &mut context.inputs {
            let ResolveInput::Argent(input) = input else {
                continue;
            };

            let args = input.args.as_ref().expect("argument resolution precedes hidden-argument resolution");
            let observations = input.observations.as_ref().expect("observation resolution precedes hidden-argument resolution");
            let spawned_actors = input.spawned_actors.as_ref().expect("spawn resolution precedes hidden-argument resolution");
            input.hidden_args = Some(self.resolve_hidden_args_in_artifact(
                input.artifact,
                input.contract,
                input.argent_entry,
                &input.source.state,
                &args.template_selectors,
                HiddenArgContexts { observed: Some(observations), spawned: Some(spawned_actors) },
            )?);
        }

        Ok(())
    }

    /// Build, validate, and finalize the transaction described by `context`.
    ///
    /// Artifact-local routes and concrete observed actors supply all
    /// compiler-generated witness arguments.
    pub fn build(&self, context: &TxContext<'_>) -> BuilderResult<Transaction> {
        let mut context = self.bind_context(context)?;
        let unsigned = self.unsigned_transaction(&context)?;
        self.resolve_context_args(&mut context, &unsigned)?;
        self.resolve_context_observations(&mut context)?;
        self.resolve_context_spawns(&mut context)?;
        self.resolve_context_hidden_args(&mut context)?;
        let mut signature_scripts = Vec::with_capacity(context.inputs.len());

        for (input_index, input) in context.inputs.iter().enumerate() {
            let signature_script = match input {
                ResolveInput::Argent(input) => {
                    let mut args = input.args.as_ref().expect("argument resolution precedes sigscript construction").values.clone();
                    args.extend(
                        input
                            .hidden_args
                            .as_ref()
                            .expect("hidden-argument resolution precedes sigscript construction")
                            .iter()
                            .cloned(),
                    );
                    let abi_script = self.encode_runtime_entry_sig_script(
                        input.artifact,
                        input.contract,
                        input.sil_entry,
                        input.argent_entry,
                        &args,
                    )?;
                    pay_to_script_hash_signature_script_with_flags(
                        self.redeem_script_for_contract(input.contract_ref(), input.source.state.clone())?,
                        abi_script,
                        covenant_engine_flags(),
                    )?
                }
                ResolveInput::Ordinary(input) => match &input.signature_script {
                    InputSigScript::Static(script) => script.clone(),
                    InputSigScript::WithTransaction(build) => {
                        build(&unsigned, input_index).map_err(|source| BuilderError::InputSigScriptCallback { input_index, source })?
                    }
                },
            };
            signature_scripts.push(signature_script);
        }

        let mut transaction = unsigned.tx;
        for (input, signature_script) in transaction.inputs.iter_mut().zip(signature_scripts) {
            input.signature_script = signature_script;
        }
        let entries =
            unsigned.entries.into_iter().map(|entry| entry.expect("context transaction inputs always carry UTXO entries")).collect();
        execute_transaction_with_covenants(&mut transaction, entries)?;
        Ok(transaction)
    }
}

fn observed_covenant_id(input: &ArgentInput<'_>, args: &ResolvedEntryArgs, observe: &ObserveArtifact) -> BuilderResult<Hash> {
    let value = match &observe.covenant_id_source {
        CovenantIdSourceArtifact::StateField { field } => input.state.get(field).ok_or_else(|| BuilderError::InvalidTransition {
            actor: input.actor.to_string(),
            entry: input.entry.name.clone(),
            message: format!("observe `{}` references missing state field `{field}`", observe.name),
        })?,
        CovenantIdSourceArtifact::EntryArgument { index } => {
            args.values.get(*index).ok_or_else(|| BuilderError::InvalidTransition {
                actor: input.actor.to_string(),
                entry: input.entry.name.clone(),
                message: format!("observe `{}` references missing entry argument {index}", observe.name),
            })?
        }
    };
    let ArtifactValue::Bytes(bytes) = value else {
        return Err(BuilderError::InvalidObservedCovenantId { observe: observe.name.clone() });
    };
    let bytes: [u8; 32] =
        bytes.as_slice().try_into().map_err(|_| BuilderError::InvalidObservedCovenantId { observe: observe.name.clone() })?;
    Ok(Hash::from_bytes(bytes))
}

fn resolve_observation(
    context: &ResolveContext<'_, '_, '_>,
    input: &ArgentInput<'_>,
    observe: &ObserveArtifact,
    covenant_id: Hash,
) -> BuilderResult<ObservedCovenantContext> {
    let matching_inputs = matching_observed_inputs(context, covenant_id);
    require_observed_count(&observe.name, Side::In, observe.inputs.len(), matching_inputs.len())?;
    let matching_outputs = matching_observed_outputs(context, covenant_id);
    require_observed_count(&observe.name, Side::Out, observe.outputs.len(), matching_outputs.len())?;

    // Pair both sides positionally: covenant members are indexed by transaction
    // order, while emitted observe checks assign indexes in declaration order.
    let mut app = None;
    let mut inputs = BTreeMap::new();
    for (declaration, index) in observe.inputs.iter().zip(matching_inputs) {
        let (handle, observed) = resolve_observed_input(&observe.name, declaration, index, &context.inputs[index], &mut app)?;
        inputs.insert(handle, observed);
    }
    let mut outputs = BTreeMap::new();
    for (declaration, index) in observe.outputs.iter().zip(matching_outputs) {
        let (handle, observed) = resolve_observed_output(&observe.name, declaration, index, &context.outputs[index], &mut app)?;
        outputs.insert(handle, observed);
    }

    let app = app.ok_or_else(|| BuilderError::InvalidTransition {
        actor: input.actor.to_string(),
        entry: input.entry.name.clone(),
        message: format!("observe `{}` has no actor inputs or outputs from which to resolve an app", observe.name),
    })?;
    Ok(ObservedCovenantContext { app, inputs, outputs })
}

fn matching_observed_inputs(context: &ResolveContext<'_, '_, '_>, covenant_id: Hash) -> Vec<usize> {
    context
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, candidate)| match candidate {
            ResolveInput::Argent(candidate) => candidate.source.utxo.covenant_id == Some(covenant_id),
            ResolveInput::Ordinary(candidate) => candidate.utxo.covenant_id == Some(covenant_id),
        })
        .map(|(index, _)| index)
        .collect()
}

fn matching_observed_outputs(context: &ResolveContext<'_, '_, '_>, covenant_id: Hash) -> Vec<usize> {
    context
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, candidate)| match candidate {
            ResolveOutput::Argent(candidate) => candidate.source.covenant.covenant_id == covenant_id,
            ResolveOutput::Ordinary(candidate) => {
                candidate.covenant.as_ref().is_some_and(|binding| binding.covenant_id == covenant_id)
            }
        })
        .map(|(index, _)| index)
        .collect()
}

fn require_observed_count(observe: &str, side: Side, expected: usize, found: usize) -> BuilderResult<()> {
    if found != expected {
        return Err(BuilderError::ObservedCountMismatch { observe: observe.to_string(), side, expected, found });
    }
    Ok(())
}

fn resolve_observed_input(
    observe: &str,
    declaration: &ObservedActorArtifact,
    index: usize,
    candidate: &ResolveInput<'_, '_, '_>,
    app: &mut Option<String>,
) -> BuilderResult<(String, ObservedInput)> {
    let ResolveInput::Argent(candidate) = candidate else {
        return Err(BuilderError::MissingObservedActorMetadata {
            observe: observe.to_string(),
            side: Side::In,
            handle: declaration.name.clone(),
            index,
        });
    };
    merge_observed_app(observe, app, &candidate.app)?;
    Ok((
        declaration.name.clone(),
        ObservedInput {
            actor: candidate.source.actor.actor.clone(),
            state: candidate.source.state.clone(),
            utxo: candidate.source.utxo.clone(),
        },
    ))
}

fn resolve_observed_output(
    observe: &str,
    declaration: &ObservedActorArtifact,
    index: usize,
    candidate: &ResolveOutput<'_, '_>,
    app: &mut Option<String>,
) -> BuilderResult<(String, ObservedOutput)> {
    let ResolveOutput::Argent(candidate) = candidate else {
        return Err(BuilderError::MissingObservedActorMetadata {
            observe: observe.to_string(),
            side: Side::Out,
            handle: declaration.name.clone(),
            index,
        });
    };
    merge_observed_app(observe, app, &candidate.app)?;
    Ok((
        declaration.name.clone(),
        ObservedOutput { actor: candidate.source.actor.actor.clone(), state: candidate.source.state.clone() },
    ))
}

fn merge_observed_app(observe: &str, app: &mut Option<String>, candidate: &str) -> BuilderResult<()> {
    match app {
        Some(expected) if expected != candidate => Err(BuilderError::ObservedAppMismatch {
            observe: observe.to_string(),
            expected: expected.clone(),
            found: candidate.to_string(),
        }),
        Some(_) => Ok(()),
        None => {
            *app = Some(candidate.to_string());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use argent_artifact::{
        ARTIFACT_SCHEMA_VERSION, ActorAbiRefArtifact, ActorArtifact, ArgentArtifact, CompiledContractArtifact,
        CompiledTemplateArtifact, EmitArtifact, EntryAbiRefArtifact, EntryArtifact, EntryKindArtifact, EntryRoutePlanArtifact,
        GeneratorArtifact, InterfaceSetArtifact, RuntimeFieldArtifact, RuntimeStateArtifact, SIL_ABI_SCHEMA_VERSION, SilAbiArtifact,
        SilContractArtifact, SilEntryArtifact, StateSpanArtifact, TemplatePlanArtifact, TemplateSelectorArtifact, TypeArtifact,
    };
    use kaspa_consensus_core::{
        Hash,
        subnets::SubnetworkId,
        tx::{CovenantBinding, ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry},
    };

    use super::*;
    use crate::{ArgValue, ArtifactBundle, ArtifactValue, EntryCall, InputSigScript, actor};

    fn artifact(app: &str, actor: &str, entry: &str) -> Artifact {
        artifact_with_entry(app, actor, entry, Vec::new(), Vec::new())
    }

    fn artifact_with_entry(
        app: &str,
        actor: &str,
        entry: &str,
        params: Vec<argent_artifact::ParamArtifact>,
        template_selectors: Vec<TemplateSelectorArtifact>,
    ) -> Artifact {
        let state = format!("{actor}State");
        let mut artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "test".to_string(), version: "0".to_string() },
            app: app.to_string(),
            root: "app.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: vec![ActorArtifact {
                    name: actor.to_string(),
                    state: state.clone(),
                    abi: ActorAbiRefArtifact { actor: actor.to_string() },
                    entries: vec![EntryArtifact {
                        name: entry.to_string(),
                        kind: EntryKindArtifact::Leader,
                        abi: EntryAbiRefArtifact { actor: actor.to_string(), entry: entry.to_string() },
                        route_plan: EntryRoutePlanArtifact::default(),
                        hidden_params: Vec::new(),
                        template_selectors,
                        observes: Vec::new(),
                        spawns: Vec::new(),
                        witnesses: Vec::new(),
                        consumes: Vec::new(),
                        emits: EmitArtifact::None,
                        routes: Vec::new(),
                    }],
                }],
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                states: Vec::new(),
                contracts: vec![SilContractArtifact {
                    name: actor.to_string(),
                    source_path: format!("sil/{actor}.sil"),
                    runtime_state: RuntimeStateArtifact {
                        source: state,
                        fields: vec![RuntimeFieldArtifact { name: "count".to_string(), ty: TypeArtifact::Int }],
                    },
                    entries: vec![SilEntryArtifact { name: entry.to_string(), selector: None, params }],
                    compiled: CompiledContractArtifact {
                        script_hex: String::new(),
                        template: CompiledTemplateArtifact {
                            prefix_hex: String::new(),
                            suffix_hex: String::new(),
                            hash_hex: String::new(),
                        },
                        state_span: StateSpanArtifact { offset: 0, len: 0 },
                    },
                }],
            },
        };
        artifact.id = artifact.computed_id_hex().expect("test artifact id computes");
        artifact
    }

    fn state(count: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([("count".to_string(), ArtifactValue::Int(count))])
    }

    fn outpoint(byte: u8) -> TransactionOutpoint {
        TransactionOutpoint::new(TransactionId::from_bytes([byte; 32]), 0)
    }

    fn resolved_args<'a>(context: &'a ResolveContext<'_, '_, '_>, input_index: usize) -> Option<&'a ResolvedEntryArgs> {
        match &context.inputs[input_index] {
            ResolveInput::Argent(input) => input.args.as_ref(),
            ResolveInput::Ordinary(_) => None,
        }
    }

    #[test]
    fn unsigned_transaction_materializes_ordered_primary_qualified_and_ordinary_items() {
        let primary = artifact("primary", "Counter", "bump");
        let attached = artifact("asset", "Reserve", "move");
        let bundle =
            ArtifactBundle::new(&primary).expect("primary artifact builds").with_app("asset", &attached).expect("app attaches");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts bundle");
        let counter_id = Hash::from_bytes([0x11; 32]);
        let reserve_id = Hash::from_bytes([0x22; 32]);
        let counter_utxo = builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(counter_id)).expect("counter UTXO builds");
        let reserve_utxo =
            builder.covenant_utxo("asset::Reserve", state(7), 2_000, 0, false, Some(reserve_id)).expect("reserve UTXO builds");
        let ordinary_utxo = UtxoEntry::new(500, ScriptPublicKey::default(), 0, false, None);
        let args_called = Cell::new(false);
        let script_called = Cell::new(false);

        let context = TxContext::new()
            .argent_input(
                "Counter",
                state(2),
                EntryCall::new("bump").args_with(|_, _| {
                    args_called.set(true);
                    vec![ArgValue::Value(ArtifactValue::Int(1))]
                }),
                outpoint(1),
                counter_utxo.clone(),
                11,
            )
            .input(
                outpoint(2),
                ordinary_utxo.clone(),
                InputSigScript::with_transaction(|_, _| {
                    script_called.set(true);
                    vec![0xaa]
                }),
                12,
            )
            .argent_input("asset::Reserve", state(7), "move", outpoint(3), reserve_utxo.clone(), 13)
            .argent_output("Counter", state(3), CovenantBinding::new(0, counter_id), 900)
            .output(ScriptPublicKey::default(), Some(CovenantBinding::new(0, counter_id)), 100)
            .argent_output("asset::Reserve", state(8), CovenantBinding::new(2, reserve_id), 2_000)
            .lock_time(14)
            .lane(SubnetworkId::from_namespace([1, 2, 3, 4]), 15)
            .payload([0xaa, 0xbb]);

        let resolved = builder.bind_context(&context).expect("context binds");
        assert!(matches!(&resolved.inputs[0], ResolveInput::Argent(input) if input.app == "primary"));
        assert!(matches!(&resolved.inputs[2], ResolveInput::Argent(input) if input.app == "asset"));
        assert!(matches!(&resolved.outputs[0], ResolveOutput::Argent(output) if output.app == "primary"));
        assert!(matches!(&resolved.outputs[2], ResolveOutput::Argent(output) if output.app == "asset"));

        let unsigned = builder.unsigned_transaction(&resolved).expect("context materializes");

        assert_eq!(unsigned.tx.version, TX_VERSION_TOCCATA);
        assert_eq!(unsigned.tx.inputs.len(), 3);
        assert!(unsigned.tx.inputs.iter().all(|input| input.signature_script.is_empty()));
        assert_eq!(unsigned.tx.inputs[0].previous_outpoint, outpoint(1));
        assert_eq!(unsigned.tx.inputs[1].previous_outpoint, outpoint(2));
        assert_eq!(unsigned.tx.inputs[2].previous_outpoint, outpoint(3));
        assert_eq!(unsigned.tx.inputs.iter().map(|input| input.sequence).collect::<Vec<_>>(), vec![11, 12, 13]);
        assert_eq!(unsigned.tx.lock_time, 14);
        assert_eq!(unsigned.tx.subnetwork_id, SubnetworkId::from_namespace([1, 2, 3, 4]));
        assert_eq!(unsigned.tx.gas, 15);
        assert_eq!(unsigned.tx.payload, [0xaa, 0xbb]);
        assert_eq!(unsigned.entries, vec![Some(counter_utxo), Some(ordinary_utxo), Some(reserve_utxo)]);
        assert_eq!(
            unsigned.tx.outputs[0].script_public_key,
            builder
                .covenant_utxo("Counter", state(3), 900, 0, false, Some(counter_id))
                .expect("counter output script builds")
                .script_public_key
        );
        assert_eq!(
            unsigned.tx.outputs[2].script_public_key,
            builder
                .covenant_utxo("asset::Reserve", state(8), 2_000, 0, false, Some(reserve_id))
                .expect("reserve output script builds")
                .script_public_key
        );
        assert_eq!(unsigned.tx.outputs[0].covenant, Some(CovenantBinding::new(0, counter_id)));
        assert_eq!(unsigned.tx.outputs[1].covenant, Some(CovenantBinding::new(0, counter_id)));
        assert_eq!(unsigned.tx.outputs[2].covenant, Some(CovenantBinding::new(2, reserve_id)));
        assert!(!args_called.get());
        assert!(!script_called.get());
    }

    #[test]
    fn unsigned_transaction_rejects_missing_covenant_id_and_mismatched_state() {
        let artifact = artifact("primary", "Counter", "bump");
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x33; 32]);
        let matching_utxo =
            builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");
        let mut unbound_utxo = matching_utxo.clone();
        unbound_utxo.covenant_id = None;

        let missing_id = TxContext::new().argent_input("Counter", state(2), "bump", outpoint(1), unbound_utxo, 0);
        let missing_id = builder.bind_context(&missing_id).expect("context binds");
        assert!(matches!(
            builder.unsigned_transaction(&missing_id),
            Err(BuilderError::MissingArgentInputCovenantId { input_index: 0, actor }) if actor == "Counter"
        ));

        let wrong_state = TxContext::new().argent_input("Counter", state(3), "bump", outpoint(1), matching_utxo, 0);
        let wrong_state = builder.bind_context(&wrong_state).expect("context binds");
        assert!(matches!(
            builder.unsigned_transaction(&wrong_state),
            Err(BuilderError::ArgentInputScriptMismatch { input_index: 0, actor }) if actor == "Counter"
        ));
    }

    #[test]
    fn context_binding_rejects_unknown_paths_and_entries() {
        let artifact = artifact("primary", "Counter", "bump");
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x44; 32]);
        let utxo = builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");

        let unknown_app = TxContext::new().argent_input("missing::Counter", state(2), "bump", outpoint(1), utxo.clone(), 0);
        assert!(matches!(builder.bind_context(&unknown_app), Err(BuilderError::UnknownAppAlias(app)) if app == "missing"));

        let unknown_actor = TxContext::new().argent_input("Missing", state(2), "bump", outpoint(1), utxo.clone(), 0);
        assert!(matches!(builder.bind_context(&unknown_actor), Err(BuilderError::UnknownActor(actor)) if actor == "Missing"));

        let unknown_entry = TxContext::new().argent_input("Counter", state(2), "missing", outpoint(1), utxo, 0);
        assert!(matches!(
            builder.bind_context(&unknown_entry),
            Err(BuilderError::UnknownEntry { actor, entry }) if actor == "Counter" && entry == "missing"
        ));
    }

    #[test]
    fn context_args_resolve_static_and_transaction_dependent_values_by_input_index() {
        let artifact = artifact_with_entry(
            "primary",
            "Counter",
            "bump",
            vec![argent_artifact::ParamArtifact { name: "delta".to_string(), ty: TypeArtifact::Int }],
            Vec::new(),
        );
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x55; 32]);
        let counter_utxo =
            builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");
        let ordinary_utxo = UtxoEntry::new(100, ScriptPublicKey::default(), 0, false, None);
        let entry_callback_called = Cell::new(false);
        let ordinary_callback_called = Cell::new(false);
        let context = TxContext::new()
            .argent_input(
                "Counter",
                state(2),
                EntryCall::new("bump").args(vec![ArgValue::Value(ArtifactValue::Int(3))]),
                outpoint(1),
                counter_utxo.clone(),
                0,
            )
            .input(
                outpoint(2),
                ordinary_utxo,
                InputSigScript::with_transaction(|_, _| {
                    ordinary_callback_called.set(true);
                    vec![0xaa]
                }),
                0,
            )
            .argent_input(
                "Counter",
                state(2),
                EntryCall::new("bump").args_with(|tx, input_index| {
                    entry_callback_called.set(true);
                    assert_eq!(input_index, 2);
                    assert_eq!(tx.tx.inputs.len(), 3);
                    assert_eq!(tx.tx.outputs.len(), 1);
                    assert!(tx.entries.iter().all(Option::is_some));
                    assert!(tx.tx.inputs.iter().all(|input| input.signature_script.is_empty()));
                    vec![ArgValue::Value(ArtifactValue::Int(4))]
                }),
                outpoint(3),
                counter_utxo,
                0,
            )
            .argent_output("Counter", state(3), CovenantBinding::new(0, covenant_id), 900);
        let mut resolved = builder.bind_context(&context).expect("context binds");
        let unsigned = builder.unsigned_transaction(&resolved).expect("context materializes");

        builder.resolve_context_args(&mut resolved, &unsigned).expect("arguments resolve");

        assert_eq!(resolved_args(&resolved, 0).expect("input 0 is Argent").values, vec![ArtifactValue::Int(3)]);
        assert!(resolved_args(&resolved, 1).is_none());
        assert_eq!(resolved_args(&resolved, 2).expect("input 2 is Argent").values, vec![ArtifactValue::Int(4)]);
        assert!(entry_callback_called.get());
        assert!(!ordinary_callback_called.get());
    }

    #[test]
    fn context_args_lower_actor_values_and_retain_template_selection() {
        let artifact = artifact_with_entry(
            "primary",
            "Router",
            "choose",
            vec![argent_artifact::ParamArtifact { name: "target".to_string(), ty: TypeArtifact::Int }],
            vec![TemplateSelectorArtifact {
                name: "target".to_string(),
                actor_enum: "Target".to_string(),
                state: "TargetState".to_string(),
                variants: vec!["Alpha".to_string(), "Beta".to_string()],
                fixed_actor: None,
            }],
        );
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x66; 32]);
        let router_utxo = builder.covenant_utxo("Router", state(2), 1_000, 0, false, Some(covenant_id)).expect("router UTXO builds");
        let context = TxContext::new().argent_input(
            "Router",
            state(2),
            EntryCall::new("choose").args(vec![actor("Beta")]),
            outpoint(1),
            router_utxo,
            0,
        );
        let mut resolved = builder.bind_context(&context).expect("context binds");
        let unsigned = builder.unsigned_transaction(&resolved).expect("context materializes");

        builder.resolve_context_args(&mut resolved, &unsigned).expect("arguments resolve");
        let resolved = resolved_args(&resolved, 0).expect("input is Argent");

        assert_eq!(resolved.values, vec![ArtifactValue::Int(1)]);
        assert_eq!(resolved.template_selectors, BTreeMap::from([("target".to_string(), "Beta".to_string())]));
    }

    #[test]
    fn context_args_lower_source_state_values_to_runtime_state() {
        let artifact = artifact_with_entry(
            "primary",
            "Counter",
            "replace",
            vec![argent_artifact::ParamArtifact { name: "next".to_string(), ty: TypeArtifact::Struct { name: "State".to_string() } }],
            Vec::new(),
        );
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x76; 32]);
        let counter_utxo =
            builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");
        let context = TxContext::new().argent_input(
            "Counter",
            state(2),
            EntryCall::new("replace").args(vec![ArgValue::Value(ArtifactValue::Object(state(9)))]),
            outpoint(1),
            counter_utxo,
            0,
        );
        let mut resolved = builder.bind_context(&context).expect("context binds");
        let unsigned = builder.unsigned_transaction(&resolved).expect("context materializes");

        builder.resolve_context_args(&mut resolved, &unsigned).expect("arguments resolve");

        assert_eq!(resolved_args(&resolved, 0).expect("input is Argent").values, vec![ArtifactValue::Object(state(9))]);
    }

    #[test]
    fn context_args_reject_wrong_user_argument_count() {
        let artifact = artifact_with_entry(
            "primary",
            "Counter",
            "bump",
            vec![argent_artifact::ParamArtifact { name: "delta".to_string(), ty: TypeArtifact::Int }],
            Vec::new(),
        );
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x77; 32]);
        let counter_utxo =
            builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");
        let context = TxContext::new().argent_input("Counter", state(2), "bump", outpoint(1), counter_utxo, 0);
        let mut resolved = builder.bind_context(&context).expect("context binds");
        let unsigned = builder.unsigned_transaction(&resolved).expect("context materializes");

        assert!(matches!(
            builder.resolve_context_args(&mut resolved, &unsigned),
            Err(BuilderError::Codec(silverscript_abi::CodecError::WrongArgumentCount { expected: 1, actual: 0, .. }))
        ));
    }

    #[test]
    fn context_reports_fallible_callback_errors_with_input_identity() {
        let artifact = artifact("primary", "Counter", "bump");
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x78; 32]);
        let counter_utxo =
            builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");
        let context = TxContext::new().argent_input(
            "Counter",
            state(2),
            EntryCall::new("bump").try_args_with(|_, _| Err::<Vec<ArgValue>, _>(std::io::Error::other("signer unavailable"))),
            outpoint(1),
            counter_utxo,
            0,
        );

        let error = builder.build(&context).expect_err("argument callback fails");
        assert!(matches!(
            error,
            BuilderError::EntryArgsCallback { input_index: 0, actor, entry, source }
                if actor == "Counter" && entry == "bump" && source.to_string() == "signer unavailable"
        ));

        let ordinary_utxo = UtxoEntry::new(100, ScriptPublicKey::default(), 0, false, None);
        let context = TxContext::new().input(
            outpoint(2),
            ordinary_utxo,
            InputSigScript::try_with_transaction(|_, _| Err::<Vec<u8>, _>(std::io::Error::other("script signer unavailable"))),
            0,
        );

        let error = builder.build(&context).expect_err("sigscript callback fails");
        assert!(matches!(
            error,
            BuilderError::InputSigScriptCallback { input_index: 0, source }
                if source.to_string() == "script signer unavailable"
        ));
    }
}
