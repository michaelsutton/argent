//! Runtime helpers for compiled Argent artifacts.
//!
//! This crate provides the consumer-side transaction-building surface for
//! Argent artifacts: hidden witness material, template receipts, route-family
//! data, and covenant transaction helpers.
//!
//! It intentionally has no dependency on the Argent compiler or
//! `silverscript-lang`. Treat it as a thin, copyable runtime layer for any
//! language or SDK that can speak Kaspa transactions and scripts. It is still
//! Argent-specific for now; lower-level Silverscript runtime abstractions can
//! split out later if the artifact model becomes generic enough.

use std::collections::BTreeMap;

pub use argent_artifact::Artifact;
pub use silverscript_abi::ArtifactValue;

use argent_artifact::{
    ActorArtifact, ArtifactVersionError, EntryArtifact, HiddenParamArtifact, HiddenParamPurposeArtifact, HiddenParamSubjectArtifact,
    ObserveArtifact, ObservedActorArtifact, ObservedActorSideArtifact, RouteTemplateLeafArtifact, RouteTemplateProofArtifact,
    RuntimeFieldRoleArtifact, RuntimeStatePlanArtifact, SilContractArtifact, SilEntryArtifact, TemplatePlanError,
    route_template_proof_receipt_id,
};
use kaspa_consensus_core::{
    Hash,
    hashing::sighash::SigHashReusedValuesUnsync,
    tx::{
        CovenantBinding, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
        VerifiableTransaction,
    },
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
    pay_to_script_hash_signature_script_with_flags, script_builder::ScriptBuilderError,
};
use kaspa_txscript_errors::TxScriptError;
use silverscript_abi::{CodecError, TypeArtifact, decode_hex, encode_entry_sig_script, encode_runtime_state_script};
use thiserror::Error;

pub type BuilderResult<T> = std::result::Result<T, BuilderError>;

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error(transparent)]
    ArtifactVersion(#[from] ArtifactVersionError),
    #[error(transparent)]
    TemplatePlan(#[from] TemplatePlanError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    ScriptBuilder(#[from] ScriptBuilderError),
    #[error(transparent)]
    TxScript(#[from] TxScriptError),
    #[error("unknown actor `{0}`")]
    UnknownActor(String),
    #[error("runtime state plan for contract `{contract}` is invalid: {message}")]
    RuntimeStatePlanMismatch { contract: String, message: String },
    #[error("hidden param `{param}` is missing route proof metadata")]
    MissingHiddenRouteProof { param: String },
    #[error("unknown route proof `{0}`")]
    UnknownRouteProof(String),
    #[error("unknown route table `{0}`")]
    UnknownRouteTable(String),
    #[error("route proof `{route_proof_id}` has no leaf `{leaf}`")]
    MissingRouteProofLeaf { route_proof_id: String, leaf: String },
    #[error("unknown route family `{0}`")]
    UnknownRouteFamily(String),
    #[error("route family table `{table_id}` contains nested route family `{family_id}`")]
    NestedRouteFamilyTableLeaf { table_id: String, family_id: String },
    #[error("hidden param `{param}` has the wrong subject kind; expected {expected}")]
    UnexpectedHiddenSubject { param: String, expected: &'static str },
    #[error("entry `{actor}::{entry}` does not define template selector `{selector}`")]
    UnknownTemplateSelector { actor: String, entry: String, selector: String },
    #[error("template selector `{selector}` requires a selected actor")]
    MissingTemplateSelectorChoice { selector: String },
    #[error("template selector `{selector}` cannot select actor `{actor}`")]
    InvalidTemplateSelectorChoice { selector: String, actor: String },
    #[error("entry `{actor}::{entry}` does not define observe `{observe}`")]
    UnknownObserve { actor: String, entry: String, observe: String },
    #[error("missing observed covenant context `{observe}`")]
    MissingObservedCovenant { observe: String },
    #[error("missing observed {side} `{observe}.{handle}`")]
    MissingObservedActor { observe: String, side: &'static str, handle: String },
    #[error("unknown observed {side} `{observe}.{handle}`")]
    UnknownObservedActor { observe: String, side: &'static str, handle: String },
    #[error("observed {side} `{observe}.{handle}` expected actor `{expected}`, got `{found}`")]
    ObservedActorMismatch { observe: String, side: &'static str, handle: String, expected: String, found: String },
    #[error("observed input `{observe}.{handle}` UTXO does not match actor `{actor}` and state")]
    ObservedUtxoScriptMismatch { observe: String, handle: String, actor: String },
    #[error("unknown entry `{actor}::{entry}`")]
    UnknownEntry { actor: String, entry: String },
    #[error("unknown terminal path {path_index} for `{actor}::{entry}`")]
    UnknownTerminalPath { actor: String, entry: String, path_index: usize },
    #[error("missing output `{0}`")]
    MissingOutput(String),
    #[error("unknown output `{0}`")]
    UnknownOutput(String),
    #[error("duplicate output `{0}`")]
    DuplicateOutput(String),
    #[error("unsupported route without a named output")]
    UnnamedRouteOutput,
}

pub struct TxBuilder<'a> {
    artifact: &'a Artifact,
    observed_artifacts: Vec<&'a Artifact>,
}

struct ContractRef<'a> {
    artifact: &'a Artifact,
    contract: &'a SilContractArtifact,
}

struct ActorRef<'a> {
    artifact: &'a Artifact,
    actor: &'a ActorArtifact,
}

struct EntryRef<'a> {
    artifact: &'a Artifact,
    entry: &'a EntryArtifact,
}

pub struct TerminalPathOutputRequest<'a> {
    pub actor_name: &'a str,
    pub entry_name: &'a str,
    pub path_index: usize,
    pub output_states: BTreeMap<String, BTreeMap<String, ArtifactValue>>,
    pub output_values: BTreeMap<String, u64>,
    pub authorizing_input: u16,
    pub covenant_id: Hash,
}

#[derive(Clone, Debug)]
pub struct ObservedInput {
    /// Actor name in an attached observed artifact.
    pub actor: String,
    /// Source-level state values for the observed input actor.
    pub state: BTreeMap<String, ArtifactValue>,
    /// Live UTXO being observed. The runtime checks its script against
    /// `actor(state)` before building hidden witnesses.
    pub utxo: UtxoEntry,
}

#[derive(Clone, Debug)]
pub struct ObservedOutput {
    /// Actor name in an attached observed artifact.
    pub actor: String,
    /// Source-level state values for the observed output actor.
    pub state: BTreeMap<String, ArtifactValue>,
}

#[derive(Clone, Debug, Default)]
pub struct ObservedCovenantContext {
    /// Observed inputs keyed by their `observes { inputs { ... } }` handle.
    pub inputs: BTreeMap<String, ObservedInput>,
    /// Observed outputs keyed by their `observes { outputs { ... } }` handle.
    pub outputs: BTreeMap<String, ObservedOutput>,
}

pub struct ObservedCovenantOutputRequest<'a> {
    pub actor_name: &'a str,
    pub entry_name: &'a str,
    pub observe: &'a str,
    pub context: &'a ObservedCovenantContext,
    pub output_values: BTreeMap<String, u64>,
    pub authorizing_input: u16,
    pub covenant_id: Hash,
}

impl<'a> TxBuilder<'a> {
    pub fn new(artifact: &'a Artifact) -> BuilderResult<Self> {
        artifact.check_schema_version()?;
        artifact.verify_template_plan()?;
        Ok(Self { artifact, observed_artifacts: Vec::new() })
    }

    /// Attach another covenant app artifact that this artifact observes.
    ///
    /// The primary artifact still owns the entry being spent. Attached artifacts
    /// supply foreign actor templates and state layouts for observed inputs and
    /// outputs, preserving the `app == covenant` boundary.
    pub fn with_observed_artifact(mut self, artifact: &'a Artifact) -> BuilderResult<Self> {
        artifact.check_schema_version()?;
        artifact.verify_template_plan()?;
        self.observed_artifacts.push(artifact);
        Ok(self)
    }

    pub fn redeem_script(&self, actor_name: &str, source_state: BTreeMap<String, ArtifactValue>) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref(actor_name)?;
        let state = self.runtime_state_values(contract_ref.artifact, contract_ref.contract, source_state)?;
        let state_script = encode_runtime_state_script(&contract_ref.contract.runtime_state, &state)?;

        let mut script = decode_hex(&contract_ref.contract.compiled.template.prefix_hex)?;
        script.extend_from_slice(&state_script);
        script.extend_from_slice(&decode_hex(&contract_ref.contract.compiled.template.suffix_hex)?);
        Ok(script)
    }

    pub fn script_public_key(
        &self,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<kaspa_consensus_core::tx::ScriptPublicKey> {
        Ok(pay_to_script_hash_script(&self.redeem_script(actor_name, source_state)?))
    }

    pub fn p2sh_signature_script(
        &self,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArtifactValue>,
    ) -> BuilderResult<Vec<u8>> {
        self.p2sh_signature_script_with_context(actor_name, entry_name, input_source_state, user_args, &BTreeMap::new(), None)
    }

    pub fn p2sh_signature_script_with_template_selector(
        &self,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArtifactValue>,
        selector: &str,
        selected_actor: &str,
    ) -> BuilderResult<Vec<u8>> {
        let mut template_selectors = BTreeMap::new();
        template_selectors.insert(selector.to_string(), selected_actor.to_string());
        self.p2sh_signature_script_with_context(actor_name, entry_name, input_source_state, user_args, &template_selectors, None)
    }

    /// Build a P2SH sigscript while deriving observed-covenant hidden witnesses.
    ///
    /// The caller provides semantic observed inputs/outputs. The runtime checks
    /// those handles against the entry artifact, validates observed input UTXOs
    /// against their declared actor/state, and fills template prefix/suffix
    /// witnesses from the primary and attached observed artifacts.
    pub fn p2sh_signature_script_with_observed_covenants(
        &self,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArtifactValue>,
        observed: &BTreeMap<String, ObservedCovenantContext>,
    ) -> BuilderResult<Vec<u8>> {
        self.p2sh_signature_script_with_context(
            actor_name,
            entry_name,
            input_source_state,
            user_args,
            &BTreeMap::new(),
            Some(observed),
        )
    }

    fn p2sh_signature_script_with_context(
        &self,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArtifactValue>,
        template_selectors: &BTreeMap<String, String>,
        observed: Option<&BTreeMap<String, ObservedCovenantContext>>,
    ) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref(actor_name)?;
        let contract = contract_ref.contract;
        let sil_entry = contract
            .entry(entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        let entry_ref = self.entry_ref(actor_name, entry_name)?;
        let argent_entry = entry_ref.entry;
        for selector in template_selectors.keys() {
            if argent_entry.template_selectors.iter().all(|candidate| &candidate.name != selector) {
                return Err(BuilderError::UnknownTemplateSelector {
                    actor: actor_name.to_string(),
                    entry: entry_name.to_string(),
                    selector: selector.clone(),
                });
            }
        }
        if let Some(observed) = observed {
            self.validate_observed_contexts(actor_name, entry_name, argent_entry, observed)?;
        }
        let mut args = self.runtime_entry_args(contract_ref.artifact, contract, sil_entry, user_args)?;
        for hidden in &argent_entry.hidden_params {
            args.push(match &hidden.purpose {
                HiddenParamPurposeArtifact::TemplatePrefixBytes => {
                    let actor = hidden_template_actor(hidden, argent_entry, template_selectors)?;
                    ArtifactValue::Bytes(decode_hex(&self.contract(&actor)?.compiled.template.prefix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplateSuffixBytes => {
                    let actor = hidden_template_actor(hidden, argent_entry, template_selectors)?;
                    ArtifactValue::Bytes(decode_hex(&self.contract(&actor)?.compiled.template.suffix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplatePrefixLen => {
                    let actor = hidden_actor_subject(hidden)?;
                    ArtifactValue::Int(decode_hex(&self.contract(actor)?.compiled.template.prefix_hex)?.len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateSuffixLen => {
                    let actor = hidden_actor_subject(hidden)?;
                    ArtifactValue::Int(decode_hex(&self.contract(actor)?.compiled.template.suffix_hex)?.len() as i64)
                }
                HiddenParamPurposeArtifact::RouteTemplateLeaf => {
                    let actor = hidden_actor_subject(hidden)?;
                    ArtifactValue::Bytes(decode_hex(&self.contract(actor)?.compiled.template.hash_hex)?)
                }
                HiddenParamPurposeArtifact::RouteTemplateProof => {
                    let actor = hidden_actor_subject(hidden)?;
                    let route_proof_id = hidden
                        .route_proof_id
                        .as_deref()
                        .ok_or_else(|| BuilderError::MissingHiddenRouteProof { param: hidden.name.clone() })?;
                    ArtifactValue::Bytes(self.route_template_proof_bytes_for_actor(entry_ref.artifact, route_proof_id, actor)?)
                }
                HiddenParamPurposeArtifact::RouteFamilyTable => {
                    let family_id = hidden_family_subject(hidden)?;
                    ArtifactValue::Bytes(self.route_family_table_bytes_in_artifact(entry_ref.artifact, family_id)?)
                }
                HiddenParamPurposeArtifact::RouteFamilyProof => {
                    let family_id = hidden_family_subject(hidden)?;
                    let route_proof_id = hidden
                        .route_proof_id
                        .as_deref()
                        .ok_or_else(|| BuilderError::MissingHiddenRouteProof { param: hidden.name.clone() })?;
                    ArtifactValue::Bytes(self.route_template_proof_bytes(
                        entry_ref.artifact,
                        route_proof_id,
                        &RouteTemplateLeafArtifact::RouteFamily {
                            family_id: family_id.to_string(),
                            proof_id: route_proof_id.to_string(),
                        },
                    )?)
                }
            });
        }

        let sigscript = encode_entry_sig_script(&contract_ref.artifact.sil_abi, contract, sil_entry, &args)?;
        Ok(pay_to_script_hash_signature_script_with_flags(
            self.redeem_script(actor_name, input_source_state)?,
            sigscript,
            covenant_engine_flags(),
        )?)
    }

    fn runtime_entry_args(
        &self,
        artifact: &'a Artifact,
        contract: &'a SilContractArtifact,
        entry: &SilEntryArtifact,
        user_args: Vec<ArtifactValue>,
    ) -> BuilderResult<Vec<ArtifactValue>> {
        let mut args = Vec::with_capacity(user_args.len());
        for (idx, value) in user_args.into_iter().enumerate() {
            if matches!(entry.params.get(idx).map(|param| &param.ty), Some(TypeArtifact::Struct { name }) if name == "State") {
                let ArtifactValue::Object(fields) = value else {
                    args.push(value);
                    continue;
                };
                args.push(ArtifactValue::Object(self.runtime_state_values(artifact, contract, fields)?));
            } else {
                args.push(value);
            }
        }
        Ok(args)
    }

    pub fn covenant_output(
        &self,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
        authorizing_input: u16,
        covenant_id: Hash,
    ) -> BuilderResult<TransactionOutput> {
        Ok(TransactionOutput {
            value,
            script_public_key: self.script_public_key(actor_name, source_state)?,
            covenant: Some(CovenantBinding { authorizing_input, covenant_id }),
        })
    }

    pub fn covenant_utxo(
        &self,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
        block_daa_score: u64,
        is_coinbase: bool,
        covenant_id: Option<Hash>,
    ) -> BuilderResult<UtxoEntry> {
        Ok(UtxoEntry::new(value, self.script_public_key(actor_name, source_state)?, block_daa_score, is_coinbase, covenant_id))
    }

    pub fn terminal_path_outputs(&self, request: TerminalPathOutputRequest<'_>) -> BuilderResult<Vec<TransactionOutput>> {
        let entry = self.entry(request.actor_name, request.entry_name)?;
        let path = entry.route_plan.terminal_paths.get(request.path_index).ok_or_else(|| BuilderError::UnknownTerminalPath {
            actor: request.actor_name.to_string(),
            entry: request.entry_name.to_string(),
            path_index: request.path_index,
        })?;
        for output in request.output_states.keys().chain(request.output_values.keys()) {
            if path.routes.iter().all(|route| route.output.as_ref() != Some(output)) {
                return Err(BuilderError::UnknownOutput(output.clone()));
            }
        }

        let mut outputs = Vec::with_capacity(path.routes.len());
        for route in &path.routes {
            let output = route.output.as_ref().ok_or(BuilderError::UnnamedRouteOutput)?;
            let state = request.output_states.get(output).ok_or_else(|| BuilderError::MissingOutput(output.clone()))?.clone();
            let value = *request.output_values.get(output).ok_or_else(|| BuilderError::MissingOutput(output.clone()))?;
            outputs.push((
                route.auth_index,
                output.clone(),
                self.covenant_output(&route.actor, state, value, request.authorizing_input, request.covenant_id)?,
            ));
        }
        outputs.sort_by_key(|(auth_index, _, _)| *auth_index);
        for window in outputs.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(BuilderError::DuplicateOutput(window[0].1.clone()));
            }
        }
        Ok(outputs.into_iter().map(|(_, _, output)| output).collect())
    }

    /// Build observed covenant outputs in the declaration order of an
    /// `observes { outputs { ... } }` block.
    pub fn observed_covenant_outputs(&self, request: ObservedCovenantOutputRequest<'_>) -> BuilderResult<Vec<TransactionOutput>> {
        let entry = self.entry(request.actor_name, request.entry_name)?;
        let observe = self.observe(request.actor_name, request.entry_name, entry, request.observe)?;
        self.validate_observed_covenant(request.observe, observe, request.context)?;

        for handle in request.context.outputs.keys().chain(request.output_values.keys()) {
            if observe.outputs.iter().all(|output| &output.name != handle) {
                return Err(BuilderError::UnknownObservedActor {
                    observe: request.observe.to_string(),
                    side: observed_side_label(ObservedActorSideArtifact::Output),
                    handle: handle.clone(),
                });
            }
        }

        let mut outputs = Vec::with_capacity(observe.outputs.len());
        for observed_output in &observe.outputs {
            let output = request.context.outputs.get(&observed_output.name).ok_or_else(|| BuilderError::MissingObservedActor {
                observe: request.observe.to_string(),
                side: observed_side_label(ObservedActorSideArtifact::Output),
                handle: observed_output.name.clone(),
            })?;
            let value = *request
                .output_values
                .get(&observed_output.name)
                .ok_or_else(|| BuilderError::MissingOutput(observed_output.name.clone()))?;
            outputs.push(self.covenant_output(
                &output.actor,
                output.state.clone(),
                value,
                request.authorizing_input,
                request.covenant_id,
            )?);
        }
        Ok(outputs)
    }

    pub fn transaction_input(previous_outpoint: TransactionOutpoint, signature_script: Vec<u8>) -> TransactionInput {
        TransactionInput::new_with_compute_budget(previous_outpoint, signature_script, 0, 0)
    }

    pub fn transaction(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
        Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![])
    }

    pub fn populated_transaction<'tx>(&self, tx: &'tx Transaction, entries: Vec<UtxoEntry>) -> PopulatedTransaction<'tx> {
        PopulatedTransaction::new(tx, entries)
    }

    pub fn contract(&self, name: &str) -> BuilderResult<&'a SilContractArtifact> {
        Ok(self.contract_ref(name)?.contract)
    }

    fn contract_ref(&self, name: &str) -> BuilderResult<ContractRef<'a>> {
        for artifact in self.artifacts() {
            if let Some(contract) = artifact.sil_abi.contract(name) {
                return Ok(ContractRef { artifact, contract });
            }
        }
        Err(BuilderError::UnknownActor(name.to_string()))
    }

    fn contract_in_artifact(&self, artifact: &'a Artifact, name: &str) -> BuilderResult<&'a SilContractArtifact> {
        artifact.sil_abi.contract(name).ok_or_else(|| BuilderError::UnknownActor(name.to_string()))
    }

    fn artifacts(&self) -> impl Iterator<Item = &'a Artifact> + '_ {
        std::iter::once(self.artifact).chain(self.observed_artifacts.iter().copied())
    }

    fn runtime_state_plan(&self, artifact: &'a Artifact, contract_name: &str) -> Option<&'a RuntimeStatePlanArtifact> {
        artifact.argent.template_plan.runtime_states.iter().find(|state| state.contract == contract_name)
    }

    fn argent_actor_ref(&self, name: &str) -> BuilderResult<ActorRef<'a>> {
        for artifact in self.artifacts() {
            if let Some(actor) = artifact.argent.actors.iter().find(|actor| actor.name == name) {
                return Ok(ActorRef { artifact, actor });
            }
        }
        Err(BuilderError::UnknownActor(name.to_string()))
    }

    pub fn entry(&self, actor_name: &str, entry_name: &str) -> BuilderResult<&'a EntryArtifact> {
        Ok(self.entry_ref(actor_name, entry_name)?.entry)
    }

    fn entry_ref(&self, actor_name: &str, entry_name: &str) -> BuilderResult<EntryRef<'a>> {
        let actor_ref = self.argent_actor_ref(actor_name)?;
        let entry = actor_ref
            .actor
            .entries
            .iter()
            .find(|entry| entry.name == entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        Ok(EntryRef { artifact: actor_ref.artifact, entry })
    }

    fn observe(
        &self,
        actor_name: &str,
        entry_name: &str,
        entry: &'a EntryArtifact,
        observe_name: &str,
    ) -> BuilderResult<&'a ObserveArtifact> {
        entry.observes.iter().find(|observe| observe.name == observe_name).ok_or_else(|| BuilderError::UnknownObserve {
            actor: actor_name.to_string(),
            entry: entry_name.to_string(),
            observe: observe_name.to_string(),
        })
    }

    fn validate_observed_contexts(
        &self,
        actor_name: &str,
        entry_name: &str,
        entry: &EntryArtifact,
        observed: &BTreeMap<String, ObservedCovenantContext>,
    ) -> BuilderResult<()> {
        for observe_name in observed.keys() {
            self.observe(actor_name, entry_name, entry, observe_name)?;
        }
        for observe in &entry.observes {
            let context =
                observed.get(&observe.name).ok_or_else(|| BuilderError::MissingObservedCovenant { observe: observe.name.clone() })?;
            self.validate_observed_covenant(&observe.name, observe, context)?;
        }
        Ok(())
    }

    fn validate_observed_covenant(
        &self,
        observe_name: &str,
        observe: &ObserveArtifact,
        context: &ObservedCovenantContext,
    ) -> BuilderResult<()> {
        self.validate_observed_inputs(observe_name, &observe.inputs, context)?;
        self.validate_observed_outputs(observe_name, &observe.outputs, context)
    }

    fn validate_observed_inputs(
        &self,
        observe_name: &str,
        expected: &[ObservedActorArtifact],
        context: &ObservedCovenantContext,
    ) -> BuilderResult<()> {
        for handle in context.inputs.keys() {
            if expected.iter().all(|input| &input.name != handle) {
                return Err(BuilderError::UnknownObservedActor {
                    observe: observe_name.to_string(),
                    side: observed_side_label(ObservedActorSideArtifact::Input),
                    handle: handle.clone(),
                });
            }
        }
        for input in expected {
            let observed = context.inputs.get(&input.name).ok_or_else(|| BuilderError::MissingObservedActor {
                observe: observe_name.to_string(),
                side: observed_side_label(ObservedActorSideArtifact::Input),
                handle: input.name.clone(),
            })?;
            self.validate_observed_actor(observe_name, ObservedActorSideArtifact::Input, input, &observed.actor)?;
            let expected_script_public_key = self.script_public_key(&observed.actor, observed.state.clone())?;
            if observed.utxo.script_public_key != expected_script_public_key {
                return Err(BuilderError::ObservedUtxoScriptMismatch {
                    observe: observe_name.to_string(),
                    handle: input.name.clone(),
                    actor: observed.actor.clone(),
                });
            }
        }
        Ok(())
    }

    fn validate_observed_outputs(
        &self,
        observe_name: &str,
        expected: &[ObservedActorArtifact],
        context: &ObservedCovenantContext,
    ) -> BuilderResult<()> {
        for handle in context.outputs.keys() {
            if expected.iter().all(|output| &output.name != handle) {
                return Err(BuilderError::UnknownObservedActor {
                    observe: observe_name.to_string(),
                    side: observed_side_label(ObservedActorSideArtifact::Output),
                    handle: handle.clone(),
                });
            }
        }
        for output in expected {
            let observed = context.outputs.get(&output.name).ok_or_else(|| BuilderError::MissingObservedActor {
                observe: observe_name.to_string(),
                side: observed_side_label(ObservedActorSideArtifact::Output),
                handle: output.name.clone(),
            })?;
            self.validate_observed_actor(observe_name, ObservedActorSideArtifact::Output, output, &observed.actor)?;
            self.redeem_script(&observed.actor, observed.state.clone())?;
        }
        Ok(())
    }

    fn validate_observed_actor(
        &self,
        observe_name: &str,
        side: ObservedActorSideArtifact,
        expected: &ObservedActorArtifact,
        found_actor: &str,
    ) -> BuilderResult<()> {
        if expected.actor != found_actor {
            return Err(BuilderError::ObservedActorMismatch {
                observe: observe_name.to_string(),
                side: observed_side_label(side),
                handle: expected.name.clone(),
                expected: expected.actor.clone(),
                found: found_actor.to_string(),
            });
        }
        Ok(())
    }

    fn runtime_state_values(
        &self,
        artifact: &'a Artifact,
        contract: &SilContractArtifact,
        mut source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<BTreeMap<String, ArtifactValue>> {
        let mut role_by_field = BTreeMap::new();
        if let Some(runtime_plan) = self.runtime_state_plan(artifact, &contract.name) {
            if runtime_plan.source != contract.runtime_state.source {
                return Err(BuilderError::RuntimeStatePlanMismatch {
                    contract: contract.name.clone(),
                    message: format!(
                        "source `{}` does not match Sil ABI source `{}`",
                        runtime_plan.source, contract.runtime_state.source
                    ),
                });
            }
            let sil_fields_by_name =
                contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<std::collections::BTreeSet<_>>();
            for field_role in &runtime_plan.field_roles {
                if !sil_fields_by_name.contains(field_role.name.as_str()) {
                    return Err(BuilderError::RuntimeStatePlanMismatch {
                        contract: contract.name.clone(),
                        message: format!("field role `{}` does not match any Sil ABI runtime field", field_role.name),
                    });
                }
                if role_by_field.insert(field_role.name.as_str(), &field_role.role).is_some() {
                    return Err(BuilderError::RuntimeStatePlanMismatch {
                        contract: contract.name.clone(),
                        message: format!("field role `{}` is duplicated", field_role.name),
                    });
                }
            }
        }

        let mut values = BTreeMap::new();
        for field in &contract.runtime_state.fields {
            match role_by_field.get(field.name.as_str()) {
                None => {
                    let value = source_state.remove(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
                    values.insert(field.name.clone(), value);
                }
                Some(RuntimeFieldRoleArtifact::Template { contract }) => {
                    values.insert(
                        field.name.clone(),
                        ArtifactValue::Bytes(decode_hex(&self.contract(contract)?.compiled.template.hash_hex)?),
                    );
                }
                Some(RuntimeFieldRoleArtifact::ObservedTemplate { contract, .. }) => {
                    let value = if let Some(value) = source_state.remove(&field.name) {
                        value
                    } else {
                        ArtifactValue::Bytes(decode_hex(&self.contract(contract)?.compiled.template.hash_hex)?)
                    };
                    values.insert(field.name.clone(), value);
                }
                Some(RuntimeFieldRoleArtifact::TemplateTable { contracts }) => {
                    let mut table = Vec::with_capacity(contracts.len() * 32);
                    for contract in contracts {
                        table.extend_from_slice(&decode_hex(
                            &self.contract_in_artifact(artifact, contract)?.compiled.template.hash_hex,
                        )?);
                    }
                    values.insert(field.name.clone(), ArtifactValue::Bytes(table));
                }
                Some(RuntimeFieldRoleArtifact::TemplateDigest { id }) => {
                    let table = self.route_family_table_bytes_in_artifact(artifact, id)?;
                    values.insert(field.name.clone(), ArtifactValue::Bytes(blake2b32(&table)));
                }
                Some(RuntimeFieldRoleArtifact::TemplateRoot { .. }) => {
                    let proof_id = route_template_proof_receipt_id(&contract.runtime_state.source, &field.name);
                    let proof = self.route_template_proof_in_artifact(artifact, &proof_id)?;
                    values.insert(field.name.clone(), ArtifactValue::Bytes(decode_hex(&proof.root_hex)?));
                }
            }
        }
        if let Some(extra) = source_state.into_keys().next() {
            return Err(CodecError::UnknownField(extra).into());
        }
        Ok(values)
    }

    fn route_template_proof_in_artifact(
        &self,
        artifact: &'a Artifact,
        route_proof_id: &str,
    ) -> BuilderResult<&'a RouteTemplateProofArtifact> {
        artifact
            .argent
            .template_plan
            .route_proofs
            .iter()
            .find(|proof| proof.id == route_proof_id)
            .ok_or_else(|| BuilderError::UnknownRouteProof(route_proof_id.to_string()))
    }

    fn route_template_proof_bytes(
        &self,
        artifact: &'a Artifact,
        route_proof_id: &str,
        wanted_leaf: &RouteTemplateLeafArtifact,
    ) -> BuilderResult<Vec<u8>> {
        let proof_receipt = self.route_template_proof_in_artifact(artifact, route_proof_id)?;
        let leaf = proof_receipt.leaves.iter().find(|leaf| &leaf.leaf == wanted_leaf).ok_or_else(|| {
            BuilderError::MissingRouteProofLeaf { route_proof_id: route_proof_id.to_string(), leaf: route_leaf_label(wanted_leaf) }
        })?;
        let mut proof = Vec::with_capacity(leaf.proof.len() * 32);
        for step in &leaf.proof {
            proof.extend_from_slice(&decode_hex(&step.hash_hex)?);
        }
        Ok(proof)
    }

    fn route_template_proof_bytes_for_actor(
        &self,
        artifact: &'a Artifact,
        route_proof_id: &str,
        actor: &str,
    ) -> BuilderResult<Vec<u8>> {
        let proof_receipt = self.route_template_proof_in_artifact(artifact, route_proof_id)?;
        let leaf = proof_receipt
            .leaves
            .iter()
            .find(|leaf| matches!(&leaf.leaf, RouteTemplateLeafArtifact::Template { actor: leaf_actor, .. } if leaf_actor == actor))
            .ok_or_else(|| BuilderError::MissingRouteProofLeaf {
                route_proof_id: route_proof_id.to_string(),
                leaf: actor.to_string(),
            })?;
        let mut proof = Vec::with_capacity(leaf.proof.len() * 32);
        for step in &leaf.proof {
            proof.extend_from_slice(&decode_hex(&step.hash_hex)?);
        }
        Ok(proof)
    }

    pub fn route_family_table_bytes(&self, family_id: &str) -> BuilderResult<Vec<u8>> {
        self.route_family_table_bytes_in_artifact(self.artifact, family_id)
    }

    fn route_family_table_bytes_in_artifact(&self, artifact: &'a Artifact, family_id: &str) -> BuilderResult<Vec<u8>> {
        let family = artifact
            .argent
            .template_plan
            .route_families
            .iter()
            .find(|family| family.id == family_id)
            .ok_or_else(|| BuilderError::UnknownRouteFamily(family_id.to_string()))?;
        let route_table = artifact
            .argent
            .template_plan
            .route_tables
            .iter()
            .find(|table| table.id == family.table_id)
            .ok_or_else(|| BuilderError::UnknownRouteTable(family.table_id.clone()))?;
        let mut table = Vec::with_capacity(route_table.byte_len);
        for entry in &route_table.entries {
            match &entry.leaf {
                RouteTemplateLeafArtifact::Template { actor, .. } => {
                    table.extend_from_slice(&decode_hex(&self.contract_in_artifact(artifact, actor)?.compiled.template.hash_hex)?);
                }
                RouteTemplateLeafArtifact::RouteFamily { family_id, .. } => {
                    return Err(BuilderError::NestedRouteFamilyTableLeaf {
                        table_id: route_table.id.clone(),
                        family_id: family_id.clone(),
                    });
                }
            }
        }
        Ok(table)
    }
}

fn hidden_actor_subject(hidden: &HiddenParamArtifact) -> BuilderResult<&str> {
    match &hidden.subject {
        HiddenParamSubjectArtifact::Actor { actor } => Ok(actor.as_str()),
        HiddenParamSubjectArtifact::ObservedActor { actor, .. } => Ok(actor.as_str()),
        HiddenParamSubjectArtifact::RouteFamily { .. } | HiddenParamSubjectArtifact::TemplateSelector { .. } => {
            Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "actor" })
        }
    }
}

fn hidden_family_subject(hidden: &HiddenParamArtifact) -> BuilderResult<&str> {
    match &hidden.subject {
        HiddenParamSubjectArtifact::RouteFamily { family_id } => Ok(family_id.as_str()),
        HiddenParamSubjectArtifact::Actor { .. }
        | HiddenParamSubjectArtifact::ObservedActor { .. }
        | HiddenParamSubjectArtifact::TemplateSelector { .. } => {
            Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "route family" })
        }
    }
}

fn hidden_template_actor(
    hidden: &HiddenParamArtifact,
    entry: &EntryArtifact,
    template_selectors: &BTreeMap<String, String>,
) -> BuilderResult<String> {
    match &hidden.subject {
        HiddenParamSubjectArtifact::Actor { actor } => Ok(actor.clone()),
        HiddenParamSubjectArtifact::ObservedActor { actor, .. } => Ok(actor.clone()),
        HiddenParamSubjectArtifact::TemplateSelector { selector: selector_name } => {
            let selector = entry
                .template_selectors
                .iter()
                .find(|candidate| candidate.name == *selector_name)
                .ok_or_else(|| BuilderError::MissingTemplateSelectorChoice { selector: selector_name.clone() })?;
            let selected_actor = match (template_selectors.get(selector_name), selector.fixed_actor.as_ref()) {
                (Some(selected_actor), Some(fixed_actor)) if selected_actor != fixed_actor => {
                    return Err(BuilderError::InvalidTemplateSelectorChoice {
                        selector: selector.name.clone(),
                        actor: selected_actor.clone(),
                    });
                }
                (Some(selected_actor), _) => selected_actor,
                (None, Some(fixed_actor)) => fixed_actor,
                (None, None) => {
                    return Err(BuilderError::MissingTemplateSelectorChoice { selector: selector_name.clone() });
                }
            };
            if selector.variants.iter().all(|variant| variant != selected_actor) {
                return Err(BuilderError::InvalidTemplateSelectorChoice {
                    selector: selector.name.clone(),
                    actor: selected_actor.clone(),
                });
            }
            Ok(selected_actor.clone())
        }
        HiddenParamSubjectArtifact::RouteFamily { .. } => {
            Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "actor or template selector" })
        }
    }
}

fn route_leaf_label(leaf: &RouteTemplateLeafArtifact) -> String {
    match leaf {
        RouteTemplateLeafArtifact::Template { actor, .. } => actor.clone(),
        RouteTemplateLeafArtifact::RouteFamily { family_id, .. } => family_id.clone(),
    }
}

fn observed_side_label(side: ObservedActorSideArtifact) -> &'static str {
    match side {
        ObservedActorSideArtifact::Input => "input",
        ObservedActorSideArtifact::Output => "output",
    }
}

fn blake2b32(data: &[u8]) -> Vec<u8> {
    blake2b_simd::Params::new().hash_length(32).to_state().update(data).finalize().as_bytes().to_vec()
}

pub fn execute_input_with_covenants(tx: &Transaction, entries: Vec<UtxoEntry>, input_idx: usize) -> Result<(), TxScriptError> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let input = tx.inputs[input_idx].clone();
    let populated = PopulatedTransaction::new(tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    TxScriptEngine::from_transaction_input(
        &populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused_values).with_covenants_ctx(&cov_ctx),
        covenant_engine_flags(),
    )
    .execute()
}

pub fn covenant_engine_flags() -> EngineFlags {
    EngineFlags { covenants_enabled: true, ..Default::default() }
}
