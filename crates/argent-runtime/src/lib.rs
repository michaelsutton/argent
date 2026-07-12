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
    ActorArtifact, ActorInterfaceArtifact, ArtifactIdentityError, ArtifactVersionError, EntryArtifact, HiddenParamArtifact,
    HiddenParamPurposeArtifact, HiddenParamSubjectArtifact, ObserveArtifact, ObservedActorArtifact, ObservedActorSideArtifact,
    RouteTemplateLeafArtifact, RouteTemplateProofArtifact, RuntimeFieldRoleArtifact, RuntimeStatePlanArtifact, SilContractArtifact,
    SilEntryArtifact, StateArtifact, TemplatePlanError, route_template_proof_receipt_id,
};
use kaspa_consensus_core::{
    Hash,
    errors::tx::PopulateGenesisCovenantsError,
    hashing::sighash::SigHashReusedValuesUnsync,
    tx::{
        CovenantBinding, GenesisCovenantGroup, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry, VerifiableTransaction,
    },
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
    pay_to_script_hash_signature_script_with_flags, script_builder::ScriptBuilderError,
};
use kaspa_txscript_errors::TxScriptError;
use silverscript_abi::{
    CodecError, TypeArtifact, decode_hex, encode_entry_sig_script, encode_runtime_state_script, encode_struct_payload,
};
use thiserror::Error;

pub type BuilderResult<T> = std::result::Result<T, BuilderError>;

/// Source-level entrypoint argument accepted by `TxBuilder`.
///
/// Plain values lower directly to Silverscript ABI values. Actor values name an
/// Argent actor and are lowered through the artifact to the matching actor-enum
/// selector index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgValue {
    Value(ArtifactValue),
    /// An Argent-only user-facing argument.
    ///
    /// Actor handles are the only entrypoint args that do not map directly to
    /// the Silverscript ABI. The runtime resolves the actor name through the
    /// artifact and passes the matching selector index to the contract.
    Actor(String),
}

/// Build an actor-valued argument for `args!`.
///
/// Use this when an Argent entrypoint takes an `actor enum` parameter.
pub fn actor(actor: impl Into<String>) -> ArgValue {
    ArgValue::Actor(actor.into())
}

impl<T> From<T> for ArgValue
where
    T: IntoArtifactValue,
{
    fn from(value: T) -> Self {
        Self::Value(value.into_artifact_value())
    }
}

pub trait IntoArtifactValue {
    fn into_artifact_value(self) -> ArtifactValue;
}

impl IntoArtifactValue for ArtifactValue {
    fn into_artifact_value(self) -> ArtifactValue {
        self
    }
}

macro_rules! impl_int_artifact_value {
    ($($ty:ty),* $(,)?) => {
        $(
            impl IntoArtifactValue for $ty {
                fn into_artifact_value(self) -> ArtifactValue {
                    ArtifactValue::Int(self as i64)
                }
            }
        )*
    };
}

impl_int_artifact_value!(i8, i16, i32, i64, isize, u16, u32);

impl IntoArtifactValue for bool {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bool(self)
    }
}

impl IntoArtifactValue for u8 {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Byte(self)
    }
}

impl IntoArtifactValue for Vec<u8> {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bytes(self)
    }
}

impl IntoArtifactValue for &[u8] {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bytes(self.to_vec())
    }
}

impl<const N: usize> IntoArtifactValue for [u8; N] {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bytes(self.to_vec())
    }
}

impl<const N: usize> IntoArtifactValue for &[u8; N] {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bytes(self.to_vec())
    }
}

impl IntoArtifactValue for Hash {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bytes(self.as_bytes().to_vec())
    }
}

impl IntoArtifactValue for &Hash {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Bytes(self.as_bytes().to_vec())
    }
}

impl IntoArtifactValue for String {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Text(self)
    }
}

impl IntoArtifactValue for &str {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Text(self.to_string())
    }
}

impl IntoArtifactValue for BTreeMap<String, ArtifactValue> {
    fn into_artifact_value(self) -> ArtifactValue {
        ArtifactValue::Object(self)
    }
}

/// Build an Argent source-state object for `TxBuilder` calls.
///
/// Returns a `BTreeMap<String, ArtifactValue>` keyed by Argent source field
/// name. Each value is converted through `IntoArtifactValue`.
///
/// ```
/// use argent_runtime::state;
///
/// // Builds:
/// // BTreeMap::from([("count".to_string(), ArtifactValue::Int(2))])
/// let counter = state! {
///     count: 2,
/// };
/// ```
#[macro_export]
macro_rules! state {
    ($($field:ident : $value:expr),* $(,)?) => {{
        let mut state = ::std::collections::BTreeMap::new();
        $(
            state.insert(
                ::std::string::ToString::to_string(stringify!($field)),
                $crate::IntoArtifactValue::into_artifact_value($value),
            );
        )*
        state
    }};
}

/// Build Argent entrypoint argument values for `TxBuilder` calls.
///
/// Returns a `Vec<ArgValue>` in the provided order. Most values convert
/// directly into ABI values; actor handles stay as actor names until the runtime
/// lowers them through the artifact.
///
/// ```
/// use argent_runtime::{args, actor};
///
/// // Builds:
/// // vec![ArgValue::Value(ArtifactValue::Int(3)), ArgValue::Actor("Alpha".to_string())]
/// let args = args![3, actor("Alpha")];
/// ```
#[macro_export]
macro_rules! args {
    ($($value:expr),* $(,)?) => {{
        vec![
            $(
                ::std::convert::Into::<$crate::ArgValue>::into($value),
            )*
        ]
    }};
}

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
    #[error(transparent)]
    PopulateGenesisCovenants(#[from] PopulateGenesisCovenantsError),
    #[error("unknown actor `{0}`")]
    UnknownActor(String),
    #[error("artifact bundle app alias `{0}` is already attached")]
    DuplicateAppAlias(String),
    #[error("artifact bundle has no app alias `{0}`")]
    UnknownAppAlias(String),
    #[error("artifact `{app}` must be attached as `{expected}`, got `{found}`")]
    AppAliasMismatch { app: String, expected: String, found: String },
    #[error("artifact bundle app `{app}` has invalid artifact id: {source}")]
    ArtifactIdentity { app: String, source: ArtifactIdentityError },
    #[error("artifact bundle app `{app}` is missing {direction} interface for actor `{actor}`")]
    MissingInterface { app: String, direction: &'static str, actor: String },
    #[error(
        "artifact bundle app `{app}` actor `{actor}` interface mismatch: expected {expected_fingerprint}, found {found_fingerprint}"
    )]
    InterfaceMismatch { app: String, actor: String, expected_fingerprint: String, found_fingerprint: String },
    #[error("no attached app supplies observed `{observe}` contract `{contract}`")]
    NoAppForObservedContract { observe: String, contract: String },
    #[error("multiple attached apps supply observed `{observe}` contract `{contract}`: {apps:?}")]
    AmbiguousAppForObservedContract { observe: String, contract: String, apps: Vec<String> },
    #[error("runtime state plan for contract `{contract}` is invalid: {message}")]
    RuntimeStatePlanMismatch { contract: String, message: String },
    #[error("runtime state field `{field}` for contract `{contract}` is generated and must be filled by the runtime")]
    HiddenRuntimeFieldProvided { contract: String, field: String },
    #[error("state expansion preimage `{contract}.{field}` as `{memory_state}` cannot be built from the source state")]
    MissingStateExpansionPreimage { contract: String, field: String, memory_state: String },
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
    #[error("argument `{param}` for `{actor}::{entry}` is actor `{selected_actor}`, but `{param}` is not an actor selector")]
    ActorArgumentWithoutSelector { actor: String, entry: String, param: String, selected_actor: String },
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
    #[error("observed {side} `{observe}.{handle}` state `{state}` layout does not match attached actor `{actor}`")]
    ObservedStateLayoutMismatch { observe: String, side: &'static str, handle: String, state: String, actor: String },
    #[error("artifact `{app}` has no state `{state}`")]
    UnknownState { app: String, state: String },
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
    #[error("genesis covenant output {0} was not populated")]
    MissingGenesisCovenantOutput(u32),
    #[error("genesis covenant output {0} does not exist")]
    UnknownGenesisOutput(u32),
}

#[derive(Clone, Debug)]
pub struct ArtifactBundle<'a> {
    primary: &'a Artifact,
    apps: BTreeMap<String, &'a Artifact>,
}

pub struct TxBuilder<'a> {
    bundle: ArtifactBundle<'a>,
}

/// Result of populating genesis covenant bindings on a transaction.
///
/// A launch transaction may create several covenant groups, and each group may
/// bind several outputs to the same covenant id.
pub struct GenesisCovenants {
    pub groups: Vec<GenesisCovenant>,
}

impl GenesisCovenants {
    /// Return the populated genesis output by transaction output index.
    pub fn output(&self, index: u32) -> BuilderResult<&GenesisOutput> {
        self.groups
            .iter()
            .flat_map(|group| group.outputs.iter())
            .find(|output| output.index == index)
            .ok_or(BuilderError::UnknownGenesisOutput(index))
    }
}

/// One populated genesis covenant group.
///
/// Mirrors one `GenesisCovenantGroup`: all `outputs` share `covenant_id`, which
/// is derived from the authorizing input outpoint and the exact output list.
pub struct GenesisCovenant {
    pub authorizing_input: u16,
    pub covenant_id: Hash,
    pub outputs: Vec<GenesisOutput>,
}

/// A concrete output created by a genesis covenant transaction.
///
/// The `outpoint` and `utxo` are the handles needed by the first covenant spend.
pub struct GenesisOutput {
    pub index: u32,
    pub covenant_id: Hash,
    pub outpoint: TransactionOutpoint,
    pub utxo: UtxoEntry,
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

/// Request for building the covenant outputs of one terminal `become` path.
///
/// Argent entries can declare named outputs:
///
/// ```text
/// emits {
///     left_out: Left;
///     peer_out: Right;
/// }
/// ```
///
/// `terminal_path_outputs` uses the artifact's route plan for such an entry to
/// turn source-level output states into concrete transaction outputs. The caller
/// supplies values by output handle; the runtime chooses the declared actor
/// template, generated hidden state fields, authorizing input index, and output
/// ordering.
///
/// `path_index` selects one terminal path through an entry body. It is usually
/// `0` for entries with a single unconditional `become` block. Entries with
/// conditional `become` paths expose one path per terminal route in artifact
/// order.
pub struct TerminalPathOutputRequest<'a> {
    /// Actor whose entry is being spent.
    pub actor_name: &'a str,
    /// Entry that declares the output handles.
    pub entry_name: &'a str,
    /// Terminal `become` path to materialize.
    pub path_index: usize,
    /// Source-level state for each named output handle.
    pub output_states: BTreeMap<String, BTreeMap<String, ArtifactValue>>,
    /// KAS value for each named output handle.
    pub output_values: BTreeMap<String, u64>,
    /// Transaction input index that authorizes these outputs.
    pub authorizing_input: u16,
    /// Covenant id carried by the emitted outputs.
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

#[derive(Clone, Debug)]
pub struct ObservedCovenantContext {
    /// Attached artifact app alias that implements this observed covenant view.
    pub app: String,
    /// Observed inputs keyed by their `observes { inputs { ... } }` handle.
    pub inputs: BTreeMap<String, ObservedInput>,
    /// Observed outputs keyed by their `observes { outputs { ... } }` handle.
    pub outputs: BTreeMap<String, ObservedOutput>,
}

impl ObservedCovenantContext {
    pub fn from_app(app: impl Into<String>) -> Self {
        Self { app: app.into(), inputs: BTreeMap::new(), outputs: BTreeMap::new() }
    }

    pub fn input(
        mut self,
        handle: impl Into<String>,
        actor: impl Into<String>,
        utxo: UtxoEntry,
        state: BTreeMap<String, ArtifactValue>,
    ) -> Self {
        self.inputs.insert(handle.into(), ObservedInput { actor: actor.into(), state, utxo });
        self
    }

    pub fn output(mut self, handle: impl Into<String>, actor: impl Into<String>, state: BTreeMap<String, ArtifactValue>) -> Self {
        self.outputs.insert(handle.into(), ObservedOutput { actor: actor.into(), state });
        self
    }
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

impl<'a> ArtifactBundle<'a> {
    pub fn new(primary: &'a Artifact) -> BuilderResult<Self> {
        validate_artifact("primary", primary)?;
        Ok(Self { primary, apps: BTreeMap::new() })
    }

    pub fn with_app(mut self, alias: impl Into<String>, artifact: &'a Artifact) -> BuilderResult<Self> {
        let alias = alias.into();
        if self.apps.contains_key(&alias) {
            return Err(BuilderError::DuplicateAppAlias(alias));
        }
        let expected = artifact_app_alias(&artifact.app);
        if alias != expected {
            return Err(BuilderError::AppAliasMismatch { app: artifact.app.clone(), expected, found: alias });
        }
        validate_artifact(&alias, artifact)?;
        self.apps.insert(alias, artifact);
        Ok(self)
    }

    fn attach_observed_artifact(mut self, artifact: &'a Artifact) -> BuilderResult<Self> {
        let alias = artifact_app_alias(&artifact.app);
        if self.apps.contains_key(&alias) {
            return Err(BuilderError::DuplicateAppAlias(alias));
        }
        validate_artifact(&alias, artifact)?;
        self.apps.insert(alias, artifact);
        Ok(self)
    }

    fn app(&self, alias: &str) -> BuilderResult<&'a Artifact> {
        self.apps.get(alias).copied().ok_or_else(|| BuilderError::UnknownAppAlias(alias.to_string()))
    }

    fn artifacts(&self) -> impl Iterator<Item = &'a Artifact> + '_ {
        std::iter::once(self.primary).chain(self.apps.values().copied())
    }
}

impl<'a> TxBuilder<'a> {
    pub fn new(artifact: &'a Artifact) -> BuilderResult<Self> {
        Ok(Self { bundle: ArtifactBundle::new(artifact)? })
    }

    pub fn from_bundle(bundle: &ArtifactBundle<'a>) -> BuilderResult<Self> {
        Ok(Self { bundle: bundle.clone() })
    }

    /// Attach another covenant app artifact that this artifact observes.
    ///
    /// The primary artifact still owns the entry being spent. Attached artifacts
    /// supply foreign actor templates and state layouts for observed inputs and
    /// outputs, preserving the `app == covenant` boundary.
    pub fn with_observed_artifact(mut self, artifact: &'a Artifact) -> BuilderResult<Self> {
        self.bundle = self.bundle.clone().attach_observed_artifact(artifact)?;
        Ok(self)
    }

    pub fn with_app(mut self, alias: impl Into<String>, artifact: &'a Artifact) -> BuilderResult<Self> {
        self.bundle = self.bundle.clone().with_app(alias, artifact)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observed_outputs(
        &self,
        actor_name: &str,
        entry_name: &str,
        observe: &str,
        context: &ObservedCovenantContext,
        output_values: BTreeMap<String, u64>,
        authorizing_input: u16,
        covenant_id: Hash,
    ) -> BuilderResult<Vec<TransactionOutput>> {
        self.observed_covenant_outputs(ObservedCovenantOutputRequest {
            actor_name,
            entry_name,
            observe,
            context,
            output_values,
            authorizing_input,
            covenant_id,
        })
    }

    pub fn redeem_script(&self, actor_name: &str, source_state: BTreeMap<String, ArtifactValue>) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref(actor_name)?;
        self.redeem_script_for_contract(contract_ref, source_state)
    }

    pub fn redeem_script_in_app(
        &self,
        app: &str,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref_in_app(app, actor_name)?;
        self.redeem_script_for_contract(contract_ref, source_state)
    }

    fn redeem_script_for_contract(
        &self,
        contract_ref: ContractRef<'a>,
        source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<Vec<u8>> {
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

    pub fn script_public_key_in_app(
        &self,
        app: &str,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<kaspa_consensus_core::tx::ScriptPublicKey> {
        Ok(pay_to_script_hash_script(&self.redeem_script_in_app(app, actor_name, source_state)?))
    }

    /// Build an actor output before it has a covenant id.
    ///
    /// The returned output has the correct P2SH script for `actor_name(state)`
    /// and `covenant: None`, ready for `Transaction::populate_genesis_covenants`.
    pub fn genesis_output(
        &self,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
    ) -> BuilderResult<TransactionOutput> {
        Ok(TransactionOutput::new(value, self.script_public_key(actor_name, source_state)?))
    }

    /// Build an actor output in an attached app before it has a covenant id.
    ///
    /// This is the multi-app variant of `genesis_output`.
    pub fn genesis_output_in_app(
        &self,
        app: &str,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
    ) -> BuilderResult<TransactionOutput> {
        Ok(TransactionOutput::new(value, self.script_public_key_in_app(app, actor_name, source_state)?))
    }

    /// Populate genesis covenant bindings and return first-spend handles.
    ///
    /// This wraps `Transaction::populate_genesis_covenants`, finalizes the tx
    /// after mutation, and reports covenant ids, outpoints, and UTXO entries for
    /// the populated outputs.
    pub fn populate_genesis_covenants(tx: &mut Transaction, groups: &[GenesisCovenantGroup]) -> BuilderResult<GenesisCovenants> {
        tx.populate_genesis_covenants(groups)?;
        tx.finalize();

        let tx_id = tx.id();
        let is_coinbase = tx.is_coinbase();
        let mut populated_groups = Vec::with_capacity(groups.len());
        for group in groups {
            let first_output_index = group.outputs.first().copied().ok_or(PopulateGenesisCovenantsError::EmptyOutputs)?;
            let first_output =
                tx.outputs.get(first_output_index as usize).ok_or(BuilderError::UnknownGenesisOutput(first_output_index))?;
            let covenant_id = first_output.covenant.ok_or(BuilderError::MissingGenesisCovenantOutput(first_output_index))?.covenant_id;
            let mut outputs = Vec::with_capacity(group.outputs.len());
            for &index in &group.outputs {
                let output = tx.outputs.get(index as usize).ok_or(BuilderError::UnknownGenesisOutput(index))?;
                let binding = output.covenant.ok_or(BuilderError::MissingGenesisCovenantOutput(index))?;
                outputs.push(GenesisOutput {
                    index,
                    covenant_id: binding.covenant_id,
                    outpoint: TransactionOutpoint::new(tx_id, index),
                    utxo: UtxoEntry::new(output.value, output.script_public_key.clone(), 0, is_coinbase, Some(binding.covenant_id)),
                });
            }
            populated_groups.push(GenesisCovenant { authorizing_input: group.authorizing_input, covenant_id, outputs });
        }

        Ok(GenesisCovenants { groups: populated_groups })
    }

    /// Build a primary-app P2SH sigscript from source state and user arguments.
    ///
    /// Template witnesses for closed observed actors are inferred from attached
    /// app interfaces. Open observed actors and observed state-derived witnesses
    /// require `p2sh_signature_script_with_observed_covenants`.
    pub fn p2sh_signature_script(
        &self,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArgValue>,
    ) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref(actor_name)?;
        let contract = contract_ref.contract;
        let sil_entry = contract
            .entry(entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        let entry_ref = self.entry_ref_in_artifact(contract_ref.artifact, actor_name, entry_name)?;
        let argent_entry = entry_ref.entry;
        let (artifact_args, template_selectors) = self.lower_arg_values(actor_name, entry_name, sil_entry, argent_entry, user_args)?;
        self.p2sh_signature_script_with_context_in_artifact(
            contract_ref.artifact,
            actor_name,
            entry_name,
            input_source_state,
            artifact_args,
            &template_selectors,
            None,
        )
    }

    pub fn p2sh_signature_script_in_app(
        &self,
        app: &str,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArgValue>,
    ) -> BuilderResult<Vec<u8>> {
        let artifact = self.bundle.app(app)?;
        let contract_ref = self.contract_ref_in_artifact(artifact, actor_name)?;
        let contract = contract_ref.contract;
        let sil_entry = contract
            .entry(entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        let entry_ref = self.entry_ref_in_artifact(artifact, actor_name, entry_name)?;
        let argent_entry = entry_ref.entry;
        let (artifact_args, template_selectors) = self.lower_arg_values(actor_name, entry_name, sil_entry, argent_entry, user_args)?;
        self.p2sh_signature_script_with_context_in_artifact(
            artifact,
            actor_name,
            entry_name,
            input_source_state,
            artifact_args,
            &template_selectors,
            None,
        )
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
        user_args: Vec<ArgValue>,
        observed: &BTreeMap<String, ObservedCovenantContext>,
    ) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref(actor_name)?;
        let contract = contract_ref.contract;
        let sil_entry = contract
            .entry(entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        let entry_ref = self.entry_ref_in_artifact(contract_ref.artifact, actor_name, entry_name)?;
        let argent_entry = entry_ref.entry;
        let (artifact_args, template_selectors) = self.lower_arg_values(actor_name, entry_name, sil_entry, argent_entry, user_args)?;
        self.p2sh_signature_script_with_context_in_artifact(
            contract_ref.artifact,
            actor_name,
            entry_name,
            input_source_state,
            artifact_args,
            &template_selectors,
            Some(observed),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn p2sh_signature_script_with_context_in_artifact(
        &self,
        artifact: &'a Artifact,
        actor_name: &str,
        entry_name: &str,
        input_source_state: BTreeMap<String, ArtifactValue>,
        user_args: Vec<ArtifactValue>,
        template_selectors: &BTreeMap<String, String>,
        observed: Option<&BTreeMap<String, ObservedCovenantContext>>,
    ) -> BuilderResult<Vec<u8>> {
        let contract_ref = self.contract_ref_in_artifact(artifact, actor_name)?;
        let contract = contract_ref.contract;
        let sil_entry = contract
            .entry(entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        let entry_ref = self.entry_ref_in_artifact(artifact, actor_name, entry_name)?;
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
                    let contract_ref =
                        self.hidden_template_contract_ref(entry_ref.artifact, hidden, argent_entry, template_selectors, observed)?;
                    ArtifactValue::Bytes(decode_hex(&contract_ref.contract.compiled.template.prefix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplateSuffixBytes => {
                    let contract_ref =
                        self.hidden_template_contract_ref(entry_ref.artifact, hidden, argent_entry, template_selectors, observed)?;
                    ArtifactValue::Bytes(decode_hex(&contract_ref.contract.compiled.template.suffix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplatePrefixLen => {
                    let contract_ref =
                        self.hidden_template_contract_ref(entry_ref.artifact, hidden, argent_entry, template_selectors, observed)?;
                    ArtifactValue::Int(decode_hex(&contract_ref.contract.compiled.template.prefix_hex)?.len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateSuffixLen => {
                    let contract_ref =
                        self.hidden_template_contract_ref(entry_ref.artifact, hidden, argent_entry, template_selectors, observed)?;
                    ArtifactValue::Int(decode_hex(&contract_ref.contract.compiled.template.suffix_hex)?.len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateHash => {
                    let contract_ref =
                        self.hidden_template_contract_ref(entry_ref.artifact, hidden, argent_entry, template_selectors, observed)?;
                    ArtifactValue::Bytes(decode_hex(&contract_ref.contract.compiled.template.hash_hex)?)
                }
                HiddenParamPurposeArtifact::RouteTemplateLeaf => {
                    let actor = hidden_actor_subject(hidden)?;
                    ArtifactValue::Bytes(decode_hex(
                        &self.contract_ref_in_artifact(entry_ref.artifact, actor)?.contract.compiled.template.hash_hex,
                    )?)
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
                HiddenParamPurposeArtifact::StateExpansionPreimage => {
                    self.state_expansion_preimage_arg(entry_ref.artifact, contract, hidden, &input_source_state)?
                }
                HiddenParamPurposeArtifact::ObservedOutputFieldValue => self.observed_output_field_arg(hidden, observed)?,
            });
        }

        let sigscript = encode_entry_sig_script(&contract_ref.artifact.sil_abi, contract, sil_entry, &args)?;
        Ok(pay_to_script_hash_signature_script_with_flags(
            self.redeem_script_for_contract(contract_ref, input_source_state)?,
            sigscript,
            covenant_engine_flags(),
        )?)
    }

    fn lower_arg_values(
        &self,
        actor_name: &str,
        entry_name: &str,
        sil_entry: &SilEntryArtifact,
        argent_entry: &EntryArtifact,
        user_args: Vec<ArgValue>,
    ) -> BuilderResult<(Vec<ArtifactValue>, BTreeMap<String, String>)> {
        let mut artifact_args = Vec::with_capacity(user_args.len());
        let mut template_selectors = BTreeMap::new();

        for (idx, arg) in user_args.into_iter().enumerate() {
            match arg {
                ArgValue::Value(value) => artifact_args.push(value),
                ArgValue::Actor(selected_actor) => {
                    let Some(param) = sil_entry.params.get(idx) else {
                        return Err(BuilderError::ActorArgumentWithoutSelector {
                            actor: actor_name.to_string(),
                            entry: entry_name.to_string(),
                            param: format!("#{idx}"),
                            selected_actor,
                        });
                    };
                    let selector =
                        argent_entry.template_selectors.iter().find(|selector| selector.name == param.name).ok_or_else(|| {
                            BuilderError::ActorArgumentWithoutSelector {
                                actor: actor_name.to_string(),
                                entry: entry_name.to_string(),
                                param: param.name.clone(),
                                selected_actor: selected_actor.clone(),
                            }
                        })?;
                    let variant_index = selector.variants.iter().position(|variant| variant == &selected_actor).ok_or_else(|| {
                        BuilderError::InvalidTemplateSelectorChoice { selector: selector.name.clone(), actor: selected_actor.clone() }
                    })?;
                    template_selectors.insert(selector.name.clone(), selected_actor);
                    artifact_args.push(ArtifactValue::Int(variant_index as i64));
                }
            }
        }

        Ok((artifact_args, template_selectors))
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

    pub fn covenant_output_in_app(
        &self,
        app: &str,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
        authorizing_input: u16,
        covenant_id: Hash,
    ) -> BuilderResult<TransactionOutput> {
        Ok(TransactionOutput {
            value,
            script_public_key: self.script_public_key_in_app(app, actor_name, source_state)?,
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

    #[allow(clippy::too_many_arguments)]
    pub fn covenant_utxo_in_app(
        &self,
        app: &str,
        actor_name: &str,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
        block_daa_score: u64,
        is_coinbase: bool,
        covenant_id: Option<Hash>,
    ) -> BuilderResult<UtxoEntry> {
        Ok(UtxoEntry::new(
            value,
            self.script_public_key_in_app(app, actor_name, source_state)?,
            block_daa_score,
            is_coinbase,
            covenant_id,
        ))
    }

    /// Build all outputs for one terminal path of a named-output entry.
    ///
    /// This is the multi-output counterpart to `covenant_output`. It is useful
    /// when an entry emits several named actors and the runtime should apply the
    /// artifact route plan instead of asking the caller to manually match output
    /// handles to actors/templates.
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
        let app = request.context.app.as_str();

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
            outputs.push(self.covenant_output_in_app(
                app,
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

    pub fn contract_in_app(&self, app: &str, name: &str) -> BuilderResult<&'a SilContractArtifact> {
        Ok(self.contract_ref_in_app(app, name)?.contract)
    }

    fn validate_actor_interface(&self, app: &str, actor: &str) -> BuilderResult<()> {
        let artifact = self.bundle.app(app)?;
        let expected = find_interface(&self.bundle.primary.argent.interfaces.imports, actor).ok_or_else(|| {
            BuilderError::MissingInterface { app: "primary".to_string(), direction: "import", actor: actor.to_string() }
        })?;
        let found = find_interface(&artifact.argent.interfaces.exports, actor).ok_or_else(|| BuilderError::MissingInterface {
            app: app.to_string(),
            direction: "export",
            actor: actor.to_string(),
        })?;
        if expected.fingerprint_hex != found.fingerprint_hex {
            return Err(BuilderError::InterfaceMismatch {
                app: app.to_string(),
                actor: actor.to_string(),
                expected_fingerprint: expected.fingerprint_hex.clone(),
                found_fingerprint: found.fingerprint_hex.clone(),
            });
        }
        Ok(())
    }

    fn observed_contract_ref(&self, observe: &str, contract: &str) -> BuilderResult<ContractRef<'a>> {
        let mut contract_apps = Vec::new();
        let mut valid_apps = Vec::new();
        let mut first_interface_error = None;
        for (app, artifact) in &self.bundle.apps {
            if artifact.sil_abi.contract(contract).is_some() {
                contract_apps.push(app.clone());
                match self.validate_actor_interface(app, contract) {
                    Ok(()) => valid_apps.push(app.clone()),
                    Err(err) if first_interface_error.is_none() => first_interface_error = Some(err),
                    Err(_) => {}
                }
            }
        }
        match valid_apps.as_slice() {
            [app] => self.contract_ref_in_app(app, contract),
            [] if contract_apps.is_empty() => {
                Err(BuilderError::NoAppForObservedContract { observe: observe.to_string(), contract: contract.to_string() })
            }
            [] => Err(first_interface_error.expect("at least one app with contract produced an interface result")),
            _ => Err(BuilderError::AmbiguousAppForObservedContract {
                observe: observe.to_string(),
                contract: contract.to_string(),
                apps: valid_apps,
            }),
        }
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
        self.bundle.artifacts()
    }

    fn contract_ref_in_artifact(&self, artifact: &'a Artifact, name: &str) -> BuilderResult<ContractRef<'a>> {
        let contract = self.contract_in_artifact(artifact, name)?;
        Ok(ContractRef { artifact, contract })
    }

    fn contract_ref_in_app(&self, app: &str, name: &str) -> BuilderResult<ContractRef<'a>> {
        self.contract_ref_in_artifact(self.bundle.app(app)?, name)
    }

    fn hidden_template_contract_ref(
        &self,
        primary_artifact: &'a Artifact,
        hidden: &HiddenParamArtifact,
        entry: &'a EntryArtifact,
        template_selectors: &BTreeMap<String, String>,
        observed: Option<&BTreeMap<String, ObservedCovenantContext>>,
    ) -> BuilderResult<ContractRef<'a>> {
        match &hidden.subject {
            HiddenParamSubjectArtifact::Actor { actor } => self.contract_ref_in_artifact(primary_artifact, actor),
            HiddenParamSubjectArtifact::ObservedActor { observe, side, handle, actor } => {
                match observed.and_then(|contexts| contexts.get(observe)) {
                    Some(context) => {
                        let observed_actor = match side {
                            ObservedActorSideArtifact::Input => context.inputs.get(handle).map(|observed| observed.actor.as_str()),
                            ObservedActorSideArtifact::Output => context.outputs.get(handle).map(|observed| observed.actor.as_str()),
                        }
                        .unwrap_or(actor.as_str());
                        self.contract_ref_in_app(&context.app, observed_actor)
                    }
                    None => {
                        let observed_actor = self.observed_actor(entry, observe, *side, handle)?;
                        if observed_actor.open_state.is_some() {
                            return Err(BuilderError::MissingObservedCovenant { observe: observe.clone() });
                        }
                        self.observed_contract_ref(observe, &observed_actor.actor)
                    }
                }
            }
            HiddenParamSubjectArtifact::TemplateSelector { .. } => {
                let actor = hidden_template_actor(hidden, entry, template_selectors)?;
                self.contract_ref_in_artifact(primary_artifact, &actor)
            }
            HiddenParamSubjectArtifact::RouteFamily { .. }
            | HiddenParamSubjectArtifact::StateExpansion { .. }
            | HiddenParamSubjectArtifact::ObservedOutputField { .. } => {
                Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "actor or template selector" })
            }
        }
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

    fn argent_actor_ref_in_artifact(&self, artifact: &'a Artifact, name: &str) -> BuilderResult<ActorRef<'a>> {
        artifact
            .argent
            .actors
            .iter()
            .find(|actor| actor.name == name)
            .map(|actor| ActorRef { artifact, actor })
            .ok_or_else(|| BuilderError::UnknownActor(name.to_string()))
    }

    pub fn entry(&self, actor_name: &str, entry_name: &str) -> BuilderResult<&'a EntryArtifact> {
        Ok(self.entry_ref(actor_name, entry_name)?.entry)
    }

    fn entry_ref(&self, actor_name: &str, entry_name: &str) -> BuilderResult<EntryRef<'a>> {
        let actor_ref = self.argent_actor_ref(actor_name)?;
        self.entry_ref_for_actor(actor_ref, actor_name, entry_name)
    }

    fn entry_ref_in_artifact(&self, artifact: &'a Artifact, actor_name: &str, entry_name: &str) -> BuilderResult<EntryRef<'a>> {
        let actor_ref = self.argent_actor_ref_in_artifact(artifact, actor_name)?;
        self.entry_ref_for_actor(actor_ref, actor_name, entry_name)
    }

    fn entry_ref_for_actor(&self, actor_ref: ActorRef<'a>, actor_name: &str, entry_name: &str) -> BuilderResult<EntryRef<'a>> {
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

    fn observed_actor(
        &self,
        entry: &'a EntryArtifact,
        observe_name: &str,
        side: ObservedActorSideArtifact,
        handle: &str,
    ) -> BuilderResult<&'a ObservedActorArtifact> {
        let observe = self.observe(&entry.abi.actor, &entry.name, entry, observe_name)?;
        let actors = match side {
            ObservedActorSideArtifact::Input => &observe.inputs,
            ObservedActorSideArtifact::Output => &observe.outputs,
        };
        actors.iter().find(|actor| actor.name == handle).ok_or_else(|| BuilderError::MissingObservedActor {
            observe: observe_name.to_string(),
            side: observed_side_label(side),
            handle: handle.to_string(),
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
        self.bundle.app(&context.app)?;
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
            self.validate_observed_actor(&context.app, observe_name, ObservedActorSideArtifact::Input, input, &observed.actor)?;
            let expected_script_public_key = self.script_public_key_in_app(&context.app, &observed.actor, observed.state.clone())?;
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
            self.validate_observed_actor(&context.app, observe_name, ObservedActorSideArtifact::Output, output, &observed.actor)?;
            self.redeem_script_in_app(&context.app, &observed.actor, observed.state.clone())?;
        }
        Ok(())
    }

    fn validate_observed_actor(
        &self,
        app: &str,
        observe_name: &str,
        side: ObservedActorSideArtifact,
        expected: &ObservedActorArtifact,
        found_actor: &str,
    ) -> BuilderResult<()> {
        if let Some(expected_state) = expected.open_state.as_deref() {
            let found = self.argent_actor_ref_in_artifact(self.bundle.app(app)?, found_actor)?;
            if !state_satisfies(found.artifact, &found.actor.state, expected_state) {
                return Err(BuilderError::ObservedStateLayoutMismatch {
                    observe: observe_name.to_string(),
                    side: observed_side_label(side),
                    handle: expected.name.clone(),
                    actor: found_actor.to_string(),
                    state: expected_state.to_string(),
                });
            }
            let expected_layout = state_artifact(self.bundle.primary, expected_state)?;
            let found_layout = state_artifact(found.artifact, &found.actor.state)?;
            if expected_layout.fields != found_layout.fields {
                return Err(BuilderError::ObservedStateLayoutMismatch {
                    observe: observe_name.to_string(),
                    side: observed_side_label(side),
                    handle: expected.name.clone(),
                    state: expected_state.to_string(),
                    actor: found_actor.to_string(),
                });
            }
            return Ok(());
        }
        if expected.actor != found_actor {
            return Err(BuilderError::ObservedActorMismatch {
                observe: observe_name.to_string(),
                side: observed_side_label(side),
                handle: expected.name.clone(),
                expected: expected.actor.clone(),
                found: found_actor.to_string(),
            });
        }
        self.validate_actor_interface(app, &expected.actor)?;
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
                    let value = if let Some(memory_state) =
                        state_expansion_memory_for_field(artifact, &contract.runtime_state.source, &field.name)
                    {
                        let payload =
                            self.state_expansion_preimage_payload(artifact, contract, &field.name, memory_state, &mut source_state)?;
                        ArtifactValue::Bytes(blake2b32(&payload))
                    } else {
                        source_state.remove(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?
                    };
                    values.insert(field.name.clone(), value);
                }
                Some(role) => {
                    if source_state.contains_key(&field.name) {
                        return Err(BuilderError::HiddenRuntimeFieldProvided {
                            contract: contract.name.clone(),
                            field: field.name.clone(),
                        });
                    }
                    match role {
                        RuntimeFieldRoleArtifact::Template { contract } => {
                            values.insert(
                                field.name.clone(),
                                ArtifactValue::Bytes(decode_hex(
                                    &self.contract_in_artifact(artifact, contract)?.compiled.template.hash_hex,
                                )?),
                            );
                        }
                        RuntimeFieldRoleArtifact::ObservedTemplate { observe, contract, .. } => {
                            values.insert(
                                field.name.clone(),
                                ArtifactValue::Bytes(decode_hex(
                                    &self.observed_contract_ref(observe, contract)?.contract.compiled.template.hash_hex,
                                )?),
                            );
                        }
                        RuntimeFieldRoleArtifact::TemplateTable { contracts } => {
                            let mut table = Vec::with_capacity(contracts.len() * 32);
                            for contract in contracts {
                                table.extend_from_slice(&decode_hex(
                                    &self.contract_in_artifact(artifact, contract)?.compiled.template.hash_hex,
                                )?);
                            }
                            values.insert(field.name.clone(), ArtifactValue::Bytes(table));
                        }
                        RuntimeFieldRoleArtifact::TemplateDigest { id } => {
                            let table = self.route_family_table_bytes_in_artifact(artifact, id)?;
                            values.insert(field.name.clone(), ArtifactValue::Bytes(blake2b32(&table)));
                        }
                        RuntimeFieldRoleArtifact::TemplateRoot { .. } => {
                            let proof_id = route_template_proof_receipt_id(&contract.runtime_state.source, &field.name);
                            let proof = self.route_template_proof_in_artifact(artifact, &proof_id)?;
                            values.insert(field.name.clone(), ArtifactValue::Bytes(decode_hex(&proof.root_hex)?));
                        }
                    }
                }
            }
        }
        if let Some(extra) = source_state.into_keys().next() {
            return Err(CodecError::UnknownField(extra).into());
        }
        Ok(values)
    }

    fn state_expansion_preimage_arg(
        &self,
        artifact: &'a Artifact,
        contract: &SilContractArtifact,
        hidden: &HiddenParamArtifact,
        source_state: &BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<ArtifactValue> {
        let HiddenParamSubjectArtifact::StateExpansion { state, field, memory_state } = &hidden.subject else {
            return Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "state expansion" });
        };
        if state != &contract.runtime_state.source {
            return Err(BuilderError::UnexpectedHiddenSubject {
                param: hidden.name.clone(),
                expected: "current contract state expansion",
            });
        }
        let mut source_state = source_state.clone();
        Ok(ArtifactValue::Bytes(self.state_expansion_preimage_payload(artifact, contract, field, memory_state, &mut source_state)?))
    }

    fn observed_output_field_arg(
        &self,
        hidden: &HiddenParamArtifact,
        observed: Option<&BTreeMap<String, ObservedCovenantContext>>,
    ) -> BuilderResult<ArtifactValue> {
        let HiddenParamSubjectArtifact::ObservedOutputField { observe, handle, state, field } = &hidden.subject else {
            return Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "observed output field" });
        };
        let context = observed
            .and_then(|contexts| contexts.get(observe))
            .ok_or_else(|| BuilderError::MissingObservedCovenant { observe: observe.clone() })?;
        let output = context.outputs.get(handle).ok_or_else(|| BuilderError::MissingObservedActor {
            observe: observe.clone(),
            side: observed_side_label(ObservedActorSideArtifact::Output),
            handle: handle.clone(),
        })?;
        let contract_ref = self.contract_ref_in_app(&context.app, &output.actor)?;
        if !state_satisfies(contract_ref.artifact, &contract_ref.contract.runtime_state.source, state) {
            return Err(BuilderError::ObservedStateLayoutMismatch {
                observe: observe.clone(),
                side: observed_side_label(ObservedActorSideArtifact::Output),
                handle: handle.clone(),
                state: state.clone(),
                actor: output.actor.clone(),
            });
        }
        let values = self.runtime_state_values(contract_ref.artifact, contract_ref.contract, output.state.clone())?;
        values.get(field).cloned().ok_or_else(|| CodecError::MissingField(field.clone()).into())
    }

    fn state_expansion_preimage_payload(
        &self,
        artifact: &'a Artifact,
        contract: &SilContractArtifact,
        digest_field: &str,
        memory_state: &str,
        source_state: &mut BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<Vec<u8>> {
        let memory = state_artifact(artifact, memory_state)?;
        let Some(ArtifactValue::Object(fields)) = source_state.remove(digest_field) else {
            return Err(BuilderError::MissingStateExpansionPreimage {
                contract: contract.name.clone(),
                field: digest_field.to_string(),
                memory_state: memory_state.to_string(),
            });
        };
        for field in &memory.fields {
            if !fields.contains_key(&field.name) {
                return Err(BuilderError::MissingStateExpansionPreimage {
                    contract: contract.name.clone(),
                    field: digest_field.to_string(),
                    memory_state: memory_state.to_string(),
                });
            }
        }
        Ok(encode_struct_payload(&artifact.sil_abi, contract, memory_state, &fields)?)
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
        self.route_family_table_bytes_in_artifact(self.bundle.primary, family_id)
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

fn validate_artifact(app: &str, artifact: &Artifact) -> BuilderResult<()> {
    artifact.check_schema_version()?;
    artifact.verify_template_plan()?;
    artifact.verify_id().map_err(|source| BuilderError::ArtifactIdentity { app: app.to_string(), source })?;
    Ok(())
}

fn find_interface<'a>(interfaces: &'a [ActorInterfaceArtifact], actor: &str) -> Option<&'a ActorInterfaceArtifact> {
    interfaces.iter().find(|interface| interface.actor == actor)
}

fn hidden_actor_subject(hidden: &HiddenParamArtifact) -> BuilderResult<&str> {
    match &hidden.subject {
        HiddenParamSubjectArtifact::Actor { actor } => Ok(actor.as_str()),
        HiddenParamSubjectArtifact::ObservedActor { actor, .. } => Ok(actor.as_str()),
        HiddenParamSubjectArtifact::RouteFamily { .. }
        | HiddenParamSubjectArtifact::TemplateSelector { .. }
        | HiddenParamSubjectArtifact::ObservedOutputField { .. }
        | HiddenParamSubjectArtifact::StateExpansion { .. } => {
            Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "actor" })
        }
    }
}

fn hidden_family_subject(hidden: &HiddenParamArtifact) -> BuilderResult<&str> {
    match &hidden.subject {
        HiddenParamSubjectArtifact::RouteFamily { family_id } => Ok(family_id.as_str()),
        HiddenParamSubjectArtifact::Actor { .. }
        | HiddenParamSubjectArtifact::ObservedActor { .. }
        | HiddenParamSubjectArtifact::TemplateSelector { .. }
        | HiddenParamSubjectArtifact::ObservedOutputField { .. }
        | HiddenParamSubjectArtifact::StateExpansion { .. } => {
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
        HiddenParamSubjectArtifact::RouteFamily { .. }
        | HiddenParamSubjectArtifact::StateExpansion { .. }
        | HiddenParamSubjectArtifact::ObservedOutputField { .. } => {
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

fn state_artifact<'a>(artifact: &'a Artifact, state: &str) -> BuilderResult<&'a StateArtifact> {
    artifact
        .argent
        .states
        .iter()
        .find(|candidate| candidate.name == state)
        .ok_or_else(|| BuilderError::UnknownState { app: artifact.app.clone(), state: state.to_string() })
}

fn state_satisfies(artifact: &Artifact, found_state: &str, expected_state: &str) -> bool {
    found_state == expected_state
        || artifact.argent.state_expansions.iter().any(|expansion| expansion.state == found_state && expansion.base == expected_state)
}

fn state_expansion_memory_for_field<'a>(artifact: &'a Artifact, state: &str, field: &str) -> Option<&'a str> {
    artifact
        .argent
        .state_expansions
        .iter()
        .find(|expansion| expansion.state == state)
        .and_then(|expansion| expansion.digests.iter().find(|digest| digest.field == field))
        .map(|digest| digest.state.as_str())
}

fn artifact_app_alias(app: &str) -> String {
    to_snake(app)
}

fn to_snake(input: &str) -> String {
    let mut out = String::new();
    let chars = input.chars().collect::<Vec<_>>();
    for (idx, ch) in chars.iter().enumerate() {
        let prev = idx.checked_sub(1).and_then(|prev| chars.get(prev)).copied();
        let next = chars.get(idx + 1).copied();
        if ch.is_ascii_uppercase() {
            let insert_sep = idx > 0
                && !out.ends_with('_')
                && prev.is_some_and(|prev| {
                    prev.is_ascii_lowercase() || prev.is_ascii_digit() || next.is_some_and(|next| next.is_ascii_lowercase())
                });
            if insert_sep {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_ascii_alphanumeric() {
            out.push(*ch);
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_macro_builds_artifact_value_map() {
        let covenant_id = Hash::from_bytes([0x44; 32]);
        let nested = state! {
            hunger: 7,
        };

        let value = state! {
            count: 2,
            ready: true,
            tag: [0xaa_u8; 2],
            controller: covenant_id,
            label: "counter",
            nested: nested.clone(),
        };

        assert_eq!(value.get("count"), Some(&ArtifactValue::Int(2)));
        assert_eq!(value.get("ready"), Some(&ArtifactValue::Bool(true)));
        assert_eq!(value.get("tag"), Some(&ArtifactValue::Bytes(vec![0xaa; 2])));
        assert_eq!(value.get("controller"), Some(&ArtifactValue::Bytes(vec![0x44; 32])));
        assert_eq!(value.get("label"), Some(&ArtifactValue::Text("counter".to_string())));
        assert_eq!(value.get("nested"), Some(&ArtifactValue::Object(nested)));
    }

    #[test]
    fn args_macro_builds_artifact_value_list() {
        assert_eq!(
            args![3, true, [0xaa_u8; 2], actor("Alpha")],
            vec![
                ArgValue::Value(ArtifactValue::Int(3)),
                ArgValue::Value(ArtifactValue::Bool(true)),
                ArgValue::Value(ArtifactValue::Bytes(vec![0xaa; 2])),
                ArgValue::Actor("Alpha".to_string()),
            ]
        );
    }

    #[test]
    fn populate_genesis_covenants_reports_multiple_groups() {
        let funding_outpoint = TransactionOutpoint::new(Hash::from_bytes([0x91; 32]), 0);
        let mut tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(funding_outpoint, Vec::new())],
            vec![
                TransactionOutput::new(1_000, Default::default()),
                TransactionOutput::new(2_000, Default::default()),
                TransactionOutput::new(3_000, Default::default()),
                TransactionOutput::new(4_000, Default::default()),
            ],
        );

        let genesis = TxBuilder::populate_genesis_covenants(
            &mut tx,
            &[GenesisCovenantGroup::new(0, vec![0, 2]), GenesisCovenantGroup::new(0, vec![1, 3])],
        )
        .expect("genesis covenant population succeeds");

        assert_eq!(genesis.groups.len(), 2);
        assert_eq!(genesis.groups[0].outputs.len(), 2);
        assert_eq!(genesis.groups[1].outputs.len(), 2);
        assert_ne!(genesis.groups[0].covenant_id, genesis.groups[1].covenant_id);

        let output_0 = genesis.output(0).expect("output 0 handle exists");
        let output_2 = genesis.output(2).expect("output 2 handle exists");
        assert_eq!(output_0.covenant_id, genesis.groups[0].covenant_id);
        assert_eq!(output_2.covenant_id, genesis.groups[0].covenant_id);
        assert_eq!(output_0.outpoint, TransactionOutpoint::new(tx.id(), 0));
        assert_eq!(output_2.outpoint, TransactionOutpoint::new(tx.id(), 2));
        assert_eq!(output_0.utxo.amount, tx.outputs[0].value);
        assert_eq!(output_0.utxo.script_public_key, tx.outputs[0].script_public_key);
        assert_eq!(output_0.utxo.covenant_id, Some(output_0.covenant_id));

        let output_1 = genesis.output(1).expect("output 1 handle exists");
        let output_3 = genesis.output(3).expect("output 3 handle exists");
        assert_eq!(output_1.covenant_id, genesis.groups[1].covenant_id);
        assert_eq!(output_3.covenant_id, genesis.groups[1].covenant_id);
        assert_eq!(tx.outputs[1].covenant.expect("output 1 covenant").covenant_id, output_1.covenant_id);
        assert!(matches!(genesis.output(99), Err(BuilderError::UnknownGenesisOutput(99))));
    }
}
