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

mod context;
mod resolve;

use std::{collections::BTreeMap, error::Error, fmt};

pub use argent_artifact::Artifact;
pub use context::{
    ActorPath, ArgentInput, ContextInput, ContextOutput, EntryArgs, EntryCall, InputSigScript, OrdinaryInput, OutputCovenant,
    OutputOwner, OutputState, StateContext, TxContext, state_with, try_state_with,
};
pub use silverscript_abi::ArtifactValue;

use argent_artifact::{
    ActorArtifact, ActorInterfaceArtifact, ArtifactIdentityError, ArtifactVersionError, CompiledTemplateArtifact, EntryArtifact,
    HiddenParamArtifact, HiddenParamPurposeArtifact, HiddenParamSubjectArtifact, ObserveArtifact, ObservedActorArtifact,
    ObservedActorSideArtifact, RouteTemplateLeafArtifact, RouteTemplateProofArtifact, RuntimeFieldRoleArtifact,
    RuntimeStatePlanArtifact, SilContractArtifact, SilEntryArtifact, StateArtifact, TemplatePlanError, fixed_runtime_context_value,
};
use kaspa_consensus_core::{
    Hash,
    config::params::MAINNET_PARAMS,
    constants::TX_VERSION_TOCCATA,
    errors::tx::PopulateGenesisCovenantsError,
    hashing::sighash::SigHashReusedValuesUnsync,
    mass::{ComputeBudget, MassCalculator, ScriptUnits},
    tx::{
        GenesisCovenantGroup, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
        VerifiableTransaction,
    },
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, SigCacheKey, TxScriptEngine, caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
    script_builder::ScriptBuilderError,
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

/// The input or output side of an observed covenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Observed inputs.
    In,
    /// Observed outputs.
    Out,
}

impl fmt::Display for Side {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::In => "input",
            Self::Out => "output",
        })
    }
}

impl From<ObservedActorSideArtifact> for Side {
    fn from(side: ObservedActorSideArtifact) -> Self {
        match side {
            ObservedActorSideArtifact::Input => Self::In,
            ObservedActorSideArtifact::Output => Self::Out,
        }
    }
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
    MissingObservedActor { observe: String, side: Side, handle: String },
    #[error("unknown observed {side} `{observe}.{handle}`")]
    UnknownObservedActor { observe: String, side: Side, handle: String },
    #[error("observed {side} `{observe}.{handle}` expected actor `{expected}`, got `{found}`")]
    ObservedActorMismatch { observe: String, side: Side, handle: String, expected: String, found: String },
    #[error("observed {side} `{observe}.{handle}` state `{state}` layout does not match attached actor `{actor}`")]
    ObservedStateLayoutMismatch { observe: String, side: Side, handle: String, state: String, actor: String },
    #[error("attached actor `{actor}` does not expose actor_type<{state}>")]
    MissingActorTypeHandle { actor: String, state: String },
    #[error("artifact `{app}` has no state `{state}`")]
    UnknownState { app: String, state: String },
    #[error("observed input `{observe}.{handle}` UTXO does not match actor `{actor}` and state")]
    ObservedUtxoScriptMismatch { observe: String, handle: String, actor: String },
    #[error("observe `{observe}` covenant id source must resolve to exactly 32 bytes")]
    InvalidObservedCovenantId { observe: String },
    #[error("observe `{observe}` expects {expected} {side}s for its covenant id, found {found}")]
    ObservedCountMismatch { observe: String, side: Side, expected: usize, found: usize },
    #[error("observed {side} `{observe}.{handle}` at transaction index {index} has no Argent actor metadata")]
    MissingObservedActorMetadata { observe: String, side: Side, handle: String, index: usize },
    #[error("spawn `{spawn}` has no genesis output `{handle}` at group index {group_index}")]
    MissingSpawnOutput { spawn: String, handle: String, group_index: usize },
    #[error("spawn `{spawn}` has no compatible genesis output group")]
    MissingSpawnGroup { spawn: String },
    #[error("invalid genesis path `{0}`; expected `launch::<name>`")]
    InvalidGenesisPath(String),
    #[error("genesis authorizing input index {0} does not fit a covenant binding")]
    GenesisAuthorizingInputOverflow(usize),
    #[error("genesis output index {0} does not fit a covenant group")]
    GenesisOutputIndexOverflow(usize),
    #[error("Argent output {output_index} `{actor}` must have an existing or genesis covenant binding")]
    UnboundArgentOutput { output_index: usize, actor: String },
    #[error("genesis actor output {output_index} `{actor}` must have static state")]
    GenesisOutputStateCallback { output_index: usize, actor: String },
    #[error("failed to build state for actor output {output_index} `{actor}`: {source}")]
    OutputStateCallback {
        output_index: usize,
        actor: String,
        #[source]
        source: Box<dyn Error + Send + Sync + 'static>,
    },
    #[error("observe `{observe}` spans apps `{expected}` and `{found}`")]
    ObservedAppMismatch { observe: String, expected: String, found: String },
    #[error("unknown entry `{actor}::{entry}`")]
    UnknownEntry { actor: String, entry: String },
    #[error("Argent input {input_index} `{actor}` has no covenant id")]
    MissingArgentInputCovenantId { input_index: usize, actor: String },
    #[error("Argent input {input_index} `{actor}` UTXO script does not match its declared state")]
    ArgentInputScriptMismatch { input_index: usize, actor: String },
    #[error(
        "Argent input {input_index} `{actor}::{entry}` requires exactly {expected} same-covenant inputs, found {found}; actor is a leader actor trusted by delegates {leader_for:?}"
    )]
    LeaderActorInputCountMismatch {
        input_index: usize,
        actor: String,
        entry: String,
        expected: usize,
        found: usize,
        leader_for: Vec<String>,
    },
    #[error("failed to build arguments for Argent input {input_index} `{actor}::{entry}`: {source}")]
    EntryArgsCallback {
        input_index: usize,
        actor: String,
        entry: String,
        #[source]
        source: Box<dyn Error + Send + Sync + 'static>,
    },
    #[error("failed to build signature script for input {input_index}: {source}")]
    InputSigScriptCallback {
        input_index: usize,
        #[source]
        source: Box<dyn Error + Send + Sync + 'static>,
    },
    #[error("cannot build transition `{actor}::{entry}`: {message}")]
    InvalidTransition { actor: String, entry: String, message: String },
    #[error("input {input_index} requires {script_units} script units, which do not fit a compute budget")]
    ComputeBudgetOverflow { input_index: usize, script_units: u64 },
    #[error("input {input_index} script failed: {source}")]
    InputScript {
        input_index: usize,
        #[source]
        source: TxScriptError,
    },
    #[error("transaction has {input_count} inputs but {entry_count} UTXO entries")]
    InputEntryCountMismatch { input_count: usize, entry_count: usize },
    #[error("transaction version {found} is not supported; expected {expected}")]
    UnsupportedTransactionVersion { expected: u16, found: u16 },
    #[error("transaction compute mass {compute_mass} exceeds limit {limit}")]
    ComputeMassLimitExceeded { compute_mass: u64, limit: u64 },
    #[error("transaction transient mass {transient_mass} exceeds limit {limit}")]
    TransientMassLimitExceeded { transient_mass: u64, limit: u64 },
    #[error("transaction output {0} has no covenant binding")]
    MissingOutputCovenant(u32),
    #[error("transaction output {0} does not exist")]
    UnknownTransactionOutput(u32),
    #[error("genesis covenant output {0} does not exist")]
    UnknownGenesisOutput(u32),
}

#[derive(Clone, Debug)]
pub struct ArtifactBundle<'a> {
    primary_alias: String,
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
    pub fn output(&self, index: u32) -> BuilderResult<&CovenantOutput> {
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
    pub outputs: Vec<CovenantOutput>,
}

/// A concrete covenant output and the handles needed to spend it.
pub struct CovenantOutput {
    pub index: u32,
    pub covenant_id: Hash,
    pub outpoint: TransactionOutpoint,
    pub utxo: UtxoEntry,
}

impl CovenantOutput {
    /// Derive a covenant output and its spendable UTXO metadata from a transaction output index.
    pub fn from_tx(tx: &Transaction, index: u32) -> BuilderResult<Self> {
        let output = tx.outputs.get(index as usize).ok_or(BuilderError::UnknownTransactionOutput(index))?;
        let covenant_id = output.covenant.ok_or(BuilderError::MissingOutputCovenant(index))?.covenant_id;
        Ok(Self {
            index,
            covenant_id,
            outpoint: TransactionOutpoint::new(tx.id(), index),
            utxo: UtxoEntry::new(output.value, output.script_public_key.clone(), 0, tx.is_coinbase(), Some(covenant_id)),
        })
    }
}

#[derive(Clone, Copy)]
struct ContractRef<'a> {
    artifact: &'a Artifact,
    contract: &'a SilContractArtifact,
}

#[derive(Clone, Copy)]
struct ActorRef<'a> {
    artifact: &'a Artifact,
    actor: &'a ActorArtifact,
}

#[derive(Clone, Debug)]
struct ObservedInput {
    actor: String,
    state: BTreeMap<String, ArtifactValue>,
    utxo: UtxoEntry,
}

#[derive(Clone, Debug)]
struct ObservedOutput {
    actor: String,
    state: BTreeMap<String, ArtifactValue>,
}

#[derive(Clone, Debug)]
struct ObservedCovenantContext {
    app: String,
    inputs: BTreeMap<String, ObservedInput>,
    outputs: BTreeMap<String, ObservedOutput>,
}

#[derive(Clone, Debug)]
struct SpawnedActorContext {
    app: String,
    actor: String,
    output_index: usize,
}

#[derive(Clone, Copy)]
struct HiddenArgContexts<'a> {
    observed: Option<&'a BTreeMap<String, ObservedCovenantContext>>,
    spawned: Option<&'a BTreeMap<(String, String), SpawnedActorContext>>,
}

impl<'a> ArtifactBundle<'a> {
    pub fn new(primary: &'a Artifact) -> BuilderResult<Self> {
        let primary_alias = artifact_app_alias(&primary.app);
        Self::named(primary_alias, primary)
    }

    /// Create a bundle with an explicitly named primary app.
    pub fn named(alias: impl Into<String>, primary: &'a Artifact) -> BuilderResult<Self> {
        let alias = alias.into();
        let expected = artifact_app_alias(&primary.app);
        if alias != expected {
            return Err(BuilderError::AppAliasMismatch { app: primary.app.clone(), expected, found: alias });
        }
        validate_artifact(&alias, primary)?;
        let apps = BTreeMap::from([(alias.clone(), primary)]);
        Ok(Self { primary_alias: alias, apps })
    }

    pub fn with_app(mut self, alias: impl Into<String>, artifact: &'a Artifact) -> BuilderResult<Self> {
        let alias = alias.into();
        let expected = artifact_app_alias(&artifact.app);
        if alias != expected {
            return Err(BuilderError::AppAliasMismatch { app: artifact.app.clone(), expected, found: alias });
        }
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

    fn primary(&self) -> &'a Artifact {
        self.apps.get(&self.primary_alias).copied().expect("bundle contains its primary app")
    }

    fn primary_alias(&self) -> &str {
        &self.primary_alias
    }
}

impl<'a> TxBuilder<'a> {
    pub fn new(artifact: &'a Artifact) -> BuilderResult<Self> {
        Ok(Self { bundle: ArtifactBundle::new(artifact)? })
    }

    pub fn from_bundle(bundle: &ArtifactBundle<'a>) -> BuilderResult<Self> {
        Ok(Self { bundle: bundle.clone() })
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

    fn script_public_key_for_actor(
        &self,
        actor: ActorPath,
        source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<kaspa_consensus_core::tx::ScriptPublicKey> {
        let contract_ref = match &actor.app {
            Some(app) => self.contract_ref_in_app(app, &actor.actor)?,
            None => self.contract_ref_in_artifact(self.bundle.primary(), &actor.actor)?,
        };
        Ok(pay_to_script_hash_script(&self.redeem_script_for_contract(contract_ref, source_state)?))
    }

    /// Build an actor output before it has a covenant id.
    ///
    /// The returned output has the correct P2SH script for `actor_name(state)`
    /// and `covenant: None`, ready for `Transaction::populate_genesis_covenants`.
    pub fn genesis_output(
        &self,
        actor: impl Into<ActorPath>,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
    ) -> BuilderResult<TransactionOutput> {
        Ok(TransactionOutput::new(value, self.script_public_key_for_actor(actor.into(), source_state)?))
    }

    /// Populate genesis covenant bindings and return first-spend handles.
    ///
    /// This wraps `Transaction::populate_genesis_covenants`, finalizes the tx
    /// after mutation, and reports covenant ids, outpoints, and UTXO entries for
    /// the populated outputs.
    pub fn populate_genesis_covenants(tx: &mut Transaction, groups: &[GenesisCovenantGroup]) -> BuilderResult<GenesisCovenants> {
        tx.populate_genesis_covenants(groups)?;
        tx.finalize();

        let mut populated_groups = Vec::with_capacity(groups.len());
        for group in groups {
            let outputs = group.outputs.iter().map(|&index| CovenantOutput::from_tx(tx, index)).collect::<BuilderResult<Vec<_>>>()?;
            let covenant_id = outputs.first().ok_or(PopulateGenesisCovenantsError::EmptyOutputs)?.covenant_id;
            populated_groups.push(GenesisCovenant { authorizing_input: group.authorizing_input, covenant_id, outputs });
        }

        Ok(GenesisCovenants { groups: populated_groups })
    }

    fn resolve_hidden_args_in_artifact(
        &self,
        artifact: &'a Artifact,
        contract: &'a SilContractArtifact,
        argent_entry: &'a EntryArtifact,
        input_source_state: &BTreeMap<String, ArtifactValue>,
        template_selectors: &BTreeMap<String, String>,
        contexts: HiddenArgContexts<'_>,
    ) -> BuilderResult<Vec<ArtifactValue>> {
        let mut args = Vec::with_capacity(argent_entry.hidden_params.len());
        for hidden in &argent_entry.hidden_params {
            args.push(match &hidden.purpose {
                HiddenParamPurposeArtifact::SpawnOutputIndex => {
                    let HiddenParamSubjectArtifact::SpawnActor { spawn, handle, .. } = &hidden.subject else {
                        return Err(BuilderError::UnexpectedHiddenSubject { param: hidden.name.clone(), expected: "spawn actor" });
                    };
                    let output_index = contexts
                        .spawned
                        .and_then(|contexts| contexts.get(&(spawn.clone(), handle.clone())))
                        .ok_or_else(|| BuilderError::MissingSpawnOutput {
                            spawn: spawn.clone(),
                            handle: handle.clone(),
                            group_index: argent_entry
                                .spawns
                                .iter()
                                .find(|candidate| candidate.name == *spawn)
                                .and_then(|spawn| spawn.outputs.iter().find(|output| output.name == *handle))
                                .map(|output| output.group_index)
                                .unwrap_or_default(),
                        })?
                        .output_index;
                    ArtifactValue::Int(output_index as i64)
                }
                HiddenParamPurposeArtifact::TemplatePrefixBytes => {
                    let template = self.hidden_template(artifact, hidden, argent_entry, template_selectors, contexts)?;
                    ArtifactValue::Bytes(decode_hex(&template.prefix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplateSuffixBytes => {
                    let template = self.hidden_template(artifact, hidden, argent_entry, template_selectors, contexts)?;
                    ArtifactValue::Bytes(decode_hex(&template.suffix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplatePrefixLen => {
                    let template = self.hidden_template(artifact, hidden, argent_entry, template_selectors, contexts)?;
                    ArtifactValue::Int(decode_hex(&template.prefix_hex)?.len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateSuffixLen => {
                    let template = self.hidden_template(artifact, hidden, argent_entry, template_selectors, contexts)?;
                    ArtifactValue::Int(decode_hex(&template.suffix_hex)?.len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateHash => {
                    let template = self.hidden_template(artifact, hidden, argent_entry, template_selectors, contexts)?;
                    ArtifactValue::Bytes(decode_hex(&template.hash_hex)?)
                }
                HiddenParamPurposeArtifact::RouteTemplateLeaf => {
                    let actor = hidden_actor_subject(hidden)?;
                    ArtifactValue::Bytes(decode_hex(
                        &self.contract_ref_in_artifact(artifact, actor)?.contract.compiled.template.hash_hex,
                    )?)
                }
                HiddenParamPurposeArtifact::RouteTemplateProof => {
                    let actor = hidden_actor_subject(hidden)?;
                    let route_proof_id = hidden
                        .route_proof_id
                        .as_deref()
                        .ok_or_else(|| BuilderError::MissingHiddenRouteProof { param: hidden.name.clone() })?;
                    ArtifactValue::Bytes(self.route_template_proof_bytes_for_actor(artifact, route_proof_id, actor)?)
                }
                HiddenParamPurposeArtifact::RouteFamilyTable => {
                    let family_id = hidden_family_subject(hidden)?;
                    ArtifactValue::Bytes(self.route_family_table_bytes_in_artifact(artifact, family_id)?)
                }
                HiddenParamPurposeArtifact::RouteFamilyProof => {
                    let family_id = hidden_family_subject(hidden)?;
                    let route_proof_id = hidden
                        .route_proof_id
                        .as_deref()
                        .ok_or_else(|| BuilderError::MissingHiddenRouteProof { param: hidden.name.clone() })?;
                    ArtifactValue::Bytes(self.route_template_proof_bytes(
                        artifact,
                        route_proof_id,
                        &RouteTemplateLeafArtifact::RouteFamily {
                            family_id: family_id.to_string(),
                            proof_id: route_proof_id.to_string(),
                        },
                    )?)
                }
                HiddenParamPurposeArtifact::StateExpansionPreimage => {
                    self.state_expansion_preimage_arg(artifact, contract, hidden, input_source_state)?
                }
                HiddenParamPurposeArtifact::ObservedOutputFieldValue => self.observed_output_field_arg(hidden, contexts.observed)?,
            });
        }
        Ok(args)
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
        argent_entry: &EntryArtifact,
        user_args: Vec<ArtifactValue>,
    ) -> BuilderResult<Vec<ArtifactValue>> {
        let mut args = Vec::with_capacity(user_args.len());
        for (idx, value) in user_args.into_iter().enumerate() {
            let runtime_contract = match entry.params.get(idx) {
                Some(param) => match &param.ty {
                    TypeArtifact::Struct { name } => {
                        self.runtime_contract_for_param(artifact, contract, argent_entry, &param.name, name)?
                    }
                    _ => None,
                },
                None => None,
            };
            match (runtime_contract, value) {
                (Some(runtime_contract), ArtifactValue::Object(fields)) => {
                    args.push(ArtifactValue::Object(self.runtime_state_values(artifact, runtime_contract, fields)?));
                }
                (_, value) => args.push(value),
            }
        }
        Ok(args)
    }

    fn encode_runtime_entry_sig_script(
        &self,
        artifact: &'a Artifact,
        contract: &'a SilContractArtifact,
        entry: &'a SilEntryArtifact,
        argent_entry: &EntryArtifact,
        args: &[ArtifactValue],
    ) -> BuilderResult<Vec<u8>> {
        let mut abi = artifact.sil_abi.clone();
        let mut runtime_fields = BTreeMap::new();
        for param in &entry.params {
            let TypeArtifact::Struct { name } = &param.ty else {
                continue;
            };
            let Some(runtime_contract) = self.runtime_contract_for_param(artifact, contract, argent_entry, &param.name, name)? else {
                continue;
            };
            if name == "State" {
                continue;
            }
            let fields: Vec<_> = runtime_contract
                .runtime_state
                .fields
                .iter()
                .map(|field| silverscript_abi::FieldArtifact { name: field.name.clone(), ty: field.ty.clone() })
                .collect();
            if let Some(existing) = runtime_fields.insert(name, fields.clone())
                && existing != fields
            {
                return Err(BuilderError::RuntimeStatePlanMismatch {
                    contract: contract.name.clone(),
                    message: format!("entry `{}` uses incompatible runtime layouts for struct `{name}`", entry.name),
                });
            }
            let Some(state) = abi.states.iter_mut().find(|state| state.name == *name) else {
                continue;
            };
            state.fields = fields;
        }
        Ok(encode_entry_sig_script(&abi, contract, entry, args)?)
    }

    fn runtime_contract_for_param(
        &self,
        artifact: &'a Artifact,
        contract: &'a SilContractArtifact,
        entry: &EntryArtifact,
        param: &str,
        state: &str,
    ) -> BuilderResult<Option<&'a SilContractArtifact>> {
        if state == "State" {
            return Ok(Some(contract));
        }
        if let Some(route) = entry.routes.iter().find(|route| route.state_expr == param) {
            let routed = self.contract_in_artifact(artifact, &route.actor)?;
            if routed.runtime_state.source != state {
                return Err(BuilderError::RuntimeStatePlanMismatch {
                    contract: contract.name.clone(),
                    message: format!(
                        "entry `{}` routes parameter `{param}: {state}` to actor `{}`, which owns `{}`",
                        entry.name, route.actor, routed.runtime_state.source
                    ),
                });
            }
            return Ok(Some(routed));
        }

        let mut candidates = artifact.sil_abi.contracts.iter().filter(|candidate| candidate.runtime_state.source == state);
        let Some(first) = candidates.next() else {
            return Ok(None);
        };
        if candidates.any(|candidate| candidate.runtime_state.fields != first.runtime_state.fields) {
            return Err(BuilderError::RuntimeStatePlanMismatch {
                contract: contract.name.clone(),
                message: format!(
                    "entry `{}` parameter `{param}: {state}` has no route and matches multiple runtime layouts",
                    entry.name
                ),
            });
        }
        Ok(Some(first))
    }

    pub fn covenant_utxo(
        &self,
        actor: impl Into<ActorPath>,
        source_state: BTreeMap<String, ArtifactValue>,
        value: u64,
        block_daa_score: u64,
        is_coinbase: bool,
        covenant_id: Option<Hash>,
    ) -> BuilderResult<UtxoEntry> {
        Ok(UtxoEntry::new(
            value,
            self.script_public_key_for_actor(actor.into(), source_state)?,
            block_daa_score,
            is_coinbase,
            covenant_id,
        ))
    }

    pub fn transaction_input(previous_outpoint: TransactionOutpoint, signature_script: Vec<u8>) -> TransactionInput {
        TransactionInput::new_with_compute_budget(previous_outpoint, signature_script, 0, 0)
    }

    pub fn transaction(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
        Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![])
    }

    /// Return the template handle by which an external app observes `actor` as
    /// `actor_type<state>`.
    pub fn actor_type_handle(&self, actor: impl Into<ActorPath>, state: &str) -> BuilderResult<Vec<u8>> {
        let actor = actor.into();
        let artifact = match &actor.app {
            Some(app) => self.bundle.app(app)?,
            None => self.bundle.primary(),
        };
        self.actor_type_handle_in_artifact(artifact, &actor.actor, state)
    }

    fn actor_type_handle_in_artifact(&self, artifact: &'a Artifact, actor: &str, state: &str) -> BuilderResult<Vec<u8>> {
        let contract = self.contract_in_artifact(artifact, actor)?;
        let expanded_base = artifact
            .argent
            .state_expansions
            .iter()
            .find(|expansion| expansion.state == contract.runtime_state.source)
            .map(|expansion| expansion.base.as_str());
        if expanded_base.is_none() && contract.runtime_state.source == state {
            return Ok(decode_hex(&contract.compiled.template.hash_hex)?);
        }
        let handle = artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == actor)
            .and_then(|template| template.actor_type_handle.as_ref())
            .filter(|handle| handle.state == state)
            .ok_or_else(|| BuilderError::MissingActorTypeHandle { actor: actor.to_string(), state: state.to_string() })?;
        Ok(decode_hex(&handle.template.hash_hex)?)
    }

    fn validate_actor_interface(&self, observing_artifact: &Artifact, app: &str, actor: &str) -> BuilderResult<()> {
        let artifact = self.bundle.app(app)?;
        let observing_app = artifact_app_alias(&observing_artifact.app);
        let expected = find_interface(&observing_artifact.argent.interfaces.imports, actor)
            .ok_or_else(|| BuilderError::MissingInterface { app: observing_app, direction: "import", actor: actor.to_string() })?;
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

    fn observed_contract_ref(
        &self,
        observing_artifact: &'a Artifact,
        observe: &str,
        contract: &str,
    ) -> BuilderResult<ContractRef<'a>> {
        let mut contract_apps = Vec::new();
        let mut valid_apps = Vec::new();
        let mut first_interface_error = None;
        for (app, artifact) in &self.bundle.apps {
            let app = app.as_str();
            let artifact = *artifact;
            if std::ptr::eq(artifact, observing_artifact) {
                continue;
            }
            if artifact.sil_abi.contract(contract).is_some() {
                contract_apps.push(app.to_string());
                match self.validate_actor_interface(observing_artifact, app, contract) {
                    Ok(()) => valid_apps.push(app.to_string()),
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

    fn contract_in_artifact(&self, artifact: &'a Artifact, name: &str) -> BuilderResult<&'a SilContractArtifact> {
        artifact.sil_abi.contract(name).ok_or_else(|| BuilderError::UnknownActor(name.to_string()))
    }

    fn contract_ref_in_artifact(&self, artifact: &'a Artifact, name: &str) -> BuilderResult<ContractRef<'a>> {
        let contract = self.contract_in_artifact(artifact, name)?;
        Ok(ContractRef { artifact, contract })
    }

    fn contract_ref_in_app(&self, app: &str, name: &str) -> BuilderResult<ContractRef<'a>> {
        self.contract_ref_in_artifact(self.bundle.app(app)?, name)
    }

    fn hidden_template(
        &self,
        primary_artifact: &'a Artifact,
        hidden: &HiddenParamArtifact,
        entry: &'a EntryArtifact,
        template_selectors: &BTreeMap<String, String>,
        contexts: HiddenArgContexts<'_>,
    ) -> BuilderResult<&'a CompiledTemplateArtifact> {
        let contract_ref = self.hidden_template_contract_ref(primary_artifact, hidden, entry, template_selectors, contexts)?;
        let open_state = match &hidden.subject {
            HiddenParamSubjectArtifact::ObservedActor { observe, side, handle, .. } => {
                self.observed_actor(entry, observe, *side, handle)?.open_state.as_deref()
            }
            HiddenParamSubjectArtifact::SpawnActor { spawn, handle, .. } => entry
                .spawns
                .iter()
                .find(|candidate| candidate.name == *spawn)
                .and_then(|spawn| spawn.outputs.iter().find(|output| output.name == *handle))
                .map(|output| output.state.as_str()),
            _ => None,
        };
        let Some(open_state) = open_state else {
            return Ok(&contract_ref.contract.compiled.template);
        };
        let expanded_base = contract_ref
            .artifact
            .argent
            .state_expansions
            .iter()
            .find(|expansion| expansion.state == contract_ref.contract.runtime_state.source)
            .map(|expansion| expansion.base.as_str());
        if expanded_base.is_none() && contract_ref.contract.runtime_state.source == open_state {
            return Ok(&contract_ref.contract.compiled.template);
        }
        let template = contract_ref
            .artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == contract_ref.contract.name)
            .and_then(|template| template.actor_type_handle.as_ref())
            .filter(|handle| handle.state == open_state)
            .ok_or_else(|| BuilderError::MissingActorTypeHandle {
                actor: contract_ref.contract.name.clone(),
                state: open_state.to_string(),
            })?;
        Ok(&template.template)
    }

    fn hidden_template_contract_ref(
        &self,
        primary_artifact: &'a Artifact,
        hidden: &HiddenParamArtifact,
        entry: &'a EntryArtifact,
        template_selectors: &BTreeMap<String, String>,
        contexts: HiddenArgContexts<'_>,
    ) -> BuilderResult<ContractRef<'a>> {
        match &hidden.subject {
            HiddenParamSubjectArtifact::Actor { actor } => self.contract_ref_in_artifact(primary_artifact, actor),
            HiddenParamSubjectArtifact::ObservedActor { observe, side, handle, actor } => {
                match contexts.observed.and_then(|contexts| contexts.get(observe)) {
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
                        self.observed_contract_ref(primary_artifact, observe, &observed_actor.actor)
                    }
                }
            }
            HiddenParamSubjectArtifact::SpawnActor { spawn, handle, .. } => {
                let context =
                    contexts.spawned.and_then(|contexts| contexts.get(&(spawn.clone(), handle.clone()))).ok_or_else(|| {
                        BuilderError::MissingSpawnOutput {
                            spawn: spawn.clone(),
                            handle: handle.clone(),
                            group_index: entry
                                .spawns
                                .iter()
                                .find(|candidate| candidate.name == *spawn)
                                .and_then(|spawn| spawn.outputs.iter().find(|output| output.name == *handle))
                                .map(|output| output.group_index)
                                .unwrap_or_default(),
                        }
                    })?;
                self.contract_ref_in_app(&context.app, &context.actor)
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

    fn argent_actor_ref_in_artifact(&self, artifact: &'a Artifact, name: &str) -> BuilderResult<ActorRef<'a>> {
        artifact
            .argent
            .actors
            .iter()
            .find(|actor| actor.name == name)
            .map(|actor| ActorRef { artifact, actor })
            .ok_or_else(|| BuilderError::UnknownActor(name.to_string()))
    }

    fn entry_ref_for_actor(&self, actor_ref: ActorRef<'a>, actor_name: &str, entry_name: &str) -> BuilderResult<&'a EntryArtifact> {
        actor_ref
            .actor
            .entries
            .iter()
            .find(|entry| entry.name == entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })
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
            side: side.into(),
            handle: handle.to_string(),
        })
    }

    fn validate_observed_contexts(
        &self,
        observing_artifact: &'a Artifact,
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
            self.validate_observed_covenant(observing_artifact, &observe.name, observe, context)?;
        }
        Ok(())
    }

    fn validate_observed_covenant(
        &self,
        observing_artifact: &'a Artifact,
        observe_name: &str,
        observe: &ObserveArtifact,
        context: &ObservedCovenantContext,
    ) -> BuilderResult<()> {
        self.bundle.app(&context.app)?;
        self.validate_observed_inputs(observing_artifact, observe_name, &observe.inputs, context)?;
        self.validate_observed_outputs(observing_artifact, observe_name, &observe.outputs, context)
    }

    fn validate_observed_inputs(
        &self,
        observing_artifact: &'a Artifact,
        observe_name: &str,
        expected: &[ObservedActorArtifact],
        context: &ObservedCovenantContext,
    ) -> BuilderResult<()> {
        for handle in context.inputs.keys() {
            if expected.iter().all(|input| &input.name != handle) {
                return Err(BuilderError::UnknownObservedActor {
                    observe: observe_name.to_string(),
                    side: Side::In,
                    handle: handle.clone(),
                });
            }
        }
        for input in expected {
            let observed = context.inputs.get(&input.name).ok_or_else(|| BuilderError::MissingObservedActor {
                observe: observe_name.to_string(),
                side: Side::In,
                handle: input.name.clone(),
            })?;
            self.validate_observed_actor(
                observing_artifact,
                &context.app,
                observe_name,
                ObservedActorSideArtifact::Input,
                input,
                &observed.actor,
            )?;
            let contract_ref = self.contract_ref_in_app(&context.app, &observed.actor)?;
            let expected_script_public_key =
                pay_to_script_hash_script(&self.redeem_script_for_contract(contract_ref, observed.state.clone())?);
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
        observing_artifact: &'a Artifact,
        observe_name: &str,
        expected: &[ObservedActorArtifact],
        context: &ObservedCovenantContext,
    ) -> BuilderResult<()> {
        for handle in context.outputs.keys() {
            if expected.iter().all(|output| &output.name != handle) {
                return Err(BuilderError::UnknownObservedActor {
                    observe: observe_name.to_string(),
                    side: Side::Out,
                    handle: handle.clone(),
                });
            }
        }
        for output in expected {
            let observed = context.outputs.get(&output.name).ok_or_else(|| BuilderError::MissingObservedActor {
                observe: observe_name.to_string(),
                side: Side::Out,
                handle: output.name.clone(),
            })?;
            self.validate_observed_actor(
                observing_artifact,
                &context.app,
                observe_name,
                ObservedActorSideArtifact::Output,
                output,
                &observed.actor,
            )?;
            let contract_ref = self.contract_ref_in_app(&context.app, &observed.actor)?;
            self.redeem_script_for_contract(contract_ref, observed.state.clone())?;
        }
        Ok(())
    }

    fn validate_observed_actor(
        &self,
        observing_artifact: &'a Artifact,
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
                    side: side.into(),
                    handle: expected.name.clone(),
                    actor: found_actor.to_string(),
                    state: expected_state.to_string(),
                });
            }
            let expected_layout = state_artifact(observing_artifact, expected_state)?;
            let found_layout = state_artifact(found.artifact, &found.actor.state)?;
            if expected_layout.fields != found_layout.fields {
                return Err(BuilderError::ObservedStateLayoutMismatch {
                    observe: observe_name.to_string(),
                    side: side.into(),
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
                side: side.into(),
                handle: expected.name.clone(),
                expected: expected.actor.clone(),
                found: found_actor.to_string(),
            });
        }
        self.validate_actor_interface(observing_artifact, app, &expected.actor)?;
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
                if role_by_field.insert(field_role.name.as_str(), field_role).is_some() {
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
                Some(field_role) => {
                    if source_state.contains_key(&field.name) {
                        return Err(BuilderError::HiddenRuntimeFieldProvided {
                            contract: contract.name.clone(),
                            field: field.name.clone(),
                        });
                    }
                    match &field_role.role {
                        RuntimeFieldRoleArtifact::ObservedTemplate { observe, contract, .. } => {
                            values.insert(
                                field.name.clone(),
                                ArtifactValue::Bytes(decode_hex(
                                    &self.observed_contract_ref(artifact, observe, contract)?.contract.compiled.template.hash_hex,
                                )?),
                            );
                        }
                        RuntimeFieldRoleArtifact::Template { .. }
                        | RuntimeFieldRoleArtifact::TemplateTable { .. }
                        | RuntimeFieldRoleArtifact::TemplateDigest { .. }
                        | RuntimeFieldRoleArtifact::TemplateRoot { .. } => {
                            let runtime_plan = self
                                .runtime_state_plan(artifact, &contract.name)
                                .expect("generated field roles come from a runtime state plan");
                            values.insert(
                                field.name.clone(),
                                ArtifactValue::Bytes(fixed_runtime_context_value(
                                    &artifact.argent.template_plan,
                                    runtime_plan,
                                    field_role,
                                )?),
                            );
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
            side: Side::Out,
            handle: handle.clone(),
        })?;
        let contract_ref = self.contract_ref_in_app(&context.app, &output.actor)?;
        if !state_satisfies(contract_ref.artifact, &contract_ref.contract.runtime_state.source, state) {
            return Err(BuilderError::ObservedStateLayoutMismatch {
                observe: observe.clone(),
                side: Side::Out,
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
        HiddenParamSubjectArtifact::SpawnActor { actor, .. } => Ok(actor.as_str()),
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
        | HiddenParamSubjectArtifact::SpawnActor { .. }
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
        HiddenParamSubjectArtifact::SpawnActor { actor, .. } => Ok(actor.clone()),
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
    let sig_cache = Cache::new(100);
    let populated = PopulatedTransaction::new(tx, entries);
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
    measure_input_script_units_with_covenants(&populated, input_idx, &sig_cache, &reused_values, &cov_ctx).map(|_| ())
}

/// Execute every covenant input, commit its measured compute budget, and check
/// the finalized transaction against the consensus non-contextual mass limits.
pub fn execute_transaction_with_covenants(tx: &mut Transaction, entries: Vec<UtxoEntry>) -> BuilderResult<()> {
    if tx.version != TX_VERSION_TOCCATA {
        return Err(BuilderError::UnsupportedTransactionVersion { expected: TX_VERSION_TOCCATA, found: tx.version });
    }
    if tx.inputs.len() != entries.len() {
        return Err(BuilderError::InputEntryCountMismatch { input_count: tx.inputs.len(), entry_count: entries.len() });
    }

    let used_script_units = {
        let reused_values = SigHashReusedValuesUnsync::new();
        let sig_cache = Cache::new(100);
        let populated = PopulatedTransaction::new(tx, entries);
        let cov_ctx = CovenantsContext::from_tx(&populated).map_err(TxScriptError::from)?;
        let mut used_script_units = Vec::with_capacity(tx.inputs.len());
        for input_index in 0..tx.inputs.len() {
            let script_units =
                measure_input_script_units_with_covenants(&populated, input_index, &sig_cache, &reused_values, &cov_ctx)
                    .map_err(|source| BuilderError::InputScript { input_index, source })?;
            used_script_units.push(script_units);
        }
        used_script_units
    };

    for (input_idx, script_units) in used_script_units.into_iter().enumerate() {
        let compute_budget = ComputeBudget::checked_covering_script_units(script_units)
            .ok_or(BuilderError::ComputeBudgetOverflow { input_index: input_idx, script_units: script_units.0 })?;
        tx.inputs[input_idx].compute_commit = compute_budget.into();
    }

    let mass_calculator = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    let masses = mass_calculator.calc_non_contextual_masses(tx);
    let limits = MAINNET_PARAMS.block_mass_limits().after();
    if masses.compute_mass > limits.compute {
        return Err(BuilderError::ComputeMassLimitExceeded { compute_mass: masses.compute_mass, limit: limits.compute });
    }
    if masses.transient_mass > limits.transient {
        return Err(BuilderError::TransientMassLimitExceeded { transient_mass: masses.transient_mass, limit: limits.transient });
    }
    Ok(())
}

fn measure_input_script_units_with_covenants(
    populated: &PopulatedTransaction<'_>,
    input_idx: usize,
    sig_cache: &Cache<SigCacheKey, bool>,
    reused_values: &SigHashReusedValuesUnsync,
    cov_ctx: &CovenantsContext,
) -> Result<ScriptUnits, TxScriptError> {
    let input = populated.tx.inputs[input_idx].clone();
    let utxo = populated.utxo(input_idx).expect("selected input utxo");

    let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
        populated,
        &input,
        input_idx,
        utxo,
        EngineCtx::new(sig_cache).with_reused(reused_values).with_covenants_ctx(cov_ctx),
        covenant_engine_flags(),
        ScriptUnits(u64::MAX),
    );
    vm.execute()?;
    Ok(vm.used_script_units())
}

pub fn covenant_engine_flags() -> EngineFlags {
    EngineFlags { covenants_enabled: true, ..Default::default() }
}

#[cfg(test)]
mod tests {
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId};
    use kaspa_txscript::opcodes::codes::OpFalse;

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
    fn transaction_execution_reports_the_failing_input_index() {
        let outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x33; 32]), 0);
        let input = TransactionInput::new_with_compute_budget(outpoint, Vec::new(), 0, 0);
        let mut transaction = Transaction::new(TX_VERSION_TOCCATA, vec![input], Vec::new(), 0, Default::default(), 0, Vec::new());
        let utxo = UtxoEntry::new(1_000, ScriptPublicKey::new(0, vec![OpFalse].into()), 0, false, None);

        let error = execute_transaction_with_covenants(&mut transaction, vec![utxo]).expect_err("false script fails");
        assert!(matches!(error, BuilderError::InputScript { input_index: 0, .. }));
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
        let direct_output_0 = CovenantOutput::from_tx(&tx, 0).expect("covenant output derives directly from transaction");
        assert_eq!(direct_output_0.covenant_id, output_0.covenant_id);
        assert_eq!(direct_output_0.outpoint, output_0.outpoint);
        assert_eq!(direct_output_0.utxo, output_0.utxo);

        let output_1 = genesis.output(1).expect("output 1 handle exists");
        let output_3 = genesis.output(3).expect("output 3 handle exists");
        assert_eq!(output_1.covenant_id, genesis.groups[1].covenant_id);
        assert_eq!(output_3.covenant_id, genesis.groups[1].covenant_id);
        assert_eq!(tx.outputs[1].covenant.expect("output 1 covenant").covenant_id, output_1.covenant_id);
        assert!(matches!(genesis.output(99), Err(BuilderError::UnknownGenesisOutput(99))));
        assert!(matches!(CovenantOutput::from_tx(&tx, 99), Err(BuilderError::UnknownTransactionOutput(99))));

        let unbound_tx = TxBuilder::transaction(Vec::new(), vec![TransactionOutput::new(1_000, Default::default())]);
        assert!(matches!(CovenantOutput::from_tx(&unbound_tx, 0), Err(BuilderError::MissingOutputCovenant(0))));
    }
}
