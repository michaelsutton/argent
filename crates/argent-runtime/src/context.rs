use std::{collections::BTreeMap, error::Error, fmt};

use kaspa_consensus_core::{
    subnets::SubnetworkId,
    tx::{CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry},
};

use crate::{ArgValue, ArtifactValue, BuilderError, BuilderResult};

/// An actor in the primary app or in a named attached app.
///
/// String conversions accept either `Actor` or `app::Actor`. The builder
/// validates the path against its artifact bundle when it resolves the
/// transaction context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPath {
    pub app: Option<String>,
    pub actor: String,
}

impl ActorPath {
    /// Refer to an actor in the primary app.
    pub fn primary(actor: impl Into<String>) -> Self {
        Self { app: None, actor: actor.into() }
    }

    /// Refer to an actor with an explicit app qualifier.
    pub fn qualified(app: impl Into<String>, actor: impl Into<String>) -> Self {
        Self { app: Some(app.into()), actor: actor.into() }
    }
}

impl From<&str> for ActorPath {
    fn from(path: &str) -> Self {
        match path.split_once("::") {
            Some((app, actor)) => Self::qualified(app, actor),
            None => Self::primary(path),
        }
    }
}

impl From<String> for ActorPath {
    fn from(path: String) -> Self {
        Self::from(path.as_str())
    }
}

impl fmt::Display for ActorPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(app) = &self.app { write!(formatter, "{app}::{}", self.actor) } else { formatter.write_str(&self.actor) }
    }
}

type CallbackError = Box<dyn Error + Send + Sync + 'static>;
type EntryArgsCallback<'a> = dyn Fn(&MutableTransaction<Transaction>, usize) -> Result<Vec<ArgValue>, CallbackError> + 'a;
pub(crate) type OutputStateCallback<'a> = dyn Fn(&StateContext) -> Result<BTreeMap<String, ArtifactValue>, CallbackError> + 'a;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GenesisPath {
    Launch(String),
    Spawn(String),
}

impl GenesisPath {
    fn parse(path: &str) -> BuilderResult<Self> {
        let Some((kind, name)) = path.split_once("::") else {
            return Err(BuilderError::InvalidGenesisPath(path.to_string()));
        };
        if name.is_empty() || name.contains("::") {
            return Err(BuilderError::InvalidGenesisPath(path.to_string()));
        }
        match kind {
            "launch" => Ok(Self::Launch(name.to_string())),
            "spawns" => Ok(Self::Spawn(name.to_string())),
            _ => Err(BuilderError::InvalidGenesisPath(path.to_string())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GenesisGroupKey {
    pub authorizing_input: usize,
    pub path: GenesisPath,
}

impl GenesisGroupKey {
    pub fn parse(authorizing_input: usize, path: &str) -> BuilderResult<Self> {
        Ok(Self { authorizing_input, path: GenesisPath::parse(path)? })
    }
}

/// Builder-resolved values available while constructing deferred output state.
///
/// The context is populated after every declared genesis group has been
/// assigned its covenant ID and before the final unsigned transaction is
/// materialized.
pub struct StateContext {
    genesis_covenant_ids: BTreeMap<GenesisGroupKey, kaspa_consensus_core::Hash>,
}

impl StateContext {
    pub(crate) fn new(genesis_covenant_ids: BTreeMap<GenesisGroupKey, kaspa_consensus_core::Hash>) -> Self {
        Self { genesis_covenant_ids }
    }

    /// Return the covenant ID assigned to a declared genesis group.
    pub fn covenant_id(&self, authorizing_input: usize, genesis: impl AsRef<str>) -> BuilderResult<kaspa_consensus_core::Hash> {
        let key = GenesisGroupKey::parse(authorizing_input, genesis.as_ref())?;
        self.genesis_covenant_ids
            .get(&key)
            .copied()
            .ok_or_else(|| BuilderError::UnknownGenesisGroup { authorizing_input, genesis: genesis.as_ref().to_string() })
    }
}

/// State for an Argent continuation output.
pub enum OutputState<'a> {
    /// State known when the transaction context is declared.
    Static(BTreeMap<String, ArtifactValue>),
    /// State computed after genesis covenant IDs have been resolved.
    WithContext(Box<OutputStateCallback<'a>>),
}

impl fmt::Debug for OutputState<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(state) => formatter.debug_tuple("Static").field(state).finish(),
            Self::WithContext(_) => formatter.write_str("WithContext(<callback>)"),
        }
    }
}

impl<'a> From<BTreeMap<String, ArtifactValue>> for OutputState<'a> {
    fn from(state: BTreeMap<String, ArtifactValue>) -> Self {
        Self::Static(state)
    }
}

/// Defer continuation state until genesis covenant IDs have been resolved.
pub fn state_with<'a>(build: impl Fn(&StateContext) -> BuilderResult<BTreeMap<String, ArtifactValue>> + 'a) -> OutputState<'a> {
    OutputState::WithContext(Box::new(move |context| build(context).map_err(|error| Box::new(error) as CallbackError)))
}

/// User arguments for an Argent entry call.
pub enum EntryArgs<'a> {
    /// Arguments that are known before the transaction is assembled.
    Static(Vec<ArgValue>),
    /// Arguments, such as signatures, derived from the unsigned transaction.
    WithTransaction(Box<EntryArgsCallback<'a>>),
}

impl fmt::Debug for EntryArgs<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(args) => formatter.debug_tuple("Static").field(args).finish(),
            Self::WithTransaction(_) => formatter.write_str("WithTransaction(<callback>)"),
        }
    }
}

/// An Argent entry name and its user-visible arguments.
#[derive(Debug)]
pub struct EntryCall<'a> {
    pub name: String,
    pub args: EntryArgs<'a>,
}

impl<'a> EntryCall<'a> {
    /// Call an entry without user arguments.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), args: EntryArgs::Static(Vec::new()) }
    }

    /// Supply arguments that do not depend on the transaction.
    pub fn args(mut self, args: Vec<ArgValue>) -> Self {
        self.args = EntryArgs::Static(args);
        self
    }

    /// Build arguments from the unsigned transaction and this input's index.
    pub fn args_with(mut self, build: impl Fn(&MutableTransaction<Transaction>, usize) -> Vec<ArgValue> + 'a) -> Self {
        self.args = EntryArgs::WithTransaction(Box::new(move |tx, input_index| Ok(build(tx, input_index))));
        self
    }

    /// Fallibly build arguments from the unsigned transaction and this input's index.
    pub fn try_args_with<E>(mut self, build: impl Fn(&MutableTransaction<Transaction>, usize) -> Result<Vec<ArgValue>, E> + 'a) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        self.args = EntryArgs::WithTransaction(Box::new(move |tx, input_index| {
            build(tx, input_index).map_err(|error| Box::new(error) as CallbackError)
        }));
        self
    }
}

impl<'a> From<&str> for EntryCall<'a> {
    fn from(name: &str) -> Self {
        Self::new(name)
    }
}

impl<'a> From<String> for EntryCall<'a> {
    fn from(name: String) -> Self {
        Self::new(name)
    }
}

type InputSigScriptCallback<'a> = dyn Fn(&MutableTransaction<Transaction>, usize) -> Result<Vec<u8>, CallbackError> + 'a;

/// Signature script supplied for a non-Argent input.
pub enum InputSigScript<'a> {
    /// A complete signature script known before transaction assembly.
    Static(Vec<u8>),
    /// A signature script derived from the unsigned transaction.
    WithTransaction(Box<InputSigScriptCallback<'a>>),
}

impl<'a> InputSigScript<'a> {
    /// Build a signature script from the unsigned transaction and input index.
    pub fn with_transaction(build: impl Fn(&MutableTransaction<Transaction>, usize) -> Vec<u8> + 'a) -> Self {
        Self::WithTransaction(Box::new(move |tx, input_index| Ok(build(tx, input_index))))
    }

    /// Fallibly build a signature script from the unsigned transaction and input index.
    pub fn try_with_transaction<E>(build: impl Fn(&MutableTransaction<Transaction>, usize) -> Result<Vec<u8>, E> + 'a) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::WithTransaction(Box::new(move |tx, input_index| {
            build(tx, input_index).map_err(|error| Box::new(error) as CallbackError)
        }))
    }
}

impl fmt::Debug for InputSigScript<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(script) => formatter.debug_tuple("Static").field(script).finish(),
            Self::WithTransaction(_) => formatter.write_str("WithTransaction(<callback>)"),
        }
    }
}

impl<'a> From<Vec<u8>> for InputSigScript<'a> {
    fn from(script: Vec<u8>) -> Self {
        Self::Static(script)
    }
}

/// One Argent covenant input in a transaction context.
#[derive(Debug)]
pub struct ArgentInput<'a> {
    pub actor: ActorPath,
    pub state: BTreeMap<String, ArtifactValue>,
    pub entry: EntryCall<'a>,
    pub outpoint: TransactionOutpoint,
    pub utxo: UtxoEntry,
    pub sequence: u64,
}

/// One non-Argent input in a transaction context.
#[derive(Debug)]
pub struct OrdinaryInput<'a> {
    pub outpoint: TransactionOutpoint,
    pub utxo: UtxoEntry,
    pub signature_script: InputSigScript<'a>,
    pub sequence: u64,
}

/// An ordered input in a transaction context.
#[derive(Debug)]
pub enum ContextInput<'a> {
    Argent(ArgentInput<'a>),
    Ordinary(OrdinaryInput<'a>),
}

/// One Argent covenant output in a transaction context.
#[derive(Debug)]
pub struct ArgentOutput<'a> {
    pub actor: ActorPath,
    pub state: OutputState<'a>,
    pub covenant: CovenantBinding,
    pub value: u64,
}

/// One Argent actor output belonging to a newly created covenant group.
#[derive(Clone, Debug)]
pub struct GenesisArgentOutput {
    pub authorizing_input: usize,
    pub genesis: String,
    pub actor: ActorPath,
    pub state: BTreeMap<String, ArtifactValue>,
    pub value: u64,
}

/// One non-Argent output in a transaction context.
#[derive(Clone, Debug)]
pub struct OrdinaryOutput {
    pub script_public_key: ScriptPublicKey,
    pub covenant: Option<CovenantBinding>,
    pub value: u64,
}

/// An ordered output in a transaction context.
#[derive(Debug)]
pub enum ContextOutput<'a> {
    Argent(ArgentOutput<'a>),
    GenesisArgent(GenesisArgentOutput),
    Ordinary(OrdinaryOutput),
}

/// Artifact-independent description of one complete transaction.
///
/// Inputs and outputs appear in transaction order. The context records only
/// transaction metadata; a [`crate::TxBuilder`] later resolves actor paths,
/// genesis bindings, deferred continuation state, and Argent-generated scripts
/// from its artifact bundle.
/// Callers provide only user-visible entry arguments and signature callbacks;
/// the builder derives compiler-generated witness material from the context
/// and artifact bundle.
///
/// Transaction-wide metadata defaults to lock time zero, the native lane with
/// zero gas, and an empty payload. Each input sequence is explicit.
#[derive(Debug, Default)]
pub struct TxContext<'a> {
    pub inputs: Vec<ContextInput<'a>>,
    pub outputs: Vec<ContextOutput<'a>>,
    pub lock_time: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: Vec<u8>,
}

impl<'a> TxContext<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the transaction lock time.
    pub fn lock_time(mut self, lock_time: u64) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Set the transaction lane and its gas value together.
    pub fn lane(mut self, id: SubnetworkId, gas: u64) -> Self {
        self.subnetwork_id = id;
        self.gas = gas;
        self
    }

    /// Set the transaction payload.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Append an Argent covenant input.
    pub fn argent_input(
        mut self,
        actor: impl Into<ActorPath>,
        state: BTreeMap<String, ArtifactValue>,
        entry: impl Into<EntryCall<'a>>,
        outpoint: TransactionOutpoint,
        utxo: UtxoEntry,
        sequence: u64,
    ) -> Self {
        self.inputs.push(ContextInput::Argent(ArgentInput {
            actor: actor.into(),
            state,
            entry: entry.into(),
            outpoint,
            utxo,
            sequence,
        }));
        self
    }

    /// Append a non-Argent input.
    pub fn input(
        mut self,
        outpoint: TransactionOutpoint,
        utxo: UtxoEntry,
        signature_script: impl Into<InputSigScript<'a>>,
        sequence: u64,
    ) -> Self {
        self.inputs.push(ContextInput::Ordinary(OrdinaryInput {
            outpoint,
            utxo,
            signature_script: signature_script.into(),
            sequence,
        }));
        self
    }

    /// Append an Argent covenant output.
    pub fn argent_output(
        mut self,
        actor: impl Into<ActorPath>,
        state: impl Into<OutputState<'a>>,
        covenant: CovenantBinding,
        value: u64,
    ) -> Self {
        self.outputs.push(ContextOutput::Argent(ArgentOutput { actor: actor.into(), state: state.into(), covenant, value }));
        self
    }

    /// Append a statically defined Argent output to a genesis covenant group.
    ///
    /// `genesis` is either `launch::<local_name>` or
    /// `spawns::<clause_name>`. Repeating the same path and authorizing input
    /// places several outputs in one ordered genesis group.
    pub fn genesis_output(
        mut self,
        authorizing_input: usize,
        genesis: impl Into<String>,
        actor: impl Into<ActorPath>,
        state: BTreeMap<String, ArtifactValue>,
        value: u64,
    ) -> Self {
        self.outputs.push(ContextOutput::GenesisArgent(GenesisArgentOutput {
            authorizing_input,
            genesis: genesis.into(),
            actor: actor.into(),
            state,
            value,
        }));
        self
    }

    /// Append a non-Argent output.
    pub fn output(mut self, script_public_key: ScriptPublicKey, covenant: Option<CovenantBinding>, value: u64) -> Self {
        self.outputs.push(ContextOutput::Ordinary(OrdinaryOutput { script_public_key, covenant, value }));
        self
    }
}

#[cfg(test)]
mod tests {
    use kaspa_consensus_core::{Hash, tx::TransactionId};

    use super::*;

    fn outpoint(byte: u8) -> TransactionOutpoint {
        TransactionOutpoint::new(TransactionId::from_bytes([byte; 32]), 0)
    }

    fn utxo(covenant_id: Option<Hash>) -> UtxoEntry {
        UtxoEntry::new(1_000, ScriptPublicKey::default(), 0, false, covenant_id)
    }

    #[test]
    fn actor_path_accepts_primary_and_qualified_actors() {
        assert_eq!(ActorPath::from("Counter"), ActorPath::primary("Counter"));
        assert_eq!(ActorPath::from("asset::Reserve"), ActorPath::qualified("asset", "Reserve"));
        assert_eq!(ActorPath::qualified("asset", "Reserve").to_string(), "asset::Reserve");
    }

    #[test]
    fn context_preserves_input_and_output_call_order() {
        let covenant_id = Hash::from_bytes([0x42; 32]);
        let binding = CovenantBinding::new(0, covenant_id);
        let context = TxContext::new()
            .argent_input(
                "Counter",
                BTreeMap::from([("count".to_string(), ArtifactValue::Int(2))]),
                EntryCall::new("bump").args(vec![ArgValue::Value(ArtifactValue::Int(3))]),
                outpoint(1),
                utxo(Some(covenant_id)),
                3,
            )
            .input(outpoint(2), utxo(None), vec![0xaa], 4)
            .argent_output("Counter", BTreeMap::from([("count".to_string(), ArtifactValue::Int(5))]), binding, 900)
            .output(ScriptPublicKey::default(), None, 100)
            .lock_time(5)
            .lane(SubnetworkId::from_namespace([1, 2, 3, 4]), 6)
            .payload([0xaa, 0xbb]);

        assert!(
            matches!(&context.inputs[0], ContextInput::Argent(input) if input.actor == ActorPath::primary("Counter") && input.sequence == 3)
        );
        assert!(
            matches!(&context.inputs[1], ContextInput::Ordinary(input) if input.sequence == 4 && matches!(input.signature_script, InputSigScript::Static(ref script) if script == &[0xaa]))
        );
        assert!(matches!(&context.outputs[0], ContextOutput::Argent(output) if output.covenant == binding));
        assert!(matches!(&context.outputs[1], ContextOutput::Ordinary(output) if output.value == 100));
        assert_eq!(context.lock_time, 5);
        assert_eq!(context.subnetwork_id, SubnetworkId::from_namespace([1, 2, 3, 4]));
        assert_eq!(context.gas, 6);
        assert_eq!(context.payload, [0xaa, 0xbb]);
    }

    #[test]
    fn entry_call_and_input_script_accept_transaction_callbacks() {
        let entry = EntryCall::new("spend").args_with(|_, input_index| vec![ArgValue::Value(ArtifactValue::Int(input_index as i64))]);
        let script = InputSigScript::with_transaction(|_, input_index| vec![input_index as u8]);

        assert!(matches!(entry.args, EntryArgs::WithTransaction(_)));
        assert!(matches!(script, InputSigScript::WithTransaction(_)));
    }
}
