use std::{collections::BTreeMap, fmt};

use kaspa_consensus_core::tx::{CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionOutpoint, UtxoEntry};

use crate::{ArgValue, ArtifactValue};

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

type EntryArgsCallback<'a> = dyn Fn(&MutableTransaction<Transaction>, usize) -> Vec<ArgValue> + 'a;

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
        self.args = EntryArgs::WithTransaction(Box::new(build));
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

type InputSigScriptCallback<'a> = dyn Fn(&MutableTransaction<Transaction>, usize) -> Vec<u8> + 'a;

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
        Self::WithTransaction(Box::new(build))
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
}

/// One non-Argent input in a transaction context.
#[derive(Debug)]
pub struct OrdinaryInput<'a> {
    pub outpoint: TransactionOutpoint,
    pub utxo: UtxoEntry,
    pub signature_script: InputSigScript<'a>,
}

/// An ordered input in a transaction context.
#[derive(Debug)]
pub enum ContextInput<'a> {
    Argent(ArgentInput<'a>),
    Ordinary(OrdinaryInput<'a>),
}

/// One Argent covenant output in a transaction context.
#[derive(Clone, Debug)]
pub struct ArgentOutput {
    pub actor: ActorPath,
    pub state: BTreeMap<String, ArtifactValue>,
    pub covenant: CovenantBinding,
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
#[derive(Clone, Debug)]
pub enum ContextOutput {
    Argent(ArgentOutput),
    Ordinary(OrdinaryOutput),
}

/// Artifact-independent description of one complete transaction.
///
/// Inputs and outputs appear in transaction order. The context records only
/// concrete transaction metadata; a [`crate::TxBuilder`] later resolves actor
/// paths and fills Argent-generated scripts from its artifact bundle.
#[derive(Debug, Default)]
pub struct TxContext<'a> {
    pub inputs: Vec<ContextInput<'a>>,
    pub outputs: Vec<ContextOutput>,
}

impl<'a> TxContext<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an Argent covenant input.
    pub fn argent_input(
        mut self,
        actor: impl Into<ActorPath>,
        state: BTreeMap<String, ArtifactValue>,
        entry: impl Into<EntryCall<'a>>,
        outpoint: TransactionOutpoint,
        utxo: UtxoEntry,
    ) -> Self {
        self.inputs.push(ContextInput::Argent(ArgentInput { actor: actor.into(), state, entry: entry.into(), outpoint, utxo }));
        self
    }

    /// Append a non-Argent input.
    pub fn input(mut self, outpoint: TransactionOutpoint, utxo: UtxoEntry, signature_script: impl Into<InputSigScript<'a>>) -> Self {
        self.inputs.push(ContextInput::Ordinary(OrdinaryInput { outpoint, utxo, signature_script: signature_script.into() }));
        self
    }

    /// Append an Argent covenant output.
    pub fn argent_output(
        mut self,
        actor: impl Into<ActorPath>,
        state: BTreeMap<String, ArtifactValue>,
        covenant: CovenantBinding,
        value: u64,
    ) -> Self {
        self.outputs.push(ContextOutput::Argent(ArgentOutput { actor: actor.into(), state, covenant, value }));
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
            )
            .input(outpoint(2), utxo(None), vec![0xaa])
            .argent_output("Counter", BTreeMap::from([("count".to_string(), ArtifactValue::Int(5))]), binding, 900)
            .output(ScriptPublicKey::default(), None, 100);

        assert!(matches!(&context.inputs[0], ContextInput::Argent(input) if input.actor == ActorPath::primary("Counter")));
        assert!(
            matches!(&context.inputs[1], ContextInput::Ordinary(input) if matches!(input.signature_script, InputSigScript::Static(ref script) if script == &[0xaa]))
        );
        assert!(matches!(&context.outputs[0], ContextOutput::Argent(output) if output.covenant == binding));
        assert!(matches!(&context.outputs[1], ContextOutput::Ordinary(output) if output.value == 100));
    }

    #[test]
    fn entry_call_and_input_script_accept_transaction_callbacks() {
        let entry = EntryCall::new("spend").args_with(|_, input_index| vec![ArgValue::Value(ArtifactValue::Int(input_index as i64))]);
        let script = InputSigScript::with_transaction(|_, input_index| vec![input_index as u8]);

        assert!(matches!(entry.args, EntryArgs::WithTransaction(_)));
        assert!(matches!(script, InputSigScript::WithTransaction(_)));
    }
}
