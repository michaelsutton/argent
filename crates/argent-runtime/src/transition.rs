use std::collections::BTreeMap;

use argent_artifact::{EmitArtifact, EntryKindArtifact};
use kaspa_consensus_core::{
    mass::ComputeBudget,
    tx::{Transaction, TransactionOutpoint, UtxoEntry},
};

use crate::{ArgValue, ArtifactValue, BuilderError, BuilderResult, TxBuilder, measure_input_script_units_with_covenants};

/// A transaction produced and verified by [`TransitionBuilder`].
#[derive(Debug)]
pub struct BuiltTransition {
    pub transaction: Transaction,
}

/// Fluent builder for one Argent entry transition.
///
/// The initial surface supports one primary-app leader input and one static
/// `emits one` successor. Additional inputs and output forms can be added here
/// without making the reusable [`TxBuilder`] stateful.
pub struct TransitionBuilder<'builder, 'artifact> {
    builder: &'builder TxBuilder<'artifact>,
    actor_name: String,
    entry_name: String,
    user_args: Vec<ArgValue>,
    input: Option<TransitionInput>,
    expected_state: Option<BTreeMap<String, ArtifactValue>>,
    output_value: Option<TransitionOutputValue>,
}

struct TransitionInput {
    outpoint: TransactionOutpoint,
    utxo: UtxoEntry,
    state: BTreeMap<String, ArtifactValue>,
}

enum TransitionOutputValue {
    Preserve,
    Explicit(u64),
}

impl<'a> TxBuilder<'a> {
    /// Start composing one primary-app entry transition.
    pub fn transition(
        &self,
        actor_name: impl Into<String>,
        entry_name: impl Into<String>,
        user_args: Vec<ArgValue>,
    ) -> TransitionBuilder<'_, 'a> {
        TransitionBuilder {
            builder: self,
            actor_name: actor_name.into(),
            entry_name: entry_name.into(),
            user_args,
            input: None,
            expected_state: None,
            output_value: None,
        }
    }
}

impl TransitionBuilder<'_, '_> {
    /// Supply the live covenant input and its source-level state.
    pub fn input(mut self, outpoint: TransactionOutpoint, utxo: UtxoEntry, state: BTreeMap<String, ArtifactValue>) -> Self {
        self.input = Some(TransitionInput { outpoint, utxo, state });
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

    /// Build the transaction, fill hidden witnesses, and execute its input.
    pub fn build(self) -> BuilderResult<BuiltTransition> {
        let entry = self.builder.entry(&self.actor_name, &self.entry_name)?;
        if entry.kind != EntryKindArtifact::Leader {
            return Err(self.error("the fluent builder currently supports leader entries only"));
        }
        if !entry.consumes.is_empty() || !entry.observes.is_empty() {
            return Err(self.error("the fluent builder currently supports one input without observed covenants"));
        }
        let output_actor = match &entry.emits {
            EmitArtifact::One { actors } if actors.len() == 1 => actors[0].clone(),
            _ => return Err(self.error("the fluent builder currently requires one statically selected output actor")),
        };

        let input = self.input.as_ref().ok_or_else(|| self.error("an input is required"))?;
        let expected_state = self.expected_state.as_ref().ok_or_else(|| self.error("an expected successor state is required"))?;
        let expected_input_script = self.builder.script_public_key(&self.actor_name, input.state.clone())?;
        if input.utxo.script_public_key != expected_input_script {
            return Err(self.error("the input UTXO does not match the actor and source state"));
        }
        let covenant_id = input.utxo.covenant_id.ok_or_else(|| self.error("the input UTXO has no covenant id"))?;
        let output_value = match self.output_value {
            Some(TransitionOutputValue::Preserve) => input.utxo.amount,
            Some(TransitionOutputValue::Explicit(value)) => value,
            None => return Err(self.error("an output value policy is required")),
        };

        let output = self.builder.covenant_output(&output_actor, expected_state.clone(), output_value, 0, covenant_id)?;
        let sigscript = self.builder.p2sh_signature_script(&self.actor_name, &self.entry_name, input.state.clone(), self.user_args)?;
        let mut transaction = TxBuilder::transaction(vec![TxBuilder::transaction_input(input.outpoint, sigscript)], vec![output]);
        // Measure without a limit, then commit the smallest covering v1 budget.
        let used_script_units = measure_input_script_units_with_covenants(&transaction, vec![input.utxo.clone()], 0)?;
        let compute_budget = ComputeBudget::checked_covering_script_units(used_script_units)
            .ok_or(BuilderError::ComputeBudgetOverflow { input_index: 0, script_units: used_script_units.0 })?;
        transaction.inputs[0].compute_commit = compute_budget.into();
        Ok(BuiltTransition { transaction })
    }

    fn error(&self, message: impl Into<String>) -> BuilderError {
        BuilderError::InvalidTransition { actor: self.actor_name.clone(), entry: self.entry_name.clone(), message: message.into() }
    }
}
