use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutput},
};
use kaspa_txscript::pay_to_script_hash_script;

use crate::{
    ActorPath, Artifact, BuilderError, BuilderResult, ContextInput, ContextOutput, ContractRef, EntryRef, TxBuilder, TxContext,
};

// This internal pass is wired to the public transaction API in a later stage.
#[allow(dead_code)]
impl<'artifact> TxBuilder<'artifact> {
    fn context_artifact(&self, actor: &ActorPath) -> BuilderResult<&'artifact Artifact> {
        match &actor.app {
            Some(app) => self.bundle.app(app),
            None => Ok(self.bundle.primary),
        }
    }

    fn context_contract_ref(&self, actor: &ActorPath) -> BuilderResult<ContractRef<'artifact>> {
        self.contract_ref_in_artifact(self.context_artifact(actor)?, &actor.actor)
    }

    fn context_entry_ref(&self, actor: &ActorPath, entry: &str) -> BuilderResult<EntryRef<'artifact>> {
        self.entry_ref_in_artifact(self.context_artifact(actor)?, &actor.actor, entry)
    }

    /// Materialize the unsigned transaction described by `context`.
    ///
    /// All input sigscripts are empty. This is the single transaction view
    /// against which later resolution passes evaluate argument and sigscript
    /// callbacks.
    pub(crate) fn unsigned_transaction(&self, context: &TxContext<'_>) -> BuilderResult<MutableTransaction<Transaction>> {
        let mut inputs = Vec::with_capacity(context.inputs.len());
        let mut entries = Vec::with_capacity(context.inputs.len());

        for (input_index, input) in context.inputs.iter().enumerate() {
            match input {
                ContextInput::Argent(input) => {
                    let contract_ref = self.context_contract_ref(&input.actor)?;
                    self.context_entry_ref(&input.actor, &input.entry.name)?;
                    if input.utxo.covenant_id.is_none() {
                        return Err(BuilderError::MissingArgentInputCovenantId { input_index, actor: input.actor.to_string() });
                    }
                    let expected_script =
                        pay_to_script_hash_script(&self.redeem_script_for_contract(contract_ref, input.state.clone())?);
                    if input.utxo.script_public_key != expected_script {
                        return Err(BuilderError::ArgentInputScriptMismatch { input_index, actor: input.actor.to_string() });
                    }
                    inputs.push(TransactionInput::new_with_compute_budget(input.outpoint, Vec::new(), 0, 0));
                    entries.push(input.utxo.clone());
                }
                ContextInput::Ordinary(input) => {
                    inputs.push(TransactionInput::new_with_compute_budget(input.outpoint, Vec::new(), 0, 0));
                    entries.push(input.utxo.clone());
                }
            }
        }

        let mut outputs = Vec::with_capacity(context.outputs.len());
        for output in &context.outputs {
            match output {
                ContextOutput::Argent(output) => {
                    let contract_ref = self.context_contract_ref(&output.actor)?;
                    let script_public_key =
                        pay_to_script_hash_script(&self.redeem_script_for_contract(contract_ref, output.state.clone())?);
                    outputs.push(TransactionOutput::with_covenant(output.value, script_public_key, Some(output.covenant)));
                }
                ContextOutput::Ordinary(output) => {
                    outputs.push(TransactionOutput::with_covenant(output.value, output.script_public_key.clone(), output.covenant));
                }
            }
        }

        let transaction = Transaction::new(TX_VERSION_TOCCATA, inputs, outputs, 0, Default::default(), 0, Vec::new());
        Ok(MutableTransaction::with_entries(transaction, entries))
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use argent_artifact::{
        ARTIFACT_SCHEMA_VERSION, ActorAbiRefArtifact, ActorArtifact, ArgentArtifact, CompiledContractArtifact,
        CompiledTemplateArtifact, EmitArtifact, EntryAbiRefArtifact, EntryArtifact, EntryKindArtifact, EntryRoutePlanArtifact,
        GeneratorArtifact, InterfaceSetArtifact, RuntimeFieldArtifact, RuntimeStateArtifact, SIL_ABI_SCHEMA_VERSION, SilAbiArtifact,
        SilContractArtifact, SilEntryArtifact, StateSpanArtifact, TemplatePlanArtifact, TypeArtifact,
    };
    use kaspa_consensus_core::{
        Hash,
        tx::{CovenantBinding, ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry},
    };

    use super::*;
    use crate::{ArgValue, ArtifactValue, EntryCall, InputSigScript};

    fn artifact(app: &str, actor: &str, entry: &str) -> Artifact {
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
                        template_selectors: Vec::new(),
                        observes: Vec::new(),
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
                    entries: vec![SilEntryArtifact { name: entry.to_string(), selector: None, params: Vec::new() }],
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

    #[test]
    fn unsigned_transaction_materializes_ordered_primary_qualified_and_ordinary_items() {
        let primary = artifact("primary", "Counter", "bump");
        let attached = artifact("asset", "Reserve", "move");
        let builder = TxBuilder::new(&primary).expect("primary artifact builds").with_app("asset", &attached).expect("app attaches");
        let counter_id = Hash::from_bytes([0x11; 32]);
        let reserve_id = Hash::from_bytes([0x22; 32]);
        let counter_utxo = builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(counter_id)).expect("counter UTXO builds");
        let reserve_utxo = builder
            .covenant_utxo_in_app("asset", "Reserve", state(7), 2_000, 0, false, Some(reserve_id))
            .expect("reserve UTXO builds");
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
            )
            .input(
                outpoint(2),
                ordinary_utxo.clone(),
                InputSigScript::with_transaction(|_, _| {
                    script_called.set(true);
                    vec![0xaa]
                }),
            )
            .argent_input("asset::Reserve", state(7), "move", outpoint(3), reserve_utxo.clone())
            .argent_output("Counter", state(3), CovenantBinding::new(0, counter_id), 900)
            .output(ScriptPublicKey::default(), Some(CovenantBinding::new(0, counter_id)), 100)
            .argent_output("asset::Reserve", state(8), CovenantBinding::new(2, reserve_id), 2_000);

        let unsigned = builder.unsigned_transaction(&context).expect("context materializes");

        assert_eq!(unsigned.tx.version, TX_VERSION_TOCCATA);
        assert_eq!(unsigned.tx.inputs.len(), 3);
        assert!(unsigned.tx.inputs.iter().all(|input| input.signature_script.is_empty()));
        assert_eq!(unsigned.tx.inputs[0].previous_outpoint, outpoint(1));
        assert_eq!(unsigned.tx.inputs[1].previous_outpoint, outpoint(2));
        assert_eq!(unsigned.tx.inputs[2].previous_outpoint, outpoint(3));
        assert_eq!(unsigned.entries, vec![Some(counter_utxo), Some(ordinary_utxo), Some(reserve_utxo)]);
        assert_eq!(
            unsigned.tx.outputs[0].script_public_key,
            builder.script_public_key("Counter", state(3)).expect("counter output script builds")
        );
        assert_eq!(
            unsigned.tx.outputs[2].script_public_key,
            builder.script_public_key_in_app("asset", "Reserve", state(8)).expect("reserve output script builds")
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

        let missing_id = TxContext::new().argent_input("Counter", state(2), "bump", outpoint(1), unbound_utxo);
        assert!(matches!(
            builder.unsigned_transaction(&missing_id),
            Err(BuilderError::MissingArgentInputCovenantId { input_index: 0, actor }) if actor == "Counter"
        ));

        let wrong_state = TxContext::new().argent_input("Counter", state(3), "bump", outpoint(1), matching_utxo);
        assert!(matches!(
            builder.unsigned_transaction(&wrong_state),
            Err(BuilderError::ArgentInputScriptMismatch { input_index: 0, actor }) if actor == "Counter"
        ));
    }

    #[test]
    fn unsigned_transaction_rejects_unknown_context_paths_and_entries() {
        let artifact = artifact("primary", "Counter", "bump");
        let builder = TxBuilder::new(&artifact).expect("artifact builds");
        let covenant_id = Hash::from_bytes([0x44; 32]);
        let utxo = builder.covenant_utxo("Counter", state(2), 1_000, 0, false, Some(covenant_id)).expect("counter UTXO builds");

        let unknown_app = TxContext::new().argent_input("missing::Counter", state(2), "bump", outpoint(1), utxo.clone());
        assert!(matches!(builder.unsigned_transaction(&unknown_app), Err(BuilderError::UnknownAppAlias(app)) if app == "missing"));

        let unknown_actor = TxContext::new().argent_input("Missing", state(2), "bump", outpoint(1), utxo.clone());
        assert!(matches!(builder.unsigned_transaction(&unknown_actor), Err(BuilderError::UnknownActor(actor)) if actor == "Missing"));

        let unknown_entry = TxContext::new().argent_input("Counter", state(2), "missing", outpoint(1), utxo);
        assert!(matches!(
            builder.unsigned_transaction(&unknown_entry),
            Err(BuilderError::UnknownEntry { actor, entry }) if actor == "Counter" && entry == "missing"
        ));
    }
}
