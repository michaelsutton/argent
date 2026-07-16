use std::collections::BTreeMap;

use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutput},
};
use kaspa_txscript::pay_to_script_hash_script;

use crate::{
    ActorPath, Artifact, ArtifactValue, BuilderError, BuilderResult, ContextInput, ContextOutput, ContractRef, EntryArgs, EntryRef,
    TxBuilder, TxContext,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ResolvedEntryArgs {
    pub values: Vec<ArtifactValue>,
    pub template_selectors: BTreeMap<String, String>,
}

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

    /// Resolve user-visible entry arguments for every Argent input.
    ///
    /// Results remain aligned with transaction input order; ordinary inputs
    /// occupy `None` slots. Hidden arguments are resolved by later passes.
    pub(crate) fn resolve_context_args(
        &self,
        context: &TxContext<'_>,
        unsigned: &MutableTransaction<Transaction>,
    ) -> BuilderResult<Vec<Option<ResolvedEntryArgs>>> {
        let mut resolved = Vec::with_capacity(context.inputs.len());

        for (input_index, input) in context.inputs.iter().enumerate() {
            let ContextInput::Argent(input) = input else {
                resolved.push(None);
                continue;
            };

            let contract_ref = self.context_contract_ref(&input.actor)?;
            let entry_ref = self.context_entry_ref(&input.actor, &input.entry.name)?;
            let sil_entry = contract_ref
                .contract
                .entry(&input.entry.name)
                .ok_or_else(|| BuilderError::UnknownEntry { actor: input.actor.to_string(), entry: input.entry.name.clone() })?;
            let expected_arg_count = sil_entry.params.len().checked_sub(entry_ref.entry.hidden_params.len()).ok_or_else(|| {
                BuilderError::InvalidTransition {
                    actor: input.actor.to_string(),
                    entry: input.entry.name.clone(),
                    message: format!(
                        "artifact has {} hidden parameters but the Sil entry has {} total parameters",
                        entry_ref.entry.hidden_params.len(),
                        sil_entry.params.len()
                    ),
                }
            })?;
            let source_args = match &input.entry.args {
                EntryArgs::Static(args) => args.clone(),
                EntryArgs::WithTransaction(build) => build(unsigned, input_index),
            };
            if source_args.len() != expected_arg_count {
                return Err(silverscript_abi::CodecError::WrongArgumentCount {
                    entry: format!("{}::{}", input.actor, input.entry.name),
                    expected: expected_arg_count,
                    actual: source_args.len(),
                }
                .into());
            }
            let (values, template_selectors) =
                self.lower_arg_values(&input.actor.actor, &input.entry.name, sil_entry, entry_ref.entry, source_args)?;
            let values = self.runtime_entry_args(contract_ref.artifact, contract_ref.contract, sil_entry, values)?;
            resolved.push(Some(ResolvedEntryArgs { values, template_selectors }));
        }

        Ok(resolved)
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
        tx::{CovenantBinding, ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry},
    };

    use super::*;
    use crate::{ArgValue, ArtifactValue, EntryCall, InputSigScript, actor};

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
            )
            .input(
                outpoint(2),
                ordinary_utxo,
                InputSigScript::with_transaction(|_, _| {
                    ordinary_callback_called.set(true);
                    vec![0xaa]
                }),
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
            )
            .argent_output("Counter", state(3), CovenantBinding::new(0, covenant_id), 900);
        let unsigned = builder.unsigned_transaction(&context).expect("context materializes");

        let resolved = builder.resolve_context_args(&context, &unsigned).expect("arguments resolve");

        assert_eq!(resolved[0].as_ref().expect("input 0 is Argent").values, vec![ArtifactValue::Int(3)]);
        assert!(resolved[1].is_none());
        assert_eq!(resolved[2].as_ref().expect("input 2 is Argent").values, vec![ArtifactValue::Int(4)]);
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
        );
        let unsigned = builder.unsigned_transaction(&context).expect("context materializes");

        let resolved = builder.resolve_context_args(&context, &unsigned).expect("arguments resolve");
        let resolved = resolved[0].as_ref().expect("input is Argent");

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
        );
        let unsigned = builder.unsigned_transaction(&context).expect("context materializes");

        let resolved = builder.resolve_context_args(&context, &unsigned).expect("arguments resolve");

        assert_eq!(resolved[0].as_ref().expect("input is Argent").values, vec![ArtifactValue::Object(state(9))]);
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
        let context = TxContext::new().argent_input("Counter", state(2), "bump", outpoint(1), counter_utxo);
        let unsigned = builder.unsigned_transaction(&context).expect("context materializes");

        assert!(matches!(
            builder.resolve_context_args(&context, &unsigned),
            Err(BuilderError::Codec(silverscript_abi::CodecError::WrongArgumentCount { expected: 1, actual: 0, .. }))
        ));
    }
}
