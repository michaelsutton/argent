use std::collections::BTreeMap;

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
use thiserror::Error;

use crate::{
    artifact::{
        ActorArtifact, Artifact, ArtifactVersionError, EntryArtifact, HiddenParamPurposeArtifact, RuntimeFieldRoleArtifact,
        SilActorArtifact,
    },
    codec::{ArtifactValue, CodecError, decode_hex, encode_entry_sig_script, encode_runtime_state_script},
};

pub type BuilderResult<T> = std::result::Result<T, BuilderError>;

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error(transparent)]
    ArtifactVersion(#[from] ArtifactVersionError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    ScriptBuilder(#[from] ScriptBuilderError),
    #[error(transparent)]
    TxScript(#[from] TxScriptError),
    #[error("unknown actor `{0}`")]
    UnknownActor(String),
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

pub struct ArtifactTxBuilder<'a> {
    artifact: &'a Artifact,
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

impl<'a> ArtifactTxBuilder<'a> {
    pub fn new(artifact: &'a Artifact) -> BuilderResult<Self> {
        artifact.check_schema_version()?;
        Ok(Self { artifact })
    }

    pub fn redeem_script(&self, actor_name: &str, source_state: BTreeMap<String, ArtifactValue>) -> BuilderResult<Vec<u8>> {
        let actor = self.actor(actor_name)?;
        let state = self.runtime_state_values(actor, source_state)?;
        let state_script = encode_runtime_state_script(&actor.runtime_state, &state)?;

        let mut script = decode_hex(&actor.compiled.template.prefix_hex)?;
        script.extend_from_slice(&state_script);
        script.extend_from_slice(&decode_hex(&actor.compiled.template.suffix_hex)?);
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
        let actor = self.actor(actor_name)?;
        let entry = actor
            .entry(entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })?;
        let mut args = user_args;
        for hidden in &entry.hidden_params {
            args.push(match &hidden.purpose {
                HiddenParamPurposeArtifact::TemplatePrefix { actor } => {
                    ArtifactValue::Bytes(decode_hex(&self.actor(actor)?.compiled.template.prefix_hex)?)
                }
                HiddenParamPurposeArtifact::TemplateSuffix { actor } => {
                    ArtifactValue::Bytes(decode_hex(&self.actor(actor)?.compiled.template.suffix_hex)?)
                }
            });
        }

        let sigscript = encode_entry_sig_script(&self.artifact.sil_abi, actor, entry, &args)?;
        Ok(pay_to_script_hash_signature_script_with_flags(
            self.redeem_script(actor_name, input_source_state)?,
            sigscript,
            covenant_engine_flags(),
        )?)
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

    pub fn transaction_input(previous_outpoint: TransactionOutpoint, signature_script: Vec<u8>) -> TransactionInput {
        TransactionInput::new_with_compute_budget(previous_outpoint, signature_script, 0, 0)
    }

    pub fn transaction(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
        Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![])
    }

    pub fn populated_transaction<'tx>(&self, tx: &'tx Transaction, entries: Vec<UtxoEntry>) -> PopulatedTransaction<'tx> {
        PopulatedTransaction::new(tx, entries)
    }

    fn actor(&self, name: &str) -> BuilderResult<&'a SilActorArtifact> {
        self.artifact.sil_abi.actor(name).ok_or_else(|| BuilderError::UnknownActor(name.to_string()))
    }

    fn argent_actor(&self, name: &str) -> BuilderResult<&'a ActorArtifact> {
        self.artifact.argent.actors.iter().find(|actor| actor.name == name).ok_or_else(|| BuilderError::UnknownActor(name.to_string()))
    }

    fn entry(&self, actor_name: &str, entry_name: &str) -> BuilderResult<&'a EntryArtifact> {
        self.argent_actor(actor_name)?
            .entries
            .iter()
            .find(|entry| entry.name == entry_name)
            .ok_or_else(|| BuilderError::UnknownEntry { actor: actor_name.to_string(), entry: entry_name.to_string() })
    }

    fn runtime_state_values(
        &self,
        actor: &SilActorArtifact,
        mut source_state: BTreeMap<String, ArtifactValue>,
    ) -> BuilderResult<BTreeMap<String, ArtifactValue>> {
        let mut values = BTreeMap::new();
        for field in &actor.runtime_state.fields {
            match &field.role {
                RuntimeFieldRoleArtifact::Source => {
                    let value = source_state.remove(&field.name).ok_or_else(|| CodecError::MissingField(field.name.clone()))?;
                    values.insert(field.name.clone(), value);
                }
                RuntimeFieldRoleArtifact::Template { actor } => {
                    values
                        .insert(field.name.clone(), ArtifactValue::Bytes(decode_hex(&self.actor(actor)?.compiled.template.hash_hex)?));
                }
            }
        }
        if let Some(extra) = source_state.into_keys().next() {
            return Err(CodecError::UnknownField(extra).into());
        }
        Ok(values)
    }
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

fn covenant_engine_flags() -> EngineFlags {
    EngineFlags { covenants_enabled: true, ..Default::default() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use kaspa_consensus_core::{
        hashing::{
            sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
            sighash_type::SIG_HASH_ALL,
        },
        tx::{MutableTransaction, TransactionId},
    };
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    use crate::{emit::emit_build, loader::load_program};

    static ARTIFACT_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn artifact_builder_redeems_ticket_transition_and_rejects_mutations() {
        let artifact = tickets_artifact();
        let builder = ArtifactTxBuilder::new(&artifact).expect("builder accepts artifact");
        let owner = keypair_from_byte(1);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let owner_hash = blake2b32(&owner_pk);
        let covenant_id = Hash::from_bytes([9; 32]);
        let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([7; 32]), index: 0 };

        let initial_state = ticket_state(owner_hash.clone(), 7, 0);
        let redeemed_state = ticket_state(owner_hash.clone(), 7, 1);
        let input_value = 1_500;

        let output =
            builder.covenant_output("Ticket", redeemed_state.clone(), input_value, 0, covenant_id).expect("redeemed output builds");
        let input_utxo = builder
            .covenant_utxo("Ticket", initial_state.clone(), input_value, 0, false, Some(covenant_id))
            .expect("ticket utxo builds");
        let unsigned_tx =
            ArtifactTxBuilder::transaction(vec![ArtifactTxBuilder::transaction_input(outpoint, Vec::new())], vec![output.clone()]);
        let signature = sign_input(&unsigned_tx, vec![input_utxo.clone()], 0, &owner);
        let sigscript = builder
            .p2sh_signature_script(
                "Ticket",
                "redeem",
                initial_state.clone(),
                vec![ArtifactValue::Bytes(signature), ArtifactValue::Bytes(owner_pk.clone())],
            )
            .expect("sigscript builds");
        let tx = ArtifactTxBuilder::transaction(vec![ArtifactTxBuilder::transaction_input(outpoint, sigscript)], vec![output]);

        execute_input_with_covenants(&tx, vec![input_utxo.clone()], 0).expect("valid redeem tx passes");

        let wrong_pk = keypair_from_byte(2).x_only_public_key().0.serialize().to_vec();
        let bad_sigscript = builder
            .p2sh_signature_script(
                "Ticket",
                "redeem",
                initial_state.clone(),
                vec![
                    ArtifactValue::Bytes(sign_input(&unsigned_tx, vec![input_utxo.clone()], 0, &owner)),
                    ArtifactValue::Bytes(wrong_pk),
                ],
            )
            .expect("bad-arg sigscript still encodes");
        let bad_arg_tx = ArtifactTxBuilder::transaction(
            vec![ArtifactTxBuilder::transaction_input(outpoint, bad_sigscript)],
            vec![tx.outputs[0].clone()],
        );
        assert!(execute_input_with_covenants(&bad_arg_tx, vec![input_utxo.clone()], 0).is_err());

        let stale_output =
            builder.covenant_output("Ticket", initial_state.clone(), input_value, 0, covenant_id).expect("stale output builds");
        let stale_unsigned_tx = ArtifactTxBuilder::transaction(
            vec![ArtifactTxBuilder::transaction_input(outpoint, Vec::new())],
            vec![stale_output.clone()],
        );
        let stale_sigscript = builder
            .p2sh_signature_script(
                "Ticket",
                "redeem",
                initial_state,
                vec![
                    ArtifactValue::Bytes(sign_input(&stale_unsigned_tx, vec![input_utxo.clone()], 0, &owner)),
                    ArtifactValue::Bytes(owner_pk),
                ],
            )
            .expect("stale-output sigscript builds");
        let stale_tx =
            ArtifactTxBuilder::transaction(vec![ArtifactTxBuilder::transaction_input(outpoint, stale_sigscript)], vec![stale_output]);
        assert!(execute_input_with_covenants(&stale_tx, vec![input_utxo], 0).is_err());
    }

    #[test]
    fn redeem_script_fills_hidden_template_state_from_artifact() {
        let artifact = tickets_artifact();
        let builder = ArtifactTxBuilder::new(&artifact).expect("builder accepts artifact");
        let actor = builder.actor("Ticket").expect("ticket actor exists");
        let source_state = ticket_state(vec![3; 32], 11, 0);

        let redeem_script = builder.redeem_script("Ticket", source_state.clone()).expect("redeem script builds");
        let state_span = &actor.compiled.state_span;
        let state_script = &redeem_script[state_span.offset..state_span.offset + state_span.len];
        let decoded = crate::codec::decode_runtime_state_script(&actor.runtime_state, state_script).expect("state decodes");

        assert_eq!(decoded.get("owner"), source_state.get("owner"));
        assert_eq!(
            decoded.get("gen__template_ticket"),
            Some(&ArtifactValue::Bytes(decode_hex(&builder.actor("Ticket").unwrap().compiled.template.hash_hex).unwrap()))
        );
        assert_eq!(
            decoded.get("gen__template_issuer"),
            Some(&ArtifactValue::Bytes(decode_hex(&builder.actor("Issuer").unwrap().compiled.template.hash_hex).unwrap()))
        );
    }

    #[test]
    fn p2sh_signature_script_accepts_user_args_only() {
        let artifact = tickets_artifact();
        let builder = ArtifactTxBuilder::new(&artifact).expect("builder accepts artifact");
        let owner = keypair_from_byte(1);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let source_state = ticket_state(blake2b32(&owner_pk), 7, 0);

        let err = builder
            .p2sh_signature_script(
                "Ticket",
                "redeem",
                source_state,
                vec![
                    ArtifactValue::Bytes(vec![1; 65]),
                    ArtifactValue::Bytes(owner_pk),
                    ArtifactValue::Bytes(vec![2; 32]),
                    ArtifactValue::Bytes(vec![3; 32]),
                ],
            )
            .expect_err("user must not provide hidden prefix/suffix witnesses");

        assert!(matches!(err, BuilderError::Codec(CodecError::WrongArgumentCount { .. })));
    }

    #[test]
    fn route_plan_builds_stones_start_game_and_rejects_bad_routes() {
        let artifact = example_artifact("examples/stones/app.ag", "stones-route-plan");
        let builder = ArtifactTxBuilder::new(&artifact).expect("builder accepts artifact");
        let entry = builder.entry("Player", "start_game").expect("start_game entry exists");
        assert_eq!(
            entry.route_plan.leader_input.as_ref().map(|input| (input.actor.as_str(), input.cov_index)),
            Some(("Player", Some(0)))
        );
        assert_eq!(entry.route_plan.consumes[0].name, "opponent");
        assert_eq!(entry.route_plan.consumes[0].actor, "Player");
        assert_eq!(entry.route_plan.consumes[0].cov_index, Some(1));
        assert_eq!(
            entry.route_plan.outputs.iter().map(|output| (output.name.as_deref(), output.auth_index)).collect::<Vec<_>>(),
            vec![(Some("self_out"), 0), (Some("opponent_out"), 1), (Some("game"), 2)]
        );

        let owner_a = keypair_from_byte(3);
        let owner_b = keypair_from_byte(4);
        let owner_a_pk = owner_a.x_only_public_key().0.serialize().to_vec();
        let owner_b_pk = owner_b.x_only_public_key().0.serialize().to_vec();
        let owner_a_hash = blake2b32(&owner_a_pk);
        let owner_b_hash = blake2b32(&owner_b_pk);
        let player_a_id = vec![0xa1; 32];
        let player_b_id = vec![0xb2; 32];
        let player_a_ref = player_ref(&owner_a_hash, &player_a_id);
        let player_b_ref = player_ref(&owner_b_hash, &player_b_id);
        let initial_a = player_state(owner_a_hash.clone(), player_a_id.clone(), 0, 0, 0, 0);
        let initial_b = player_state(owner_b_hash.clone(), player_b_id.clone(), 0, 0, 0, 0);
        let next_a = player_state(owner_a_hash.clone(), player_a_id.clone(), 1, 0, 0, 0);
        let next_b = player_state(owner_b_hash.clone(), player_b_id.clone(), 1, 0, 0, 0);
        let next_game = game_state(player_a_ref, player_b_ref, 7, 3, 0);
        let covenant_id = Hash::from_bytes([5; 32]);
        let outpoint_a = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0xa; 32]), index: 0 };
        let outpoint_b = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0xb; 32]), index: 0 };
        let input_a_value = 1_000;
        let input_b_value = 2_000;
        let game_value = 500;
        let player_a_utxo = builder
            .covenant_utxo("Player", initial_a.clone(), input_a_value, 0, false, Some(covenant_id))
            .expect("player A utxo builds");
        let player_b_utxo = builder
            .covenant_utxo("Player", initial_b.clone(), input_b_value, 0, false, Some(covenant_id))
            .expect("player B utxo builds");
        let entries = vec![player_a_utxo.clone(), player_b_utxo.clone()];
        let output_states =
            BTreeMap::from([("self_out".to_string(), next_a), ("opponent_out".to_string(), next_b), ("game".to_string(), next_game)]);
        let output_values = BTreeMap::from([
            ("self_out".to_string(), input_a_value),
            ("opponent_out".to_string(), input_b_value),
            ("game".to_string(), game_value),
        ]);
        let outputs = builder
            .terminal_path_outputs(TerminalPathOutputRequest {
                actor_name: "Player",
                entry_name: "start_game",
                path_index: 0,
                output_states,
                output_values,
                authorizing_input: 0,
                covenant_id,
            })
            .expect("route-plan outputs build");
        let unsigned_tx = ArtifactTxBuilder::transaction(
            vec![
                ArtifactTxBuilder::transaction_input(outpoint_a, Vec::new()),
                ArtifactTxBuilder::transaction_input(outpoint_b, Vec::new()),
            ],
            outputs.clone(),
        );
        let tx = signed_start_game_tx(
            &builder,
            unsigned_tx,
            entries.clone(),
            outpoint_a,
            outpoint_b,
            &initial_a,
            &initial_b,
            &owner_a,
            &owner_b,
            &owner_a_pk,
            &owner_b_pk,
        );

        execute_input_with_covenants(&tx, entries.clone(), 0).expect("leader input passes");
        execute_input_with_covenants(&tx, entries.clone(), 1).expect("delegate input passes");

        let swapped_outputs = vec![outputs[1].clone(), outputs[0].clone(), outputs[2].clone()];
        let swapped_unsigned_tx = ArtifactTxBuilder::transaction(
            vec![
                ArtifactTxBuilder::transaction_input(outpoint_a, Vec::new()),
                ArtifactTxBuilder::transaction_input(outpoint_b, Vec::new()),
            ],
            swapped_outputs,
        );
        let swapped_tx = signed_start_game_tx(
            &builder,
            swapped_unsigned_tx,
            entries.clone(),
            outpoint_a,
            outpoint_b,
            &initial_a,
            &initial_b,
            &owner_a,
            &owner_b,
            &owner_a_pk,
            &owner_b_pk,
        );
        assert!(execute_input_with_covenants(&swapped_tx, entries.clone(), 0).is_err());

        let wrong_peer = builder
            .covenant_utxo("League", league_state(vec![0; 32], 7, 3), input_b_value, 0, false, Some(covenant_id))
            .expect("wrong-template peer utxo builds");
        let wrong_entries = vec![player_a_utxo, wrong_peer];
        let wrong_peer_unsigned_tx = ArtifactTxBuilder::transaction(
            vec![
                ArtifactTxBuilder::transaction_input(outpoint_a, Vec::new()),
                ArtifactTxBuilder::transaction_input(outpoint_b, Vec::new()),
            ],
            outputs,
        );
        let leader_sig = sign_input(&wrong_peer_unsigned_tx, wrong_entries.clone(), 0, &owner_a);
        let leader_sigscript = builder
            .p2sh_signature_script(
                "Player",
                "start_game",
                initial_a,
                vec![
                    ArtifactValue::Bytes(leader_sig),
                    ArtifactValue::Bytes(owner_a_pk),
                    ArtifactValue::Int(0),
                    ArtifactValue::Int(7),
                    ArtifactValue::Int(3),
                ],
            )
            .expect("leader sigscript builds");
        let wrong_peer_tx = ArtifactTxBuilder::transaction(
            vec![
                ArtifactTxBuilder::transaction_input(outpoint_a, leader_sigscript),
                ArtifactTxBuilder::transaction_input(outpoint_b, Vec::new()),
            ],
            wrong_peer_unsigned_tx.outputs,
        );
        assert!(execute_input_with_covenants(&wrong_peer_tx, wrong_entries, 0).is_err());
    }

    fn tickets_artifact() -> Artifact {
        example_artifact("examples/tickets.ag", "tickets")
    }

    fn example_artifact(input: &str, name: &str) -> Artifact {
        let counter = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let out_dir = std::env::temp_dir().join(format!("argent-{name}-{}-{counter}", std::process::id()));
        if out_dir.exists() {
            std::fs::remove_dir_all(&out_dir).expect("old temp dir removed");
        }
        let program = load_program(input).expect("example source loads");
        emit_build(&program, &out_dir).expect("example artifact builds");
        let json = std::fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        serde_json::from_str(&json).expect("artifact deserializes")
    }

    fn ticket_state(owner: Vec<u8>, serial: i64, redeemed: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("owner".to_string(), ArtifactValue::Bytes(owner)),
            ("serial".to_string(), ArtifactValue::Int(serial)),
            ("redeemed".to_string(), ArtifactValue::Int(redeemed)),
        ])
    }

    fn keypair_from_byte(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[byte; 32]).expect("test secret key is valid");
        Keypair::from_secret_key(&secp, &secret_key)
    }

    fn blake2b32(data: &[u8]) -> Vec<u8> {
        blake2b_simd::Params::new().hash_length(32).to_state().update(data).finalize().as_bytes().to_vec()
    }

    fn player_ref(owner: &[u8], player_id: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(owner.len() + player_id.len());
        bytes.extend_from_slice(owner);
        bytes.extend_from_slice(player_id);
        blake2b32(&bytes)
    }

    fn player_state(
        owner: Vec<u8>,
        player_id: Vec<u8>,
        open_games: i64,
        games: i64,
        wins: i64,
        losses: i64,
    ) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("owner".to_string(), ArtifactValue::Bytes(owner)),
            ("player_id".to_string(), ArtifactValue::Bytes(player_id)),
            ("open_games".to_string(), ArtifactValue::Int(open_games)),
            ("games".to_string(), ArtifactValue::Int(games)),
            ("wins".to_string(), ArtifactValue::Int(wins)),
            ("losses".to_string(), ArtifactValue::Int(losses)),
        ])
    }

    fn game_state(player_a: Vec<u8>, player_b: Vec<u8>, pile: i64, max_take: i64, turn: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("player_a".to_string(), ArtifactValue::Bytes(player_a)),
            ("player_b".to_string(), ArtifactValue::Bytes(player_b)),
            ("pile".to_string(), ArtifactValue::Int(pile)),
            ("max_take".to_string(), ArtifactValue::Int(max_take)),
            ("turn".to_string(), ArtifactValue::Int(turn)),
        ])
    }

    fn league_state(admin: Vec<u8>, default_pile: i64, default_max_take: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("admin".to_string(), ArtifactValue::Bytes(admin)),
            ("default_pile".to_string(), ArtifactValue::Int(default_pile)),
            ("default_max_take".to_string(), ArtifactValue::Int(default_max_take)),
        ])
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_start_game_tx(
        builder: &ArtifactTxBuilder<'_>,
        unsigned_tx: Transaction,
        entries: Vec<UtxoEntry>,
        outpoint_a: TransactionOutpoint,
        outpoint_b: TransactionOutpoint,
        initial_a: &BTreeMap<String, ArtifactValue>,
        initial_b: &BTreeMap<String, ArtifactValue>,
        owner_a: &Keypair,
        owner_b: &Keypair,
        owner_a_pk: &[u8],
        owner_b_pk: &[u8],
    ) -> Transaction {
        let leader_sig = sign_input(&unsigned_tx, entries.clone(), 0, owner_a);
        let delegate_sig = sign_input(&unsigned_tx, entries, 1, owner_b);
        let leader_sigscript = builder
            .p2sh_signature_script(
                "Player",
                "start_game",
                initial_a.clone(),
                vec![
                    ArtifactValue::Bytes(leader_sig),
                    ArtifactValue::Bytes(owner_a_pk.to_vec()),
                    ArtifactValue::Int(0),
                    ArtifactValue::Int(7),
                    ArtifactValue::Int(3),
                ],
            )
            .expect("leader sigscript builds");
        let delegate_sigscript = builder
            .p2sh_signature_script(
                "Player",
                "accept_start",
                initial_b.clone(),
                vec![ArtifactValue::Bytes(delegate_sig), ArtifactValue::Bytes(owner_b_pk.to_vec())],
            )
            .expect("delegate sigscript builds");

        ArtifactTxBuilder::transaction(
            vec![
                ArtifactTxBuilder::transaction_input(outpoint_a, leader_sigscript),
                ArtifactTxBuilder::transaction_input(outpoint_b, delegate_sigscript),
            ],
            unsigned_tx.outputs,
        )
    }

    fn sign_input(tx: &Transaction, entries: Vec<UtxoEntry>, input_idx: usize, keypair: &Keypair) -> Vec<u8> {
        let tx = MutableTransaction::with_entries(tx.clone(), entries);
        let reused_values = SigHashReusedValuesUnsync::new();
        let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("valid sighash message");
        let sig = keypair.sign_schnorr(msg);
        let mut signature = sig.as_ref().to_vec();
        signature.push(SIG_HASH_ALL.to_u8());
        signature
    }
}
