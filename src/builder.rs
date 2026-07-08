pub use argent_runtime::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::{
            HiddenParamPurposeArtifact, HiddenParamSubjectArtifact, TemplatePlanError, route_template_proof_receipt_id,
            route_template_table_receipt_id,
        },
        codec::{CodecError, decode_hex, encode_entry_sig_script},
        emit::emit_build,
        loader::load_program,
    };
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use kaspa_consensus_core::{
        Hash,
        hashing::{
            sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
            sighash_type::SIG_HASH_ALL,
        },
        tx::{MutableTransaction, Transaction, TransactionId, TransactionOutpoint, UtxoEntry},
    };
    use kaspa_txscript::pay_to_script_hash_signature_script_with_flags;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    static ARTIFACT_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn subject_label(subject: &HiddenParamSubjectArtifact) -> &str {
        match subject {
            HiddenParamSubjectArtifact::Actor { actor } => actor,
            HiddenParamSubjectArtifact::ObservedActor { actor, .. } => actor,
            HiddenParamSubjectArtifact::RouteFamily { family_id } => family_id,
            HiddenParamSubjectArtifact::TemplateSelector { selector } => selector,
        }
    }

    #[test]
    fn artifact_builder_redeems_ticket_transition_and_rejects_mutations() {
        let artifact = tickets_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
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
        let unsigned_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, Vec::new())], vec![output.clone()]);
        let signature = sign_input(&unsigned_tx, vec![input_utxo.clone()], 0, &owner);
        let sigscript = builder
            .p2sh_signature_script(
                "Ticket",
                "redeem",
                initial_state.clone(),
                vec![ArtifactValue::Bytes(signature), ArtifactValue::Bytes(owner_pk.clone())],
            )
            .expect("sigscript builds");
        let tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, sigscript)], vec![output]);

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
        let bad_arg_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, bad_sigscript)], vec![tx.outputs[0].clone()]);
        assert!(execute_input_with_covenants(&bad_arg_tx, vec![input_utxo.clone()], 0).is_err());

        let stale_output =
            builder.covenant_output("Ticket", initial_state.clone(), input_value, 0, covenant_id).expect("stale output builds");
        let stale_unsigned_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, Vec::new())], vec![stale_output.clone()]);
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
        let stale_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, stale_sigscript)], vec![stale_output]);
        assert!(execute_input_with_covenants(&stale_tx, vec![input_utxo], 0).is_err());
    }

    #[test]
    fn redeem_script_fills_hidden_template_state_from_artifact() {
        let artifact = tickets_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let actor = builder.contract("Ticket").expect("ticket contract exists");
        let source_state = ticket_state(vec![3; 32], 11, 0);

        let redeem_script = builder.redeem_script("Ticket", source_state.clone()).expect("redeem script builds");
        let state_span = &actor.compiled.state_span;
        let state_script = &redeem_script[state_span.offset..state_span.offset + state_span.len];
        let decoded = crate::codec::decode_runtime_state_script(&actor.runtime_state, state_script).expect("state decodes");

        assert_eq!(decoded.get("owner"), source_state.get("owner"));
        assert_eq!(
            decoded.get("gen__ticket_template"),
            Some(&ArtifactValue::Bytes(decode_hex(&builder.contract("Ticket").unwrap().compiled.template.hash_hex).unwrap()))
        );
        assert!(!decoded.contains_key("gen__issuer_template"), "Ticket state should not carry unrelated Issuer template");

        let mut explicit_hidden_state = source_state;
        explicit_hidden_state.insert("gen__ticket_template".to_string(), ArtifactValue::Bytes(vec![0; 32]));
        let err = builder
            .redeem_script("Ticket", explicit_hidden_state)
            .expect_err("hidden runtime state fields must be filled by the runtime");
        assert!(
            matches!(err, BuilderError::HiddenRuntimeFieldProvided { ref field, .. } if field == "gen__ticket_template"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn p2sh_signature_script_accepts_user_args_only() {
        let artifact = tickets_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
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
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
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
        assert_eq!(
            entry
                .witnesses
                .iter()
                .map(|witness| (witness.param.as_str(), subject_label(&witness.subject), witness.purpose))
                .collect::<Vec<_>>(),
            vec![
                ("gen__player_prefix_len", "Player", HiddenParamPurposeArtifact::TemplatePrefixLen),
                ("gen__player_suffix_len", "Player", HiddenParamPurposeArtifact::TemplateSuffixLen),
                ("gen__stones_game_prefix", "StonesGame", HiddenParamPurposeArtifact::TemplatePrefixBytes),
                ("gen__stones_game_suffix", "StonesGame", HiddenParamPurposeArtifact::TemplateSuffixBytes),
            ]
        );
        assert_eq!(
            entry.route_plan.terminal_paths[0].witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
            entry.witnesses.iter().map(|witness| witness.recipe_id.as_str()).collect::<Vec<_>>()
        );
        assert!(entry.route_plan.terminal_paths[0].routes[0].witness_recipe_ids.is_empty());
        assert!(entry.route_plan.terminal_paths[0].routes[1].witness_recipe_ids.is_empty());
        assert_eq!(
            entry.route_plan.terminal_paths[0].routes[2].witness_recipe_ids.as_slice(),
            ["witness/stones_game/template_prefix_bytes", "witness/stones_game/template_suffix_bytes"]
        );

        let accept_start = builder.entry("Player", "accept_start").expect("accept_start entry exists");
        assert_eq!(
            accept_start
                .hidden_params
                .iter()
                .map(|param| (param.name.as_str(), subject_label(&param.subject), param.purpose))
                .collect::<Vec<_>>(),
            vec![
                ("gen__player_prefix_len", "Player", HiddenParamPurposeArtifact::TemplatePrefixLen),
                ("gen__player_suffix_len", "Player", HiddenParamPurposeArtifact::TemplateSuffixLen),
            ]
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
        let unsigned_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(outpoint_a, Vec::new()), TxBuilder::transaction_input(outpoint_b, Vec::new())],
            outputs.clone(),
        );
        let tx = signed_start_game_tx(
            &builder,
            unsigned_tx.clone(),
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

        let player_template = &builder.contract("Player").expect("Player contract exists").compiled.template;
        let wrong_delegate_sigscript = {
            let delegate_sig = sign_input(&unsigned_tx, entries.clone(), 1, &owner_b);
            let prefix_len = decode_hex(&player_template.prefix_hex).expect("prefix hex decodes").len() as i64;
            let suffix_len = decode_hex(&player_template.suffix_hex).expect("suffix hex decodes").len() as i64;
            let accept_entry =
                builder.contract("Player").expect("Player contract exists").entry("accept_start").expect("accept_start exists");
            let sigscript = encode_entry_sig_script(
                &artifact.sil_abi,
                builder.contract("Player").expect("Player contract exists"),
                accept_entry,
                &[
                    ArtifactValue::Bytes(delegate_sig),
                    ArtifactValue::Bytes(owner_b_pk.clone()),
                    ArtifactValue::Int(prefix_len + 1),
                    ArtifactValue::Int(suffix_len),
                ],
            )
            .expect("bad delegate sigscript encodes");
            pay_to_script_hash_signature_script_with_flags(
                builder.redeem_script("Player", initial_b.clone()).expect("delegate redeem script builds"),
                sigscript,
                covenant_engine_flags(),
            )
            .expect("bad delegate p2sh sigscript builds")
        };
        let wrong_length_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(outpoint_a, tx.inputs[0].signature_script.clone()),
                TxBuilder::transaction_input(outpoint_b, wrong_delegate_sigscript),
            ],
            tx.outputs.clone(),
        );
        assert!(
            execute_input_with_covenants(&wrong_length_tx, entries.clone(), 1).is_err(),
            "delegate input must reject a wrong read-only template prefix length"
        );

        let swapped_outputs = vec![outputs[1].clone(), outputs[0].clone(), outputs[2].clone()];
        let swapped_unsigned_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(outpoint_a, Vec::new()), TxBuilder::transaction_input(outpoint_b, Vec::new())],
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
        let wrong_peer_unsigned_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(outpoint_a, Vec::new()), TxBuilder::transaction_input(outpoint_b, Vec::new())],
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
        let wrong_peer_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(outpoint_a, leader_sigscript), TxBuilder::transaction_input(outpoint_b, Vec::new())],
            wrong_peer_unsigned_tx.outputs,
        );
        assert!(execute_input_with_covenants(&wrong_peer_tx, wrong_entries, 0).is_err());
    }

    #[test]
    fn toy_chess_builder_redeems_route_family_and_worker_paths() {
        let artifact = example_artifact("examples/toy_chess/app.ag", "toy-chess-builder-family-paths");
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let covenant_id = Hash::from_bytes([0x61; 32]);
        let input_value = 1_000;

        let player_initial = toy_player_state(7);
        let mux_initial = board_state(7, 0);
        let player_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x62; 32]), index: 0 };
        let player_utxo = builder
            .covenant_utxo("Player", player_initial.clone(), input_value, 0, false, Some(covenant_id))
            .expect("Player utxo builds");
        let mux_output = builder.covenant_output("Mux", mux_initial.clone(), input_value, 0, covenant_id).expect("Mux output builds");
        let enter_mux_sigscript = builder
            .p2sh_signature_script("Player", "enter_mux", player_initial.clone(), Vec::new())
            .expect("enter_mux sigscript fills the family route table");
        let enter_mux_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(player_outpoint, enter_mux_sigscript)], vec![mux_output.clone()]);
        execute_input_with_covenants(&enter_mux_tx, vec![player_utxo.clone()], 0).expect("Player can enter the mux family");

        let player_contract = builder.contract("Player").expect("Player contract exists");
        let enter_mux = player_contract.entry("enter_mux").expect("enter_mux ABI exists");
        let mux_template = &builder.contract("Mux").expect("Mux contract exists").compiled.template;
        let mut wrong_routes = builder.route_family_table_bytes("route_family/BoardState/mux").expect("mux family route table builds");
        wrong_routes[0] ^= 1;
        let bad_route_table_sigscript = encode_entry_sig_script(
            &artifact.sil_abi,
            player_contract,
            enter_mux,
            &[
                ArtifactValue::Bytes(decode_hex(&mux_template.prefix_hex).expect("Mux prefix decodes")),
                ArtifactValue::Bytes(decode_hex(&mux_template.suffix_hex).expect("Mux suffix decodes")),
                ArtifactValue::Bytes(wrong_routes),
            ],
        )
        .expect("bad route table sigscript encodes");
        let bad_route_table_sigscript = pay_to_script_hash_signature_script_with_flags(
            builder.redeem_script("Player", player_initial).expect("Player redeem script builds"),
            bad_route_table_sigscript,
            covenant_engine_flags(),
        )
        .expect("bad route table p2sh sigscript builds");
        let bad_route_table_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(player_outpoint, bad_route_table_sigscript)], vec![mux_output]);
        assert!(
            execute_input_with_covenants(&bad_route_table_tx, vec![player_utxo], 0).is_err(),
            "Player must reject a route-family table that does not match the stored digest"
        );

        let pawn_next = board_state(7, 1);
        let mux_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x63; 32]), index: 0 };
        let mux_utxo =
            builder.covenant_utxo("Mux", mux_initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Mux utxo builds");
        let pawn_output = builder.covenant_output("Pawn", pawn_next.clone(), input_value, 0, covenant_id).expect("Pawn output builds");
        let choose_pawn_sigscript = builder
            .p2sh_signature_script("Mux", "choose_pawn", mux_initial.clone(), Vec::new())
            .expect("choose_pawn sigscript fills Pawn template lens");
        let choose_pawn_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(mux_outpoint, choose_pawn_sigscript.clone())], vec![pawn_output]);
        execute_input_with_covenants(&choose_pawn_tx, vec![mux_utxo.clone()], 0).expect("Mux can route to Pawn by table slice");

        let dynamic_pawn_next = board_state(7, 1);
        let dynamic_pawn_output = builder
            .covenant_output("Pawn", dynamic_pawn_next.clone(), input_value, 0, covenant_id)
            .expect("dynamic Pawn output builds");
        let dynamic_pawn_sigscript = builder
            .p2sh_signature_script_with_template_selector(
                "Mux",
                "choose",
                mux_initial.clone(),
                vec![ArtifactValue::Int(0)],
                "target",
                "Pawn",
            )
            .expect("selector sigscript fills Pawn template lens");
        let dynamic_pawn_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, dynamic_pawn_sigscript.clone())],
            vec![dynamic_pawn_output],
        );
        execute_input_with_covenants(&dynamic_pawn_tx, vec![mux_utxo.clone()], 0)
            .expect("Mux can route through an actor enum selector");

        let dynamic_knight_output =
            builder.covenant_output("Knight", board_state(7, 1), input_value, 0, covenant_id).expect("dynamic Knight output builds");
        let dynamic_knight_sigscript = builder
            .p2sh_signature_script_with_template_selector(
                "Mux",
                "choose",
                mux_initial.clone(),
                vec![ArtifactValue::Int(1)],
                "target",
                "Knight",
            )
            .expect("selector sigscript fills Knight template lens");
        let dynamic_knight_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, dynamic_knight_sigscript)],
            vec![dynamic_knight_output],
        );
        execute_input_with_covenants(&dynamic_knight_tx, vec![mux_utxo.clone()], 0)
            .expect("Mux selector can choose the second table entry");

        let missing_selector = builder
            .p2sh_signature_script("Mux", "choose", mux_initial.clone(), vec![ArtifactValue::Int(0)])
            .expect_err("selector entries require an explicit template choice");
        assert!(
            matches!(missing_selector, BuilderError::MissingTemplateSelectorChoice { ref selector } if selector == "target"),
            "unexpected error: {missing_selector}"
        );

        let invalid_selector = builder
            .p2sh_signature_script_with_template_selector(
                "Mux",
                "choose",
                mux_initial.clone(),
                vec![ArtifactValue::Int(0)],
                "target",
                "League",
            )
            .expect_err("selector must choose one of the actor enum variants");
        assert!(
            matches!(
                invalid_selector,
                BuilderError::InvalidTemplateSelectorChoice { ref selector, ref actor }
                    if selector == "target" && actor == "League"
            ),
            "unexpected error: {invalid_selector}"
        );

        let out_of_range_selector = builder
            .p2sh_signature_script_with_template_selector(
                "Mux",
                "choose",
                mux_initial.clone(),
                vec![ArtifactValue::Int(2)],
                "target",
                "Pawn",
            )
            .expect("selector sigscript can encode an out-of-range selector value");
        let out_of_range_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, out_of_range_selector)],
            vec![
                builder
                    .covenant_output("Pawn", board_state(7, 1), input_value, 0, covenant_id)
                    .expect("out-of-range Pawn output builds"),
            ],
        );
        assert!(
            execute_input_with_covenants(&out_of_range_tx, vec![mux_utxo.clone()], 0).is_err(),
            "selector index must be bounded by the actor enum variant count"
        );

        let wrong_selector_witness = builder
            .p2sh_signature_script_with_template_selector(
                "Mux",
                "choose",
                mux_initial.clone(),
                vec![ArtifactValue::Int(0)],
                "target",
                "Knight",
            )
            .expect("selector sigscript can encode mismatched witness material");
        let wrong_selector_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, wrong_selector_witness)],
            vec![
                builder
                    .covenant_output("Pawn", dynamic_pawn_next, input_value, 0, covenant_id)
                    .expect("dynamic wrong-witness Pawn output builds"),
            ],
        );
        assert!(
            execute_input_with_covenants(&wrong_selector_tx, vec![mux_utxo.clone()], 0).is_err(),
            "selector witness must match the actor selected by table index"
        );

        let const_knight_sigscript = builder
            .p2sh_signature_script("Mux", "choose_knight_const", mux_initial.clone(), Vec::new())
            .expect("fixed actor enum selector fills Knight template lens");
        let const_knight_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, const_knight_sigscript.clone())],
            vec![
                builder.covenant_output("Knight", board_state(7, 1), input_value, 0, covenant_id).expect("const Knight output builds"),
            ],
        );
        execute_input_with_covenants(&const_knight_tx, vec![mux_utxo.clone()], 0)
            .expect("fixed actor enum selector can route to Knight without caller selector metadata");

        let const_wrong_output = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, const_knight_sigscript)],
            vec![
                builder
                    .covenant_output("Pawn", board_state(7, 1), input_value, 0, covenant_id)
                    .expect("const wrong Pawn output builds"),
            ],
        );
        assert!(
            execute_input_with_covenants(&const_wrong_output, vec![mux_utxo.clone()], 0).is_err(),
            "fixed actor enum selector must reject a non-Knight output"
        );

        let wrong_worker_output =
            builder.covenant_output("Knight", pawn_next, input_value, 0, covenant_id).expect("wrong worker output builds");
        let wrong_worker_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(mux_outpoint, choose_pawn_sigscript)], vec![wrong_worker_output]);
        assert!(
            execute_input_with_covenants(&wrong_worker_tx, vec![mux_utxo], 0).is_err(),
            "choose_pawn must reject an output using the wrong worker template"
        );
    }

    #[test]
    fn builder_rejects_template_plan_hash_mismatch() {
        let mut artifact = tickets_artifact();
        artifact.verify_template_plan().expect("fixture receipt verifies before mutation");
        let ticket_receipt = artifact
            .argent
            .template_plan
            .templates
            .iter_mut()
            .find(|template| template.actor == "Ticket")
            .expect("Ticket template receipt exists");
        ticket_receipt.hash_hex = "00".repeat(32);

        let err = match TxBuilder::new(&artifact) {
            Ok(_) => panic!("builder must reject a corrupted template plan receipt"),
            Err(err) => err,
        };
        assert!(
            matches!(err, BuilderError::TemplatePlan(TemplatePlanError::TemplateHashMismatch { ref id, .. }) if id == "template/ticket"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn builder_rejects_route_template_table_mismatch() {
        let mut artifact = example_artifact("examples/toy_chess/app.ag", "toy-chess-route-table-plan");
        artifact.verify_template_plan().expect("fixture receipt verifies before mutation");
        let table = artifact
            .argent
            .template_plan
            .route_tables
            .iter_mut()
            .find(|table| table.id == route_template_table_receipt_id("BoardState", "gen__mux_routes"))
            .expect("BoardState route table receipt exists");
        table.entries[1].offset = 33;

        let err = match TxBuilder::new(&artifact) {
            Ok(_) => panic!("builder must reject a corrupted route template table receipt"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                BuilderError::TemplatePlan(TemplatePlanError::RouteTableOffsetMismatch {
                    ref id,
                    index: 1,
                    offset: 33,
                    expected: 32,
                }) if id == "route_table/BoardState/gen__mux_routes"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn builder_rejects_route_template_merkle_proof_mismatch() {
        let mut artifact = example_artifact("examples/toy_chess/app.ag", "toy-chess-route-proof-plan");
        artifact.verify_template_plan().expect("fixture receipt verifies before mutation");
        let proof = artifact
            .argent
            .template_plan
            .route_proofs
            .iter_mut()
            .find(|proof| proof.id == route_template_proof_receipt_id("BoardState", "gen__mux_routes"))
            .expect("BoardState route proof receipt exists");
        proof.leaves[1].proof[0].hash_hex = "00".repeat(32);

        let err = match TxBuilder::new(&artifact) {
            Ok(_) => panic!("builder must reject a corrupted route template proof receipt"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err,
                BuilderError::TemplatePlan(TemplatePlanError::RouteProofMismatch {
                    ref id,
                    index: 1,
                    ..
                }) if id == "route_proof/BoardState/gen__mux_routes"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn same_template_shortcut_redeems_self_transition_and_rejects_changed_template() {
        let artifact = inline_artifact(
            "same-template-shortcut",
            r#"
            state FooState {
                int count;
            }

            actor Foo owns FooState {
                entry bump(amount: int) emits one Foo {
                    State next_state = {
                        count: count + amount,
                    };
                    become Foo(next_state);
                }
            }

            actor Bar owns FooState {
                entry noop() emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Foo;
                actor Bar;
            }
            "#,
        );
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let foo_bump = builder.entry("Foo", "bump").expect("bump entry exists");
        assert!(foo_bump.hidden_params.is_empty(), "same-template route should not need hidden template witnesses");

        let initial = count_state(4);
        let next = count_state(9);
        let covenant_id = Hash::from_bytes([0x51; 32]);
        let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x52; 32]), index: 0 };
        let input_value = 1_000;

        let input_utxo =
            builder.covenant_utxo("Foo", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("foo utxo builds");
        let output = builder.covenant_output("Foo", next.clone(), input_value, 0, covenant_id).expect("foo output builds");
        let sigscript =
            builder.p2sh_signature_script("Foo", "bump", initial.clone(), vec![ArtifactValue::Int(5)]).expect("bump sigscript builds");
        let tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, sigscript.clone())], vec![output]);

        execute_input_with_covenants(&tx, vec![input_utxo.clone()], 0).expect("same-template transition passes");

        let wrong_template_output =
            builder.covenant_output("Bar", next, input_value, 0, covenant_id).expect("bar output builds with same source state");
        let wrong_template_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, sigscript)], vec![wrong_template_output]);
        assert!(
            execute_input_with_covenants(&wrong_template_tx, vec![input_utxo], 0).is_err(),
            "same-template validation must reject a different actor template"
        );
    }

    #[test]
    fn exact_continuation_shortcut_redeems_register_player_and_rejects_changed_state() {
        let artifact = example_artifact("examples/stones/app.ag", "stones-exact-continuation");
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let register_player = builder.entry("League", "register_player").expect("register_player entry exists");
        assert_eq!(
            register_player.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            ["gen__player_prefix", "gen__player_suffix"],
            "exact league continuation should not need League template witnesses"
        );

        let owner = keypair_from_byte(8);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let owner_hash = blake2b32(&owner_pk);
        let covenant_id = Hash::from_bytes([0x53; 32]);
        let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x54; 32]), index: 0 };
        let league_initial = league_state(vec![0x55; 32], 7, 3);
        let player_id = stones_player_id(&outpoint);
        let player_next = player_state(owner_hash, player_id, 0, 0, 0, 0);
        let input_value = 10_000;
        let player_value = 500;

        let league_utxo = builder
            .covenant_utxo("League", league_initial.clone(), input_value, 0, false, Some(covenant_id))
            .expect("league utxo builds");
        let entries = vec![league_utxo.clone()];
        let outputs = builder
            .terminal_path_outputs(TerminalPathOutputRequest {
                actor_name: "League",
                entry_name: "register_player",
                path_index: 0,
                output_states: BTreeMap::from([
                    ("league".to_string(), league_initial.clone()),
                    ("player".to_string(), player_next.clone()),
                ]),
                output_values: BTreeMap::from([("league".to_string(), input_value), ("player".to_string(), player_value)]),
                authorizing_input: 0,
                covenant_id,
            })
            .expect("register outputs build");
        let unsigned_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, Vec::new())], outputs.clone());
        let signature = sign_input(&unsigned_tx, entries.clone(), 0, &owner);
        let sigscript = builder
            .p2sh_signature_script(
                "League",
                "register_player",
                league_initial.clone(),
                vec![ArtifactValue::Bytes(signature.clone()), ArtifactValue::Bytes(owner_pk.clone())],
            )
            .expect("register sigscript builds");
        let tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, sigscript)], outputs.clone());

        execute_input_with_covenants(&tx, entries.clone(), 0).expect("exact continuation register_player passes");

        let player_template = &builder.contract("Player").expect("Player contract exists").compiled.template;
        let register_entry =
            builder.contract("League").expect("League contract exists").entry("register_player").expect("register_player exists");
        let mut bad_prefix = decode_hex(&player_template.prefix_hex).expect("player prefix decodes");
        bad_prefix.push(0);
        let bad_prefix_sigscript = encode_entry_sig_script(
            &artifact.sil_abi,
            builder.contract("League").expect("League contract exists"),
            register_entry,
            &[
                ArtifactValue::Bytes(signature),
                ArtifactValue::Bytes(owner_pk.clone()),
                ArtifactValue::Bytes(bad_prefix),
                ArtifactValue::Bytes(decode_hex(&player_template.suffix_hex).expect("player suffix decodes")),
            ],
        )
        .expect("bad prefix sigscript encodes");
        let bad_prefix_sigscript = pay_to_script_hash_signature_script_with_flags(
            builder.redeem_script("League", league_initial.clone()).expect("league redeem script builds"),
            bad_prefix_sigscript,
            covenant_engine_flags(),
        )
        .expect("bad prefix p2sh sigscript builds");
        let bad_prefix_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, bad_prefix_sigscript)], outputs.clone());
        assert!(
            execute_input_with_covenants(&bad_prefix_tx, entries.clone(), 0).is_err(),
            "register_player must reject a corrupted Player template prefix"
        );

        let changed_league_state = league_state(vec![0x56; 32], 7, 3);
        let bad_outputs = builder
            .terminal_path_outputs(TerminalPathOutputRequest {
                actor_name: "League",
                entry_name: "register_player",
                path_index: 0,
                output_states: BTreeMap::from([("league".to_string(), changed_league_state), ("player".to_string(), player_next)]),
                output_values: BTreeMap::from([("league".to_string(), input_value), ("player".to_string(), player_value)]),
                authorizing_input: 0,
                covenant_id,
            })
            .expect("bad register outputs build");
        let bad_unsigned_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, Vec::new())], bad_outputs.clone());
        let bad_signature = sign_input(&bad_unsigned_tx, entries.clone(), 0, &owner);
        let bad_sigscript = builder
            .p2sh_signature_script(
                "League",
                "register_player",
                league_initial,
                vec![ArtifactValue::Bytes(bad_signature), ArtifactValue::Bytes(owner_pk)],
            )
            .expect("bad register sigscript builds");
        let bad_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, bad_sigscript)], bad_outputs);
        assert!(execute_input_with_covenants(&bad_tx, entries, 0).is_err(), "exact continuation must reject a changed League state");
    }

    #[test]
    fn observed_covenant_runtime_builds_icc_mint_and_rejects_mismatches() {
        let controller_artifact = icc_controller_artifact();
        let asset_artifact = icc_asset_artifact();
        let bundle = ArtifactBundle::new(&controller_artifact)
            .expect("bundle accepts controller artifact")
            .with_app("asset", &asset_artifact)
            .expect("bundle accepts observed asset artifact");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts artifact bundle");
        let owner = keypair_from_byte(9);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let recipient_owner = [0x55; 32].to_vec();
        let controller_covenant_id = Hash::from_bytes([0xc0; 32]);
        let asset_covenant_id = Hash::from_bytes([0xa5; 32]);
        let wrong_asset_covenant_id = Hash::from_bytes([0xee; 32]);
        let minter_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x11; 32]), index: 0 };
        let proxy_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x22; 32]), index: 0 };
        let minter_value = 3_000;
        let proxy_value = 2_000;
        let recipient_value = 1_000;
        let minted_amount = 17;

        let minter_initial = minter_state(owner_pk.clone(), asset_covenant_id, 100, true);
        let minter_next = minter_state(owner_pk.clone(), asset_covenant_id, 83, true);
        let proxy_state = minter_proxy_state(controller_covenant_id);
        let recipient_state = kcc20_state(recipient_owner.clone(), minted_amount);

        let mut explicit_observed_template_state = minter_initial.clone();
        explicit_observed_template_state.insert("gen__asset_kcc20_template".to_string(), ArtifactValue::Bytes(vec![0; 32]));
        let hidden_field_err = builder
            .covenant_output("Minter", explicit_observed_template_state, minter_value, 0, controller_covenant_id)
            .expect_err("observed template fields must be filled by the runtime");
        assert!(
            matches!(hidden_field_err, BuilderError::HiddenRuntimeFieldProvided { ref field, .. } if field == "gen__asset_kcc20_template"),
            "unexpected error: {hidden_field_err}"
        );

        let observed = observed_asset_context(
            "MinterProxy",
            proxy_state.clone(),
            builder
                .covenant_utxo_in_app("asset", "MinterProxy", proxy_state.clone(), proxy_value, 0, false, Some(asset_covenant_id))
                .expect("proxy utxo builds"),
            "KCC20",
            recipient_state.clone(),
        );
        let outputs = icc_mint_outputs(
            &builder,
            minter_next.clone(),
            &observed,
            minter_value,
            proxy_value,
            recipient_value,
            controller_covenant_id,
            asset_covenant_id,
        );
        let minter_utxo = builder
            .covenant_utxo("Minter", minter_initial.clone(), minter_value, 0, false, Some(controller_covenant_id))
            .expect("minter utxo builds");
        let proxy_utxo = observed.get("asset").unwrap().inputs.get("proxy").unwrap().utxo.clone();
        let entries = vec![minter_utxo.clone(), proxy_utxo.clone()];
        let proxy_sigscript = builder
            .p2sh_signature_script_in_app(
                "asset",
                "MinterProxy",
                "mint",
                proxy_state.clone(),
                vec![ArtifactValue::Object(proxy_state.clone()), ArtifactValue::Object(recipient_state.clone())],
            )
            .expect("proxy mint sigscript builds");
        let unsigned_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, Vec::new()),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript.clone()),
            ],
            outputs.clone(),
        );
        let signature = sign_input(&unsigned_tx, entries.clone(), 0, &owner);
        let sigscript = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                minter_initial.clone(),
                vec![
                    ArtifactValue::Bytes(signature),
                    ArtifactValue::Bytes(recipient_owner.clone()),
                    ArtifactValue::Int(minted_amount),
                ],
                &observed,
            )
            .expect("observed mint sigscript builds");
        let tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, sigscript),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript.clone()),
            ],
            outputs,
        );
        execute_input_with_covenants(&tx, entries.clone(), 0).expect("observed ICC mint passes");

        let minter_contract = builder.contract("Minter").expect("Minter contract exists");
        let minter_entry = minter_contract.entry("mint").expect("mint entry exists");
        let mut bad_proxy_suffix = decode_hex(&builder.contract_in_app("asset", "MinterProxy").unwrap().compiled.template.suffix_hex)
            .expect("proxy suffix decodes");
        bad_proxy_suffix.push(0);
        let corrupt_hidden_sigscript = encode_entry_sig_script(
            &controller_artifact.sil_abi,
            minter_contract,
            minter_entry,
            &[
                ArtifactValue::Bytes(sign_input(&unsigned_tx, entries.clone(), 0, &owner)),
                ArtifactValue::Bytes(recipient_owner.clone()),
                ArtifactValue::Int(minted_amount),
                ArtifactValue::Bytes(
                    decode_hex(&builder.contract_in_app("asset", "MinterProxy").unwrap().compiled.template.prefix_hex)
                        .expect("proxy prefix decodes"),
                ),
                ArtifactValue::Bytes(bad_proxy_suffix),
                ArtifactValue::Bytes(
                    decode_hex(&builder.contract_in_app("asset", "KCC20").unwrap().compiled.template.prefix_hex)
                        .expect("KCC20 prefix decodes"),
                ),
                ArtifactValue::Bytes(
                    decode_hex(&builder.contract_in_app("asset", "KCC20").unwrap().compiled.template.suffix_hex)
                        .expect("KCC20 suffix decodes"),
                ),
            ],
        )
        .expect("manual corrupt observed sigscript encodes");
        let corrupt_hidden_sigscript = pay_to_script_hash_signature_script_with_flags(
            builder.redeem_script("Minter", minter_initial.clone()).expect("Minter redeem script builds"),
            corrupt_hidden_sigscript,
            covenant_engine_flags(),
        )
        .expect("corrupt P2SH sigscript builds");
        let corrupt_hidden_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, corrupt_hidden_sigscript),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript.clone()),
            ],
            tx.outputs.clone(),
        );
        assert!(execute_input_with_covenants(&corrupt_hidden_tx, entries.clone(), 0).is_err());

        let missing_proxy = BTreeMap::from([(
            "asset".to_string(),
            ObservedCovenantContext { inputs: BTreeMap::new(), outputs: observed.get("asset").unwrap().outputs.clone() },
        )]);
        let missing_proxy_err = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                minter_initial.clone(),
                vec![
                    ArtifactValue::Bytes(sign_input(&unsigned_tx, entries.clone(), 0, &owner)),
                    ArtifactValue::Bytes(recipient_owner.clone()),
                    ArtifactValue::Int(minted_amount),
                ],
                &missing_proxy,
            )
            .expect_err("missing observed input is rejected by the runtime");
        assert!(matches!(missing_proxy_err, BuilderError::MissingObservedActor { side: "input", handle, .. } if handle == "proxy"));

        let wrong_proxy_state = minter_proxy_state(Hash::from_bytes([0xd0; 32]));
        let wrong_observed =
            observed_asset_context("MinterProxy", wrong_proxy_state, proxy_utxo.clone(), "KCC20", recipient_state.clone());
        let wrong_proxy_err = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                minter_initial.clone(),
                vec![
                    ArtifactValue::Bytes(sign_input(&unsigned_tx, entries.clone(), 0, &owner)),
                    ArtifactValue::Bytes(recipient_owner.clone()),
                    ArtifactValue::Int(minted_amount),
                ],
                &wrong_observed,
            )
            .expect_err("observed input state must match its UTXO script");
        assert!(matches!(wrong_proxy_err, BuilderError::ObservedUtxoScriptMismatch { handle, .. } if handle == "proxy"));

        let wrong_recipient_outputs = icc_mint_outputs(
            &builder,
            minter_next.clone(),
            &observed_asset_context(
                "MinterProxy",
                proxy_state.clone(),
                proxy_utxo.clone(),
                "KCC20",
                kcc20_state(recipient_owner.clone(), minted_amount + 1),
            ),
            minter_value,
            proxy_value,
            recipient_value,
            controller_covenant_id,
            asset_covenant_id,
        );
        let wrong_recipient_unsigned = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, Vec::new()),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript.clone()),
            ],
            wrong_recipient_outputs.clone(),
        );
        let wrong_recipient_sigscript = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                minter_initial.clone(),
                vec![
                    ArtifactValue::Bytes(sign_input(&wrong_recipient_unsigned, entries.clone(), 0, &owner)),
                    ArtifactValue::Bytes(recipient_owner.clone()),
                    ArtifactValue::Int(minted_amount),
                ],
                &observed,
            )
            .expect("wrong-recipient sigscript still builds");
        let wrong_recipient_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, wrong_recipient_sigscript),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript.clone()),
            ],
            wrong_recipient_outputs,
        );
        assert!(execute_input_with_covenants(&wrong_recipient_tx, entries.clone(), 0).is_err());

        let wrong_asset_minter_initial = minter_state(owner_pk.clone(), wrong_asset_covenant_id, 100, true);
        let wrong_asset_minter_next = minter_state(owner_pk, wrong_asset_covenant_id, 83, true);
        let wrong_asset_outputs = icc_mint_outputs(
            &builder,
            wrong_asset_minter_next,
            &observed,
            minter_value,
            proxy_value,
            recipient_value,
            controller_covenant_id,
            asset_covenant_id,
        );
        let wrong_asset_minter_utxo = builder
            .covenant_utxo("Minter", wrong_asset_minter_initial.clone(), minter_value, 0, false, Some(controller_covenant_id))
            .expect("wrong-asset minter utxo builds");
        let wrong_asset_entries = vec![wrong_asset_minter_utxo, proxy_utxo];
        let wrong_asset_unsigned = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, Vec::new()),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript.clone()),
            ],
            wrong_asset_outputs.clone(),
        );
        let wrong_asset_sigscript = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                wrong_asset_minter_initial,
                vec![
                    ArtifactValue::Bytes(sign_input(&wrong_asset_unsigned, wrong_asset_entries.clone(), 0, &owner)),
                    ArtifactValue::Bytes(recipient_owner),
                    ArtifactValue::Int(minted_amount),
                ],
                &observed,
            )
            .expect("wrong-asset sigscript still builds");
        let wrong_asset_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(minter_outpoint, wrong_asset_sigscript),
                TxBuilder::transaction_input(proxy_outpoint, proxy_sigscript),
            ],
            wrong_asset_outputs,
        );
        assert!(execute_input_with_covenants(&wrong_asset_tx, wrong_asset_entries, 0).is_err());
    }

    #[test]
    fn artifact_bundle_rejects_bad_ids_and_interface_mismatches() {
        let controller_artifact = icc_controller_artifact();
        let asset_artifact = icc_asset_artifact();

        controller_artifact.verify_id().expect("controller artifact id is stable");
        asset_artifact.verify_id().expect("asset artifact id is stable");
        let bundle = ArtifactBundle::new(&controller_artifact)
            .expect("bundle accepts controller artifact")
            .with_app("asset", &asset_artifact)
            .expect("matching observed artifact attaches");
        TxBuilder::from_bundle(&bundle).expect("builder accepts valid bundle");
        TxBuilder::new(&controller_artifact)
            .expect("builder accepts controller artifact")
            .with_observed_artifact(&asset_artifact)
            .expect("legacy observed artifact attach infers the observed alias")
            .contract_in_app("asset", "MinterProxy")
            .expect("inferred alias exposes the observed asset app");

        let wrong_alias_err = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact remains valid")
            .with_app("wrong", &asset_artifact)
            .expect_err("unknown observed app alias is rejected");
        assert!(matches!(wrong_alias_err, BuilderError::UnknownObservedAppAlias(alias) if alias == "wrong"));

        let mut bad_id_asset = asset_artifact.clone();
        bad_id_asset.id = "00".repeat(32);
        let bad_id_err = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact remains valid")
            .with_app("asset", &bad_id_asset)
            .expect_err("bad observed artifact id is rejected");
        assert!(matches!(bad_id_err, BuilderError::ArtifactIdentity { app, .. } if app == "asset"));

        let mut bad_interface_asset = asset_artifact.clone();
        let proxy_export = bad_interface_asset
            .argent
            .interfaces
            .exports
            .iter_mut()
            .find(|interface| interface.actor == "MinterProxy")
            .expect("asset exports MinterProxy");
        proxy_export.fingerprint_hex = "11".repeat(32);
        bad_interface_asset.id = bad_interface_asset.computed_id_hex().expect("mutated artifact id computes");
        let mismatch_err = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact remains valid")
            .with_app("asset", &bad_interface_asset)
            .expect_err("interface fingerprint mismatch is rejected");
        assert!(
            matches!(&mismatch_err, BuilderError::InterfaceMismatch { app, actor, .. } if app == "asset" && actor == "MinterProxy"),
            "unexpected error: {mismatch_err}"
        );
    }

    #[test]
    fn open_icc_baseline_spends_core_and_agent_covenants() {
        let core_artifact = open_icc_core_artifact();
        let agent_artifact = open_icc_agent_artifact();
        let bundle = ArtifactBundle::new(&core_artifact)
            .expect("bundle accepts open ICC core")
            .with_app("agent", &agent_artifact)
            .expect("bundle accepts open ICC agent app");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts open ICC bundle");

        let controller_covenant_id = Hash::from_bytes([0x31; 32]);
        let agent_covenant_id = Hash::from_bytes([0x41; 32]);
        let cell_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x51; 32]), index: 0 };
        let agent_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x52; 32]), index: 0 };
        let cell_value = 4_000;
        let agent_value = 2_000;
        let caps_digest = vec![0x77; 32];

        let cell_initial = open_cell_state(agent_covenant_id, 7);
        let cell_next = open_cell_state(agent_covenant_id, 8);
        let agent_initial = open_agent_state(controller_covenant_id, caps_digest.clone(), 5);
        let agent_next = open_agent_state(controller_covenant_id, caps_digest, 4);

        let agent_utxo = builder
            .covenant_utxo_in_app("agent", "Agent", agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("agent utxo builds");
        let observed = open_agent_context("Agent", agent_initial.clone(), agent_utxo.clone(), agent_next.clone());
        let outputs = open_icc_advance_outputs(
            &builder,
            cell_next,
            &observed,
            cell_value,
            agent_value,
            controller_covenant_id,
            agent_covenant_id,
        );
        let cell_utxo = builder
            .covenant_utxo("Cell", cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("cell utxo builds");
        let entries = vec![cell_utxo, agent_utxo];
        let agent_sigscript = builder
            .p2sh_signature_script_in_app(
                "agent",
                "Agent",
                "step",
                agent_initial.clone(),
                vec![ArtifactValue::Object(agent_next.clone())],
            )
            .expect("agent step sigscript builds");
        let cell_sigscript = builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_initial.clone(), vec![], &observed)
            .expect("cell advance sigscript builds");
        let tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(cell_outpoint, cell_sigscript),
                TxBuilder::transaction_input(agent_outpoint, agent_sigscript),
            ],
            outputs,
        );
        execute_input_with_covenants(&tx, entries.clone(), 0).expect("core cell input passes");
        execute_input_with_covenants(&tx, entries.clone(), 1).expect("agent input passes");

        let wrong_agent_next = open_agent_state(controller_covenant_id, vec![0x77; 32], 5);
        let wrong_observed = open_agent_context("Agent", agent_initial.clone(), entries[1].clone(), wrong_agent_next.clone());
        let wrong_outputs = open_icc_advance_outputs(
            &builder,
            open_cell_state(agent_covenant_id, 8),
            &wrong_observed,
            cell_value,
            agent_value,
            controller_covenant_id,
            agent_covenant_id,
        );
        let wrong_agent_sigscript = builder
            .p2sh_signature_script_in_app(
                "agent",
                "Agent",
                "step",
                agent_initial.clone(),
                vec![ArtifactValue::Object(wrong_agent_next)],
            )
            .expect("agent accepts controller-authorized non-physics state");
        let wrong_cell_sigscript = builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_initial.clone(), vec![], &observed)
            .expect("cell sigscript builds for wrong-output tx");
        let wrong_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(cell_outpoint, wrong_cell_sigscript),
                TxBuilder::transaction_input(agent_outpoint, wrong_agent_sigscript),
            ],
            wrong_outputs,
        );
        assert!(
            execute_input_with_covenants(&wrong_tx, entries.clone(), 0).is_err(),
            "core physics rejects an agent output that does not spend one energy"
        );
        execute_input_with_covenants(&wrong_tx, entries, 1).expect("agent still accepts authorized header-preserving output");
    }

    fn tickets_artifact() -> Artifact {
        example_artifact("examples/tickets.ag", "tickets")
    }

    fn icc_controller_artifact() -> Artifact {
        example_artifact("examples/icc/minter.ag", "icc-controller")
    }

    fn icc_asset_artifact() -> Artifact {
        example_artifact("examples/icc/kcc20_asset.ag", "icc-asset")
    }

    fn open_icc_core_artifact() -> Artifact {
        example_artifact("examples/open_icc/core.ag", "open-icc-core")
    }

    fn open_icc_agent_artifact() -> Artifact {
        example_artifact("examples/open_icc/agent.ag", "open-icc-agent")
    }

    fn inline_artifact(name: &str, source: &str) -> Artifact {
        let counter = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let out_dir = std::env::temp_dir().join(format!("argent-{name}-{}-{counter}", std::process::id()));
        let root = out_dir.join("app.ag");
        if out_dir.exists() {
            fs::remove_dir_all(&out_dir).expect("old temp dir removed");
        }
        fs::create_dir_all(&out_dir).expect("temp source dir created");
        fs::write(&root, source).expect("temp Argent source written");
        let artifact = example_artifact_from_path(root, name);
        fs::remove_dir_all(out_dir).expect("temp source dir removed");
        artifact
    }

    fn example_artifact(input: &str, name: &str) -> Artifact {
        example_artifact_from_path(PathBuf::from(input), name)
    }

    fn example_artifact_from_path(input: PathBuf, name: &str) -> Artifact {
        let counter = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let out_dir = std::env::temp_dir().join(format!("argent-{name}-{}-{counter}", std::process::id()));
        if out_dir.exists() {
            std::fs::remove_dir_all(&out_dir).expect("old temp dir removed");
        }
        let program = load_program(&input).expect("example source loads");
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

    fn count_state(count: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([("count".to_string(), ArtifactValue::Int(count))])
    }

    fn toy_player_state(nonce: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([("nonce".to_string(), ArtifactValue::Int(nonce))])
    }

    fn board_state(selector: i64, ply: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([("selector".to_string(), ArtifactValue::Int(selector)), ("ply".to_string(), ArtifactValue::Int(ply))])
    }

    fn minter_state(owner: Vec<u8>, kcc20_covid: Hash, amount: i64, initialized: bool) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("owner".to_string(), ArtifactValue::Bytes(owner)),
            ("kcc20_covid".to_string(), ArtifactValue::Bytes(kcc20_covid.as_bytes().to_vec())),
            ("amount".to_string(), ArtifactValue::Int(amount)),
            ("initialized".to_string(), ArtifactValue::Bool(initialized)),
        ])
    }

    fn minter_proxy_state(controller_id: Hash) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([("controller_id".to_string(), ArtifactValue::Bytes(controller_id.as_bytes().to_vec()))])
    }

    fn kcc20_state(owner_identifier: Vec<u8>, amount: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("owner_identifier".to_string(), ArtifactValue::Bytes(owner_identifier)),
            ("identifier_type".to_string(), ArtifactValue::Byte(0)),
            ("amount".to_string(), ArtifactValue::Int(amount)),
        ])
    }

    fn open_cell_state(agent_id: Hash, tick: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("agent_id".to_string(), ArtifactValue::Bytes(agent_id.as_bytes().to_vec())),
            ("tick".to_string(), ArtifactValue::Int(tick)),
        ])
    }

    fn open_agent_state(controller_id: Hash, caps_digest: Vec<u8>, energy: i64) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("controller_id".to_string(), ArtifactValue::Bytes(controller_id.as_bytes().to_vec())),
            ("caps_digest".to_string(), ArtifactValue::Bytes(caps_digest)),
            ("energy".to_string(), ArtifactValue::Int(energy)),
        ])
    }

    fn observed_asset_context(
        proxy_actor: &str,
        proxy_state: BTreeMap<String, ArtifactValue>,
        proxy_utxo: UtxoEntry,
        recipient_actor: &str,
        recipient_state: BTreeMap<String, ArtifactValue>,
    ) -> BTreeMap<String, ObservedCovenantContext> {
        BTreeMap::from([(
            "asset".to_string(),
            ObservedCovenantContext::new()
                .input("proxy", proxy_actor, proxy_utxo, proxy_state.clone())
                .output("proxy", proxy_actor, proxy_state)
                .output("recipient", recipient_actor, recipient_state),
        )])
    }

    #[allow(clippy::too_many_arguments)]
    fn icc_mint_outputs(
        builder: &TxBuilder<'_>,
        minter_next: BTreeMap<String, ArtifactValue>,
        observed: &BTreeMap<String, ObservedCovenantContext>,
        minter_value: u64,
        proxy_value: u64,
        recipient_value: u64,
        controller_covenant_id: Hash,
        asset_covenant_id: Hash,
    ) -> Vec<kaspa_consensus_core::tx::TransactionOutput> {
        let mut outputs = vec![
            builder
                .covenant_output("Minter", minter_next, minter_value, 0, controller_covenant_id)
                .expect("minter controller output builds"),
        ];
        outputs.extend(
            builder
                .observed_outputs(
                    "Minter",
                    "mint",
                    "asset",
                    observed.get("asset").expect("asset observed context exists"),
                    BTreeMap::from([("proxy".to_string(), proxy_value), ("recipient".to_string(), recipient_value)]),
                    1,
                    asset_covenant_id,
                )
                .expect("observed asset outputs build"),
        );
        outputs
    }

    fn open_agent_context(
        agent_actor: &str,
        agent_state: BTreeMap<String, ArtifactValue>,
        agent_utxo: UtxoEntry,
        next_agent_state: BTreeMap<String, ArtifactValue>,
    ) -> BTreeMap<String, ObservedCovenantContext> {
        BTreeMap::from([(
            "agent".to_string(),
            ObservedCovenantContext::new().input("agent", agent_actor, agent_utxo, agent_state).output(
                "agent",
                agent_actor,
                next_agent_state,
            ),
        )])
    }

    fn open_icc_advance_outputs(
        builder: &TxBuilder<'_>,
        cell_next: BTreeMap<String, ArtifactValue>,
        observed: &BTreeMap<String, ObservedCovenantContext>,
        cell_value: u64,
        agent_value: u64,
        controller_covenant_id: Hash,
        agent_covenant_id: Hash,
    ) -> Vec<kaspa_consensus_core::tx::TransactionOutput> {
        let mut outputs =
            vec![builder.covenant_output("Cell", cell_next, cell_value, 0, controller_covenant_id).expect("cell output builds")];
        outputs.extend(
            builder
                .observed_outputs(
                    "Cell",
                    "advance",
                    "agent",
                    observed.get("agent").expect("agent observed context exists"),
                    BTreeMap::from([("agent".to_string(), agent_value)]),
                    1,
                    agent_covenant_id,
                )
                .expect("agent output builds"),
        );
        outputs
    }

    fn stones_player_id(outpoint: &TransactionOutpoint) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"StonesPlayer");
        bytes.extend_from_slice(&outpoint.transaction_id.as_bytes());
        bytes.extend_from_slice(&outpoint.index.to_le_bytes());
        blake2b32(&bytes)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_start_game_tx(
        builder: &TxBuilder<'_>,
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

        TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(outpoint_a, leader_sigscript),
                TxBuilder::transaction_input(outpoint_b, delegate_sigscript),
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
