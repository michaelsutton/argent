pub use argent_runtime::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::{
            HiddenParamPurposeArtifact, HiddenParamSubjectArtifact, TemplatePlanError, TypeArtifact, route_template_proof_receipt_id,
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
        tx::{
            CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint, TransactionOutput,
            UtxoEntry,
        },
    };
    use kaspa_txscript::pay_to_script_hash_signature_script_with_flags;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    static ARTIFACT_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn subject_label(subject: &HiddenParamSubjectArtifact) -> &str {
        match subject {
            HiddenParamSubjectArtifact::Actor { actor } => actor,
            HiddenParamSubjectArtifact::ObservedActor { actor, .. } => actor,
            HiddenParamSubjectArtifact::ObservedOutputField { field, .. } => field,
            HiddenParamSubjectArtifact::RouteFamily { family_id } => family_id,
            HiddenParamSubjectArtifact::TemplateSelector { selector } => selector,
            HiddenParamSubjectArtifact::StateExpansion { memory_state, .. } => memory_state,
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
            .p2sh_signature_script("Ticket", "redeem", initial_state.clone(), args![signature, owner_pk.clone()])
            .expect("sigscript builds");
        let tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, sigscript)], vec![output]);

        execute_input_with_covenants(&tx, vec![input_utxo.clone()], 0).expect("valid redeem tx passes");

        let wrong_pk = keypair_from_byte(2).x_only_public_key().0.serialize().to_vec();
        let bad_sigscript = builder
            .p2sh_signature_script(
                "Ticket",
                "redeem",
                initial_state.clone(),
                args![sign_input(&unsigned_tx, vec![input_utxo.clone()], 0, &owner), wrong_pk],
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
                args![sign_input(&stale_unsigned_tx, vec![input_utxo.clone()], 0, &owner), owner_pk],
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
    fn expanded_actor_redeem_script_matches_capsule_template_cut() {
        let artifact = capsule_route_context_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts capsule route artifact");
        let state = state! {
            owner_kind: 1,
            owner_id: Hash::from_bytes([0x31; 32]),
            policy: state! {
                nonce: 4,
            },
            balance: 100,
        };
        let redeem_script = builder.redeem_script("ReserveAsset", state).expect("expanded redeem script builds");
        let receipt = artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == "ReserveAsset")
            .expect("ReserveAsset template receipt exists");
        let handle = receipt.actor_type_handle.as_ref().expect("ReserveAsset capsule handle exists");
        let prefix = decode_hex(&handle.template.prefix_hex).expect("capsule prefix decodes");
        let suffix = decode_hex(&handle.template.suffix_hex).expect("capsule suffix decodes");

        assert!(redeem_script.starts_with(&prefix));
        assert!(redeem_script.ends_with(&suffix));
        assert_eq!(
            builder.actor_type_handle("ReserveAsset", "AssetCapsule").expect("capsule handle resolves"),
            decode_hex(&handle.template.hash_hex).expect("capsule hash decodes")
        );
        assert_ne!(handle.template.hash_hex, receipt.canonical_template_hash);
        assert!(matches!(
            builder.actor_type_handle("ReserveAsset", "ReserveAssetState"),
            Err(BuilderError::MissingActorTypeHandle { actor, state })
                if actor == "ReserveAsset" && state == "ReserveAssetState"
        ));
    }

    #[test]
    fn p2sh_signature_script_accepts_user_args_only() {
        let artifact = tickets_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let owner = keypair_from_byte(1);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let source_state = ticket_state(blake2b32(&owner_pk), 7, 0);

        let err = builder
            .p2sh_signature_script("Ticket", "redeem", source_state, args![vec![1; 65], owner_pk, vec![2; 32], vec![3; 32]])
            .expect_err("user must not provide hidden prefix/suffix witnesses");

        assert!(matches!(err, BuilderError::Codec(CodecError::WrongArgumentCount { .. })));
    }

    #[test]
    fn fluent_transition_builds_and_verifies_signed_single_output() {
        let artifact = inline_artifact(
            "fluent-counter",
            r#"
            state CounterState {
                pubkey owner;
                int count;
            }

            actor Counter owns CounterState {
                entry bump(owner_sig: sig, delta: int) emits one Counter {
                    require(checkSig(owner_sig, owner));

                    CounterState next = {
                        owner: owner,
                        count: count + delta,
                    };

                    become Counter(next);
                }
            }

            app CounterApp {
                actor Counter;
            }
            "#,
        );
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let owner = keypair_from_byte(1);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let initial = state! { owner: owner_pk.clone(), count: 2 };
        let next = state! { owner: owner_pk, count: 5 };
        let input_value = 1_000;
        let covenant_id = Hash::from_bytes([0x42; 32]);
        let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x11; 32]), index: 0 };
        let input_utxo =
            builder.covenant_utxo("Counter", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("counter UTXO builds");

        let built = builder
            .transition("Counter", "bump")
            .input(outpoint, input_utxo.clone(), initial.clone())
            .expect(next)
            .preserve_value()
            .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), 3])
            .build()
            .expect("fluent transition builds");

        assert_eq!(built.transaction.inputs.len(), 1);
        assert_eq!(built.transaction.outputs.len(), 1);
        assert_eq!(built.transaction.version, 1);
        assert!(built.transaction.inputs[0].compute_commit.compute_budget().is_some());
        assert_eq!(built.transaction.outputs[0].value, input_value);
        assert_eq!(built.transaction.outputs[0].covenant, Some(CovenantBinding { authorizing_input: 0, covenant_id }));

        let err = builder
            .transition("Counter", "bump")
            .input(outpoint, input_utxo, initial.clone())
            .expect(initial)
            .preserve_value()
            .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), 3])
            .build()
            .expect_err("incorrect expected state must fail contract execution");
        assert!(matches!(err, BuilderError::TxScript(_)), "unexpected error: {err}");
    }

    #[test]
    fn fluent_transition_builds_paired_transfer_and_enforces_compute_mass() {
        let artifact = inline_artifact(
            "fluent-paired-transfer",
            r#"
            state BoxState {
                int units;
            }

            actor Left owns BoxState {
                entry shift(amount: int) consumes {
                    peer: Right;
                } emits {
                    left_out: Left;
                    peer_out: Right;
                } {
                    BoxState next_left = { units: units - amount, };
                    BoxState next_peer = { units: peer.units + amount, };

                    become {
                        left_out <- Left(next_left);
                        peer_out <- Right(next_peer);
                    };
                }
            }

            actor Right owns BoxState {
                delegate accept_shift() consumes {
                    leader: Left;
                } {}
            }

            app PairApp {
                actor Left;
                actor Right;
            }
            "#,
        );
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let covenant_id = Hash::from_bytes([0x66; 32]);
        let left_initial = state! { units: 10 };
        let right_initial = state! { units: 1 };
        let left_utxo =
            builder.covenant_utxo("Left", left_initial.clone(), 3_000, 0, false, Some(covenant_id)).expect("left UTXO builds");
        let right_utxo =
            builder.covenant_utxo("Right", right_initial.clone(), 2_000, 0, false, Some(covenant_id)).expect("right UTXO builds");
        let entries = vec![left_utxo.clone(), right_utxo.clone()];

        let built = builder
            .transition("Left", "shift")
            .args(args![3])
            .input(TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x61; 32]), index: 0 }, left_utxo, left_initial)
            .consume(
                "peer",
                "accept_shift",
                TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x62; 32]), index: 0 },
                right_utxo,
                right_initial,
                args![],
            )
            .output("left_out", state! { units: 7 }, 3_000)
            .output("peer_out", state! { units: 4 }, 2_000)
            .build()
            .expect("paired transition builds");

        assert_eq!(built.transaction.inputs.len(), 2);
        assert_eq!(built.transaction.outputs.len(), 2);
        assert!(built.transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));
        assert!(
            built
                .transaction
                .outputs
                .iter()
                .all(|output| { output.covenant == Some(CovenantBinding { authorizing_input: 0, covenant_id }) })
        );

        let mut oversized = built.transaction;
        oversized.outputs.extend((0..5).map(|_| TransactionOutput::new(1, ScriptPublicKey::from_vec(0, vec![0; 10_000]))));
        let err = execute_transaction_with_covenants(&mut oversized, entries).expect_err("oversized compute mass must fail");
        assert!(matches!(err, BuilderError::ComputeMassLimitExceeded { limit: 500_000, .. }), "unexpected error: {err}");
    }

    #[test]
    fn fluent_transition_builds_closed_icc_without_observed_context() {
        let controller_artifact =
            example_artifact("tests/fixtures/runtime/fluent_closed_icc/controller.ag", "fluent-closed-icc-controller");
        let asset_artifact = example_artifact("tests/fixtures/runtime/fluent_closed_icc/asset.ag", "fluent-closed-icc-asset");
        let bundle = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact is valid")
            .with_app("badge_asset", &asset_artifact)
            .expect("asset artifact attaches");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts bundle");
        let controller_covenant_id = Hash::from_bytes([0x70; 32]);
        let asset_covenant_id = Hash::from_bytes([0x71; 32]);
        let badge_owner = keypair_from_byte(6);
        let badge_owner_pk = badge_owner.x_only_public_key().0.serialize().to_vec();
        let controller_initial = state! { minted: 0 };
        let badge_initial = state! { owner: badge_owner_pk.clone(), controller_id: controller_covenant_id, balance: 10 };
        let controller_next = state! { minted: 7 };
        let badge_next = state! { owner: badge_owner_pk, controller_id: controller_covenant_id, balance: 17 };
        let controller_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x72; 32]), index: 0 };
        let badge_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x73; 32]), index: 0 };
        let controller_utxo = builder
            .covenant_utxo("Controller", controller_initial.clone(), 4_000, 0, false, Some(controller_covenant_id))
            .expect("controller UTXO builds");
        let badge_utxo = builder
            .covenant_utxo_in_app("badge_asset", "Badge", badge_initial.clone(), 2_000, 0, false, Some(asset_covenant_id))
            .expect("badge UTXO builds");

        let built = builder
            .transition("Controller", "mint")
            .args(args![asset_covenant_id, 7])
            .input(controller_outpoint, controller_utxo.clone(), controller_initial.clone())
            .output("controller", controller_next.clone(), 4_000)
            .co_spend_in_app_with(
                "badge_asset",
                "Badge",
                "apply",
                badge_outpoint,
                badge_utxo.clone(),
                badge_initial.clone(),
                |tx, input_idx| args![17, sign_mutable_input(tx, input_idx, &badge_owner)],
                badge_next.clone(),
                2_000,
            )
            .build()
            .expect("closed ICC transition builds without observed context");

        assert_eq!(built.transaction.inputs.len(), 2);
        assert_eq!(built.transaction.outputs.len(), 2);
        assert_eq!(built.transaction.outputs[0].covenant.unwrap().authorizing_input, 0);
        assert_eq!(built.transaction.outputs[1].covenant.unwrap().authorizing_input, 1);
        assert!(built.transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

        let context = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial.clone(),
                EntryCall::new("mint").args(args![asset_covenant_id, 7]),
                controller_outpoint,
                controller_utxo.clone(),
            )
            .argent_input(
                "badge_asset::Badge",
                badge_initial.clone(),
                EntryCall::new("apply").args_with(|tx, input_idx| args![17, sign_mutable_input(tx, input_idx, &badge_owner)]),
                badge_outpoint,
                badge_utxo.clone(),
            )
            .argent_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
            .argent_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
        let context_tx = builder.build(&context).expect("context resolves the closed observed covenant");
        assert!(context_tx.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

        let extra_output = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial.clone(),
                EntryCall::new("mint").args(args![asset_covenant_id, 7]),
                controller_outpoint,
                controller_utxo.clone(),
            )
            .argent_input(
                "badge_asset::Badge",
                badge_initial.clone(),
                EntryCall::new("apply").args(args![17, vec![0; 65]]),
                badge_outpoint,
                badge_utxo.clone(),
            )
            .argent_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
            .argent_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000)
            .argent_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
        let err = builder.build(&extra_output).expect_err("observed covenant output cardinality must be exact");
        assert!(
            matches!(
                err,
                BuilderError::ObservedCountMismatch { ref observe, side: "output", expected: 1, found: 2 }
                    if observe == "asset"
            ),
            "unexpected error: {err}"
        );

        let ordinary_badge_script = builder
            .script_public_key_in_app("badge_asset", "Badge", badge_next)
            .expect("ordinary output can reproduce the Badge script");
        let missing_metadata = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial,
                EntryCall::new("mint").args(args![asset_covenant_id, 7]),
                controller_outpoint,
                controller_utxo,
            )
            .argent_input(
                "badge_asset::Badge",
                badge_initial,
                EntryCall::new("apply").args(args![17, vec![0; 65]]),
                badge_outpoint,
                badge_utxo,
            )
            .argent_output("Controller", controller_next, CovenantBinding::new(0, controller_covenant_id), 4_000)
            .output(ordinary_badge_script, Some(CovenantBinding::new(1, asset_covenant_id)), 2_000);
        let err = builder.build(&missing_metadata).expect_err("observed outputs must retain Argent metadata");
        assert!(
            matches!(
                err,
                BuilderError::MissingObservedActorMetadata {
                    ref observe,
                    side: "output",
                    ref handle,
                    index: 1
                } if observe == "asset" && handle == "badge"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fluent_observed_co_spend_builds_transaction_dependent_args() {
        let controller_artifact =
            example_artifact("tests/fixtures/runtime/fluent_signed_observed/controller.ag", "fluent-signed-observed-controller");
        let asset_artifact =
            example_artifact("tests/fixtures/runtime/fluent_signed_observed/asset.ag", "fluent-signed-observed-asset");
        let bundle = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact is valid")
            .with_app("asset_app", &asset_artifact)
            .expect("asset artifact attaches");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts bundle");
        let controller_covenant_id = Hash::from_bytes([0x74; 32]);
        let asset_covenant_id = Hash::from_bytes([0x75; 32]);
        let owner = keypair_from_byte(7);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let next_owner_pk = keypair_from_byte(8).x_only_public_key().0.serialize().to_vec();
        let asset_type = builder.actor_type_handle("asset_app::Asset", "AssetState").expect("asset actor type resolves");
        let controller_initial = state! { asset_type: asset_type.clone(), swaps: 0 };
        let controller_next = state! { asset_type: asset_type, swaps: 1 };
        let asset_initial = state! { owner: owner_pk, amount: 10 };
        let asset_next = state! { owner: next_owner_pk.clone(), amount: 10 };
        let controller_utxo = builder
            .covenant_utxo("Controller", controller_initial.clone(), 4_000, 0, false, Some(controller_covenant_id))
            .expect("controller UTXO builds");
        let asset_utxo = builder
            .covenant_utxo_in_app("asset_app", "Asset", asset_initial.clone(), 2_000, 0, false, Some(asset_covenant_id))
            .expect("asset UTXO builds");
        let observed = ObservedCovenantContext::from_app("asset_app")
            .input("payment", "Asset", asset_utxo.clone(), asset_initial.clone())
            .output("reserve", "Asset", asset_next.clone());
        let controller_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x76; 32]), index: 0 };
        let asset_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x77; 32]), index: 0 };

        let built = builder
            .transition("Controller", "swap")
            .args(args![asset_covenant_id, next_owner_pk.clone()])
            .input(controller_outpoint, controller_utxo.clone(), controller_initial.clone())
            .observe("flow", observed.clone())
            .expect(controller_next.clone())
            .preserve_value()
            .co_spend_observed_with(
                "flow",
                "payment",
                "transfer",
                asset_outpoint,
                |tx, input_idx| args![next_owner_pk.clone(), sign_mutable_input(tx, input_idx, &owner)],
                2_000,
            )
            .build()
            .expect("signed observed co-spend builds");

        assert_eq!(built.transaction.inputs.len(), 2);
        assert_eq!(built.transaction.outputs.len(), 2);
        assert_eq!(built.transaction.outputs[1].covenant.unwrap().authorizing_input, 1);

        let err = builder
            .transition("Controller", "swap")
            .args(args![asset_covenant_id, next_owner_pk.clone()])
            .input(controller_outpoint, controller_utxo, controller_initial)
            .observe("flow", observed)
            .expect(controller_next)
            .preserve_value()
            .co_spend_observed_with(
                "flow",
                "payment",
                "transfer",
                asset_outpoint,
                move |_tx, _input_idx| args![next_owner_pk, vec![0; 65]],
                2_000,
            )
            .build()
            .expect_err("invalid observed co-spend signature must fail");
        assert!(matches!(err, BuilderError::TxScript(_)), "unexpected error: {err}");
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
            entry.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
            entry.witnesses.iter().map(|witness| witness.recipe_id.as_str()).collect::<Vec<_>>()
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
        let outputs = vec![
            builder.covenant_output("Player", next_a, input_a_value, 0, covenant_id).expect("player A output builds"),
            builder.covenant_output("Player", next_b, input_b_value, 0, covenant_id).expect("player B output builds"),
            builder.covenant_output("StonesGame", next_game, game_value, 0, covenant_id).expect("game output builds"),
        ];
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
            .p2sh_signature_script("Player", "start_game", initial_a, args![leader_sig, owner_a_pk, 0, 7, 3])
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
            .p2sh_signature_script("Player", "enter_mux", player_initial.clone(), args![])
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
            .p2sh_signature_script("Mux", "choose_pawn", mux_initial.clone(), args![])
            .expect("choose_pawn sigscript fills Pawn template lens");
        let choose_pawn_tx =
            TxBuilder::transaction(vec![TxBuilder::transaction_input(mux_outpoint, choose_pawn_sigscript.clone())], vec![pawn_output]);
        execute_input_with_covenants(&choose_pawn_tx, vec![mux_utxo.clone()], 0).expect("Mux can route to Pawn by table slice");

        let dynamic_pawn_next = board_state(7, 1);
        let dynamic_pawn_output = builder
            .covenant_output("Pawn", dynamic_pawn_next.clone(), input_value, 0, covenant_id)
            .expect("dynamic Pawn output builds");
        let dynamic_pawn_sigscript = builder
            .p2sh_signature_script("Mux", "choose", mux_initial.clone(), args![actor("Pawn")])
            .expect("selector sigscript fills Pawn template lens");
        let dynamic_pawn_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, dynamic_pawn_sigscript.clone())],
            vec![dynamic_pawn_output],
        );
        execute_input_with_covenants(&dynamic_pawn_tx, vec![mux_utxo.clone()], 0)
            .expect("Mux can route through an actor enum selector");

        let context = TxContext::new()
            .argent_input(
                "Mux",
                mux_initial.clone(),
                EntryCall::new("choose").args(args![actor("Pawn")]),
                mux_outpoint,
                mux_utxo.clone(),
            )
            .argent_output("Pawn", dynamic_pawn_next.clone(), CovenantBinding::new(0, covenant_id), input_value);
        let context_tx = builder.build(&context).expect("context builder resolves the dynamic route witnesses");
        assert!(context_tx.inputs[0].compute_commit.compute_budget().is_some());
        assert_eq!(context_tx.inputs[0].signature_script, dynamic_pawn_sigscript);

        let dynamic_knight_output =
            builder.covenant_output("Knight", board_state(7, 1), input_value, 0, covenant_id).expect("dynamic Knight output builds");
        let dynamic_knight_sigscript = builder
            .p2sh_signature_script("Mux", "choose", mux_initial.clone(), args![actor("Knight")])
            .expect("selector sigscript fills Knight template lens");
        let dynamic_knight_tx = TxBuilder::transaction(
            vec![TxBuilder::transaction_input(mux_outpoint, dynamic_knight_sigscript)],
            vec![dynamic_knight_output],
        );
        execute_input_with_covenants(&dynamic_knight_tx, vec![mux_utxo.clone()], 0)
            .expect("Mux selector can choose the second table entry");

        let missing_selector = builder
            .p2sh_signature_script("Mux", "choose", mux_initial.clone(), args![0])
            .expect_err("selector entries require an explicit template choice");
        assert!(
            matches!(missing_selector, BuilderError::MissingTemplateSelectorChoice { ref selector } if selector == "target"),
            "unexpected error: {missing_selector}"
        );

        let invalid_selector = builder
            .p2sh_signature_script("Mux", "choose", mux_initial.clone(), args![actor("League")])
            .expect_err("selector must choose one of the actor enum variants");
        assert!(
            matches!(
                invalid_selector,
                BuilderError::InvalidTemplateSelectorChoice { ref selector, ref actor }
                    if selector == "target" && actor == "League"
            ),
            "unexpected error: {invalid_selector}"
        );

        let wrong_selector_witness = builder
            .p2sh_signature_script("Mux", "choose", mux_initial.clone(), args![actor("Knight")])
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
            .p2sh_signature_script("Mux", "choose_knight_const", mux_initial.clone(), args![])
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
        ticket_receipt.canonical_template_hash = "00".repeat(32);

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
        let sigscript = builder.p2sh_signature_script("Foo", "bump", initial.clone(), args![5]).expect("bump sigscript builds");
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
        let outputs = vec![
            builder.covenant_output("League", league_initial.clone(), input_value, 0, covenant_id).expect("league output builds"),
            builder.covenant_output("Player", player_next.clone(), player_value, 0, covenant_id).expect("player output builds"),
        ];
        let unsigned_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, Vec::new())], outputs.clone());
        let signature = sign_input(&unsigned_tx, entries.clone(), 0, &owner);
        let sigscript = builder
            .p2sh_signature_script("League", "register_player", league_initial.clone(), args![signature.clone(), owner_pk.clone()])
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
        let bad_outputs = vec![
            builder.covenant_output("League", changed_league_state, input_value, 0, covenant_id).expect("league output builds"),
            builder.covenant_output("Player", player_next, player_value, 0, covenant_id).expect("player output builds"),
        ];
        let bad_unsigned_tx = TxBuilder::transaction(vec![TxBuilder::transaction_input(outpoint, Vec::new())], bad_outputs.clone());
        let bad_signature = sign_input(&bad_unsigned_tx, entries.clone(), 0, &owner);
        let bad_sigscript = builder
            .p2sh_signature_script("League", "register_player", league_initial, args![bad_signature, owner_pk])
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
            .with_app("kcc20_asset", &asset_artifact)
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
                .covenant_utxo_in_app(
                    "kcc20_asset",
                    "MinterProxy",
                    proxy_state.clone(),
                    proxy_value,
                    0,
                    false,
                    Some(asset_covenant_id),
                )
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
                "kcc20_asset",
                "MinterProxy",
                "mint",
                proxy_state.clone(),
                args![proxy_state.clone(), recipient_state.clone()],
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
        let inferred_sigscript = builder
            .p2sh_signature_script(
                "Minter",
                "mint",
                minter_initial.clone(),
                args![signature.clone(), recipient_owner.clone(), minted_amount],
            )
            .expect("closed observed template witnesses are inferred from the attached app");
        let sigscript = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                minter_initial.clone(),
                args![signature, recipient_owner.clone(), minted_amount],
                &observed,
            )
            .expect("observed mint sigscript builds");
        assert_eq!(inferred_sigscript, sigscript);
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
        let proxy_template = &builder.contract_in_app("kcc20_asset", "MinterProxy").unwrap().compiled.template;
        let proxy_prefix_len = decode_hex(&proxy_template.prefix_hex).expect("proxy prefix decodes").len() as i64;
        let bad_proxy_suffix_len = decode_hex(&proxy_template.suffix_hex).expect("proxy suffix decodes").len() as i64 + 1;
        let corrupt_hidden_sigscript = encode_entry_sig_script(
            &controller_artifact.sil_abi,
            minter_contract,
            minter_entry,
            &[
                ArtifactValue::Bytes(sign_input(&unsigned_tx, entries.clone(), 0, &owner)),
                ArtifactValue::Bytes(recipient_owner.clone()),
                ArtifactValue::Int(minted_amount),
                ArtifactValue::Int(proxy_prefix_len),
                ArtifactValue::Int(bad_proxy_suffix_len),
                ArtifactValue::Bytes(
                    decode_hex(&builder.contract_in_app("kcc20_asset", "KCC20").unwrap().compiled.template.prefix_hex)
                        .expect("KCC20 prefix decodes"),
                ),
                ArtifactValue::Bytes(
                    decode_hex(&builder.contract_in_app("kcc20_asset", "KCC20").unwrap().compiled.template.suffix_hex)
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
            ObservedCovenantContext {
                app: "kcc20_asset".to_string(),
                inputs: BTreeMap::new(),
                outputs: observed.get("asset").unwrap().outputs.clone(),
            },
        )]);
        let missing_proxy_err = builder
            .p2sh_signature_script_with_observed_covenants(
                "Minter",
                "mint",
                minter_initial.clone(),
                args![sign_input(&unsigned_tx, entries.clone(), 0, &owner), recipient_owner.clone(), minted_amount],
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
                args![sign_input(&unsigned_tx, entries.clone(), 0, &owner), recipient_owner.clone(), minted_amount],
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
                args![sign_input(&wrong_recipient_unsigned, entries.clone(), 0, &owner), recipient_owner.clone(), minted_amount],
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
                args![sign_input(&wrong_asset_unsigned, wrong_asset_entries.clone(), 0, &owner), recipient_owner, minted_amount],
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
            .with_app("kcc20_asset", &asset_artifact)
            .expect("matching observed artifact attaches");
        TxBuilder::from_bundle(&bundle).expect("builder accepts valid bundle");
        ArtifactBundle::named("kcc20_mint_controller", &controller_artifact)
            .expect("bundle accepts an explicitly named primary artifact");
        TxBuilder::new(&controller_artifact)
            .expect("builder accepts controller artifact")
            .with_observed_artifact(&asset_artifact)
            .expect("observed artifact attaches under its app alias")
            .contract_in_app("kcc20_asset", "MinterProxy")
            .expect("app alias exposes the observed asset app");

        let wrong_alias_err = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact remains valid")
            .with_app("wrong", &asset_artifact)
            .expect_err("wrong app alias is rejected");
        assert!(matches!(
            wrong_alias_err,
            BuilderError::AppAliasMismatch { app, expected, found }
                if app == "KCC20Asset" && expected == "kcc20_asset" && found == "wrong"
        ));

        let wrong_primary_alias_err =
            ArtifactBundle::named("wrong", &controller_artifact).expect_err("wrong primary app alias is rejected");
        assert!(matches!(
            wrong_primary_alias_err,
            BuilderError::AppAliasMismatch { app, expected, found }
                if app == "KCC20MintController" && expected == "kcc20_mint_controller" && found == "wrong"
        ));

        let mut bad_id_asset = asset_artifact.clone();
        bad_id_asset.id = "00".repeat(32);
        let bad_id_err = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact remains valid")
            .with_app("kcc20_asset", &bad_id_asset)
            .expect_err("bad observed artifact id is rejected");
        assert!(matches!(bad_id_err, BuilderError::ArtifactIdentity { app, .. } if app == "kcc20_asset"));

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
        let bad_interface_bundle = ArtifactBundle::new(&controller_artifact)
            .expect("controller artifact remains valid")
            .with_app("kcc20_asset", &bad_interface_asset)
            .expect("interface mismatch is checked when the app is used");
        let bad_interface_builder = TxBuilder::from_bundle(&bad_interface_bundle).expect("builder accepts bundle shape");
        let mismatch_err = bad_interface_builder
            .covenant_output(
                "Minter",
                minter_state(vec![0x22; 32], Hash::from_bytes([0xa5; 32]), 1, true),
                1_000,
                0,
                Hash::from_bytes([0xc0; 32]),
            )
            .expect_err("interface fingerprint mismatch is rejected when filling observed template fields");
        assert!(
            matches!(&mismatch_err, BuilderError::InterfaceMismatch { app, actor, .. } if app == "kcc20_asset" && actor == "MinterProxy"),
            "unexpected error: {mismatch_err}"
        );
    }

    #[test]
    fn open_icc_baseline_spends_core_and_agent_covenants() {
        let core_artifact = open_icc_core_artifact();
        let agent_artifact = open_icc_agent_artifact();
        let bundle = ArtifactBundle::new(&core_artifact)
            .expect("bundle accepts open ICC core")
            .with_app("open_agent", &agent_artifact)
            .expect("bundle accepts open ICC agent app");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts open ICC bundle");
        let advance = core_artifact
            .argent
            .actors
            .iter()
            .find(|actor| actor.name == "Cell")
            .and_then(|actor| actor.entries.iter().find(|entry| entry.name == "advance"))
            .expect("Cell::advance artifact exists");
        let next_digest = advance
            .hidden_params
            .iter()
            .find(|param| param.name == "gen__remote_agent_next_strategy")
            .expect("virtual observed output slot is hidden runtime plumbing");
        assert_eq!(next_digest.purpose, HiddenParamPurposeArtifact::ObservedOutputFieldValue);
        assert_eq!(
            next_digest.subject,
            HiddenParamSubjectArtifact::ObservedOutputField {
                observe: "remote".to_string(),
                handle: "agent".to_string(),
                state: "AgentCapsule".to_string(),
                field: "strategy".to_string(),
            }
        );

        let controller_covenant_id = Hash::from_bytes([0x31; 32]);
        let agent_covenant_id = Hash::from_bytes([0x41; 32]);
        let cell_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x51; 32]), index: 0 };
        let agent_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x52; 32]), index: 0 };
        let cell_value = 4_000;
        let agent_value = 2_000;
        let caps_digest = vec![0x77; 32];
        let agent_type = decode_hex(&agent_artifact.sil_abi.contract("Agent").expect("Agent ABI exists").compiled.template.hash_hex)
            .expect("agent template hash decodes");

        let cell_initial = open_cell_state(agent_covenant_id, agent_type.clone(), 7);
        let cell_next = open_cell_state(agent_covenant_id, agent_type.clone(), 8);
        let agent_initial = open_agent_state(controller_covenant_id, caps_digest.clone(), 5);
        let agent_next = open_agent_state(controller_covenant_id, caps_digest, 4);

        let missing_context_err = builder
            .p2sh_signature_script("Cell", "advance", cell_initial.clone(), args![])
            .expect_err("open observed actors still require explicit context");
        assert!(
            matches!(&missing_context_err, BuilderError::MissingObservedCovenant { observe } if observe == "remote"),
            "unexpected error: {missing_context_err}"
        );

        let agent_utxo = builder
            .covenant_utxo_in_app("open_agent", "Agent", agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("agent utxo builds");
        let observed = open_agent_context("Agent", agent_initial.clone(), agent_utxo.clone(), agent_next.clone());
        let fluent_cell_utxo = builder
            .covenant_utxo("Cell", cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("fluent cell UTXO builds");
        let fluent = builder
            .transition("Cell", "advance")
            .input(cell_outpoint, fluent_cell_utxo.clone(), cell_initial.clone())
            .observe("remote", observed.get("remote").expect("remote context exists").clone())
            .output("cell", cell_next.clone(), cell_value)
            .co_spend_observed("remote", "agent", "step", agent_outpoint, args![agent_next.clone()], agent_value)
            .build()
            .expect("open ICC transition builds from explicit observed context");
        assert_eq!(fluent.transaction.inputs.len(), 2);
        assert_eq!(fluent.transaction.outputs.len(), 2);
        assert_eq!(fluent.transaction.outputs[0].covenant.unwrap().authorizing_input, 0);
        assert_eq!(fluent.transaction.outputs[1].covenant.unwrap().authorizing_input, 1);
        assert!(fluent.transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

        let context = TxContext::new()
            .argent_input("Cell", cell_initial.clone(), "advance", cell_outpoint, fluent_cell_utxo)
            .argent_input(
                "open_agent::Agent",
                agent_initial.clone(),
                EntryCall::new("step").args(args![agent_next.clone()]),
                agent_outpoint,
                agent_utxo.clone(),
            )
            .argent_output("Cell", cell_next.clone(), CovenantBinding::new(0, controller_covenant_id), cell_value)
            .argent_output("open_agent::Agent", agent_next.clone(), CovenantBinding::new(1, agent_covenant_id), agent_value);
        let context_tx = builder.build(&context).expect("context resolves the open observed actor");
        assert_eq!(context_tx.inputs[0].signature_script, fluent.transaction.inputs[0].signature_script);
        assert_eq!(context_tx.inputs[1].signature_script, fluent.transaction.inputs[1].signature_script);

        let mut observed_keyed_by_app = BTreeMap::new();
        observed_keyed_by_app
            .insert("open_agent".to_string(), observed.get("remote").expect("remote observed context exists").clone());
        let wrong_observe_key_err = builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_initial.clone(), args![], &observed_keyed_by_app)
            .expect_err("observed context map is keyed by observe name, not app alias");
        assert!(
            matches!(
                &wrong_observe_key_err,
                BuilderError::UnknownObserve { actor, entry, observe }
                    if actor == "Cell" && entry == "advance" && observe == "open_agent"
            ),
            "unexpected error: {wrong_observe_key_err}"
        );
        let wrong_app_context = ObservedCovenantContext::from_app("remote")
            .input("agent", "Agent", agent_utxo.clone(), agent_initial.clone())
            .output("agent", "Agent", agent_next.clone());
        let wrong_app_alias_err = builder
            .observed_outputs(
                "Cell",
                "advance",
                "remote",
                &wrong_app_context,
                BTreeMap::from([("agent".to_string(), agent_value)]),
                1,
                agent_covenant_id,
            )
            .expect_err("observed context app is the attached artifact alias, not the observe name");
        assert!(
            matches!(&wrong_app_alias_err, BuilderError::UnknownAppAlias(alias) if alias == "remote"),
            "unexpected error: {wrong_app_alias_err}"
        );
        let mut bad_layout_agent_artifact = agent_artifact.clone();
        let bad_energy_field = bad_layout_agent_artifact
            .argent
            .states
            .iter_mut()
            .find(|state| state.name == "AgentCapsule")
            .and_then(|state| state.fields.iter_mut().find(|field| field.name == "energy"))
            .expect("AgentCapsule.energy exists");
        bad_energy_field.ty = TypeArtifact::Bool;
        bad_layout_agent_artifact.id = bad_layout_agent_artifact.computed_id_hex().expect("mutated agent artifact id computes");
        let bad_layout_bundle = ArtifactBundle::new(&core_artifact)
            .expect("core artifact is valid")
            .with_app("open_agent", &bad_layout_agent_artifact)
            .expect("layout mismatch is checked when open observed actor is used");
        let bad_layout_builder = TxBuilder::from_bundle(&bad_layout_bundle).expect("builder accepts bundle shape");
        let bad_layout_err = bad_layout_builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_initial.clone(), args![], &observed)
            .expect_err("open observed actor state layout mismatch is rejected");
        assert!(
            matches!(
                &bad_layout_err,
                BuilderError::ObservedStateLayoutMismatch { observe, side, handle, state, actor }
                    if observe == "remote" && *side == "input" && handle == "agent" && state == "AgentCapsule" && actor == "Agent"
            ),
            "unexpected error: {bad_layout_err}"
        );

        let expanded_agent_artifact = open_icc_expanded_agent_artifact();
        let expanded_bundle = ArtifactBundle::new(&core_artifact)
            .expect("core artifact is valid")
            .with_app("open_agent", &expanded_agent_artifact)
            .expect("expanded agent artifact attaches under the same app alias");
        let expanded_builder = TxBuilder::from_bundle(&expanded_bundle).expect("builder accepts expanded agent bundle");
        let expanded_agent_type = expanded_builder
            .actor_type_handle("open_agent::Forager", "AgentCapsule")
            .expect("Forager exposes its AgentCapsule handle");
        let expanded_cell_initial = open_cell_state(agent_covenant_id, expanded_agent_type, 7);
        let expanded_agent_initial = expanded_open_agent_state(controller_covenant_id, 2, 5);
        let expanded_agent_next = expanded_open_agent_state(controller_covenant_id, 3, 4);
        let expanded_agent_utxo = expanded_builder
            .covenant_utxo_in_app(
                "open_agent",
                "Forager",
                expanded_agent_initial.clone(),
                agent_value,
                0,
                false,
                Some(agent_covenant_id),
            )
            .expect("expanded agent utxo builds");
        let expanded_observed = open_agent_context("Forager", expanded_agent_initial, expanded_agent_utxo, expanded_agent_next);
        expanded_builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", expanded_cell_initial, args![], &expanded_observed)
            .expect("open observed actor accepts a state that expands the expected base state");
        expanded_builder
            .p2sh_signature_script_in_app(
                "open_agent",
                "Forager",
                "step",
                expanded_open_agent_state(controller_covenant_id, 2, 5),
                args![],
            )
            .expect("expanded agent sigscript is built from slot-qualified source fields");
        let mut flattened_forager_state = expanded_open_agent_state(controller_covenant_id, 2, 5);
        flattened_forager_state.remove("strategy");
        flattened_forager_state.insert("hunger".to_string(), ArtifactValue::Int(2));
        flattened_forager_state.insert("mood".to_string(), ArtifactValue::Int(1));
        flattened_forager_state.insert("target_agent_id".to_string(), ArtifactValue::Bytes(vec![0x55; 32]));
        let flattened_err = expanded_builder
            .p2sh_signature_script_in_app("open_agent", "Forager", "step", flattened_forager_state, args![])
            .expect_err("expanded agent state must provide slot-qualified source fields");
        assert!(
            matches!(&flattened_err, BuilderError::MissingStateExpansionPreimage { contract, field, memory_state }
                if contract == "Forager" && field == "strategy" && memory_state == "ForagerStrategy"),
            "unexpected error: {flattened_err}"
        );

        let forager_type =
            decode_hex(&agent_artifact.sil_abi.contract("Forager").expect("Forager ABI exists").compiled.template.hash_hex)
                .expect("Forager template hash decodes");
        let forager_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x53; 32]), index: 0 };
        let controller_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x54; 32]), index: 0 };
        let forager_initial = expanded_open_agent_state(controller_covenant_id, 2, 5);
        let forager_next = expanded_open_agent_state_at(controller_covenant_id, 3, 4, 1, 0);
        let controller_utxo = builder
            .covenant_utxo(
                "Cell",
                open_cell_state(agent_covenant_id, forager_type, 7),
                cell_value,
                0,
                false,
                Some(controller_covenant_id),
            )
            .expect("controller cell utxo builds");
        let forager_utxo = builder
            .covenant_utxo_in_app("open_agent", "Forager", forager_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("Forager utxo builds");
        let forager_output = builder
            .covenant_output_in_app("open_agent", "Forager", forager_next, agent_value, 1, agent_covenant_id)
            .expect("Forager output builds with packed expanded memory digest");
        let forager_sigscript = builder
            .p2sh_signature_script_in_app("open_agent", "Forager", "step", forager_initial, args![1, 0, 4])
            .expect("Forager step sigscript fills hidden expanded-memory preimage");
        let forager_tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(controller_outpoint, Vec::new()),
                TxBuilder::transaction_input(forager_outpoint, forager_sigscript),
            ],
            vec![forager_output],
        );
        execute_input_with_covenants(&forager_tx, vec![controller_utxo, forager_utxo], 1)
            .expect("Forager step executes with digest-backed memory repacking");

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
            .p2sh_signature_script_in_app("open_agent", "Agent", "step", agent_initial.clone(), args![agent_next.clone()])
            .expect("agent step sigscript builds");
        let cell_sigscript = builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_initial.clone(), args![], &observed)
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
            open_cell_state(agent_covenant_id, agent_type, 8),
            &wrong_observed,
            cell_value,
            agent_value,
            controller_covenant_id,
            agent_covenant_id,
        );
        let wrong_agent_sigscript = builder
            .p2sh_signature_script_in_app("open_agent", "Agent", "step", agent_initial.clone(), args![wrong_agent_next])
            .expect("agent accepts controller-co-spent non-physics state");
        let wrong_cell_sigscript = builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_initial.clone(), args![], &observed)
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
        execute_input_with_covenants(&wrong_tx, entries, 1).expect("agent still accepts co-spent header-preserving output");
    }

    #[test]
    fn anonymous_open_binding_fills_template_hash_and_executes() {
        let core_artifact = example_artifact("tests/fixtures/emit/open_observed_actor_binding/app.ag", "anonymous-open-binding-core");
        let agent_artifact = inline_artifact(
            "anonymous-open-binding-agent",
            r#"
            state AgentCapsule {
                covid controller_id;
                byte[32] caps_digest;
                int energy;
            }

            actor Agent owns AgentCapsule {
                entry step(next_state: AgentCapsule) emits one Agent {
                    require(controller_id.co_spent());
                    become Agent(next_state);
                }
            }

            app AgentApp {
                actor Agent;
            }
            "#,
        );
        let bundle = ArtifactBundle::new(&core_artifact)
            .expect("bundle accepts anonymous open core")
            .with_app("agent_app", &agent_artifact)
            .expect("bundle accepts anonymous observed app");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts anonymous open bundle");

        let agent_template = agent_artifact.sil_abi.contract("Agent").expect("Agent contract exists").compiled.template.clone();
        let agent_template_hash = decode_hex(&agent_template.hash_hex).expect("Agent template hash decodes");
        let controller_covenant_id = Hash::from_bytes([0x33; 32]);
        let agent_covenant_id = Hash::from_bytes([0x44; 32]);
        let agent_state = state! {
            controller_id: controller_covenant_id,
            caps_digest: vec![0x22; 32],
            energy: 5,
        };
        let next_agent_state = state! {
            controller_id: controller_covenant_id,
            caps_digest: vec![0x22; 32],
            energy: 4,
        };
        let cell_state = state! {
            agent_covid: agent_covenant_id,
            agent_type: agent_template_hash.clone(),
            tick: 0,
        };
        let next_cell_state = state! {
            agent_covid: agent_covenant_id,
            agent_type: agent_template_hash.clone(),
            tick: 1,
        };
        let agent_utxo = builder
            .covenant_utxo_in_app("agent_app", "Agent", agent_state.clone(), 1_000, 0, false, Some(agent_covenant_id))
            .expect("observed Agent UTXO builds");
        let observed = BTreeMap::from([(
            "remote".to_string(),
            ObservedCovenantContext::from_app("agent_app").input("agent", "Agent", agent_utxo, agent_state.clone()).output(
                "agent",
                "Agent",
                next_agent_state.clone(),
            ),
        )]);

        let sigscript = builder
            .p2sh_signature_script_with_observed_covenants("Cell", "advance", cell_state.clone(), args![], &observed)
            .expect("anonymous open sigscript builds");
        let contract = builder.contract("Cell").expect("Cell contract exists");
        let entry = contract.entry("advance").expect("advance entry exists");
        let expected_args = vec![
            ArtifactValue::Int(decode_hex(&agent_template.prefix_hex).expect("Agent prefix decodes").len() as i64),
            ArtifactValue::Int(decode_hex(&agent_template.suffix_hex).expect("Agent suffix decodes").len() as i64),
            ArtifactValue::Bytes(agent_template_hash),
        ];
        let expected_entry = encode_entry_sig_script(&core_artifact.sil_abi, contract, entry, &expected_args)
            .expect("expected entry sigscript encodes");
        let expected = pay_to_script_hash_signature_script_with_flags(
            builder.redeem_script("Cell", cell_state.clone()).expect("Cell redeem script builds"),
            expected_entry,
            covenant_engine_flags(),
        )
        .expect("expected P2SH sigscript builds");

        assert_eq!(sigscript, expected);

        // Execute both sides of the co-spent anonymous observer/agent transition.
        let cell_utxo =
            builder.covenant_utxo("Cell", cell_state, 2_000, 0, false, Some(controller_covenant_id)).expect("Cell UTXO builds");
        let agent_utxo = observed.get("remote").unwrap().inputs.get("agent").unwrap().utxo.clone();
        let outputs = vec![
            builder.covenant_output("Cell", next_cell_state, 2_000, 0, controller_covenant_id).expect("Cell output builds"),
            builder
                .covenant_output_in_app("agent_app", "Agent", next_agent_state.clone(), 1_000, 1, agent_covenant_id)
                .expect("Agent output builds"),
        ];
        let agent_sigscript = builder
            .p2sh_signature_script_in_app("agent_app", "Agent", "step", agent_state, args![next_agent_state])
            .expect("Agent sigscript builds");
        let tx = TxBuilder::transaction(
            vec![
                TxBuilder::transaction_input(
                    TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x55; 32]), index: 0 },
                    sigscript,
                ),
                TxBuilder::transaction_input(
                    TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x66; 32]), index: 0 },
                    agent_sigscript,
                ),
            ],
            outputs,
        );
        let entries = vec![cell_utxo, agent_utxo];
        execute_input_with_covenants(&tx, entries.clone(), 0).expect("anonymous observer input passes");
        execute_input_with_covenants(&tx, entries, 1).expect("observed Agent input passes");
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

    fn open_icc_expanded_agent_artifact() -> Artifact {
        inline_artifact(
            "open-icc-expanded-agent",
            r#"
            state AgentCapsule {
                byte[32] world_id;
                byte[32] agent_id;
                byte[32] species_id;

                covid controller_id;
                byte[32] capabilities_digest;
                virtual strategy;

                int x;
                int y;
                int energy;
                int generation;
            }

            state ForagerStrategy {
                int hunger;
                int mood;
                byte[32] target_agent_id;
            }

            state ForagerState expands AgentCapsule {
                strategy: ForagerStrategy;
            }

            actor Forager owns ForagerState {
                entry step() emits {
                    agent: Forager;
                } {
                    require(controller_id.co_spent());

                    ForagerState next_agent = {
                        world_id: world_id,
                        agent_id: agent_id,
                        species_id: species_id,
                        controller_id: controller_id,
                        capabilities_digest: capabilities_digest,
                        strategy: ForagerStrategy {
                            hunger: strategy.hunger + 1,
                            mood: strategy.mood,
                            target_agent_id: strategy.target_agent_id,
                        },
                        x: x,
                        y: y,
                        energy: energy - 1,
                        generation: generation,
                    };

                    become agent <- Forager(next_agent);
                }
            }

            app OpenAgent {
                actor Forager;
            }
            "#,
        )
    }

    fn capsule_route_context_artifact() -> Artifact {
        example_artifact("tests/fixtures/emit/capsule_route_context/app.ag", "capsule-route-context")
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
        state! {
            owner: owner,
            serial: serial,
            redeemed: redeemed,
        }
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
        state! {
            owner: owner,
            player_id: player_id,
            open_games: open_games,
            games: games,
            wins: wins,
            losses: losses,
        }
    }

    fn game_state(player_a: Vec<u8>, player_b: Vec<u8>, pile: i64, max_take: i64, turn: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            player_a: player_a,
            player_b: player_b,
            pile: pile,
            max_take: max_take,
            turn: turn,
        }
    }

    fn league_state(admin: Vec<u8>, default_pile: i64, default_max_take: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            admin: admin,
            default_pile: default_pile,
            default_max_take: default_max_take,
        }
    }

    fn count_state(count: i64) -> BTreeMap<String, ArtifactValue> {
        state! { count: count }
    }

    fn toy_player_state(nonce: i64) -> BTreeMap<String, ArtifactValue> {
        state! { nonce: nonce }
    }

    fn board_state(selector: i64, ply: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            selector: selector,
            ply: ply,
        }
    }

    fn minter_state(owner: Vec<u8>, kcc20_covid: Hash, amount: i64, initialized: bool) -> BTreeMap<String, ArtifactValue> {
        state! {
            owner: owner,
            kcc20_covid: kcc20_covid,
            amount: amount,
            initialized: initialized,
        }
    }

    fn minter_proxy_state(controller_id: Hash) -> BTreeMap<String, ArtifactValue> {
        state! { controller_id: controller_id }
    }

    fn kcc20_state(owner_identifier: Vec<u8>, amount: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            owner_identifier: owner_identifier,
            identifier_type: 0_u8,
            amount: amount,
        }
    }

    fn open_cell_state(agent_covid: Hash, agent_type: Vec<u8>, _tick: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            world_id: vec![0x11; 32],
            x: 0,
            y: 0,
            food: 0,
            occupant_agent_covid: agent_covid,
            occupant_agent_type: agent_type,
            occupant_caps_digest: vec![0x77; 32],
        }
    }

    fn open_agent_state(controller_id: Hash, caps_digest: Vec<u8>, energy: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            world_id: vec![0x11; 32],
            agent_id: vec![0x22; 32],
            species_id: vec![0x33; 32],
            controller_id: controller_id,
            capabilities_digest: caps_digest,
            strategy: vec![0x44; 32],
            x: 0,
            y: 0,
            energy: energy,
            generation: 0,
        }
    }

    fn expanded_open_agent_state(controller_id: Hash, hunger: i64, energy: i64) -> BTreeMap<String, ArtifactValue> {
        expanded_open_agent_state_at(controller_id, hunger, energy, 0, 0)
    }

    fn expanded_open_agent_state_at(controller_id: Hash, hunger: i64, energy: i64, x: i64, y: i64) -> BTreeMap<String, ArtifactValue> {
        state! {
            world_id: vec![0x11; 32],
            agent_id: vec![0x22; 32],
            species_id: vec![0x33; 32],
            controller_id: controller_id,
            capabilities_digest: vec![0x77; 32],
            strategy: state! {
                hunger: hunger,
                mood: 1,
                target_agent_id: vec![0x55; 32],
            },
            x: x,
            y: y,
            energy: energy,
            generation: 0,
        }
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
            ObservedCovenantContext::from_app("kcc20_asset")
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
            "remote".to_string(),
            ObservedCovenantContext::from_app("open_agent").input("agent", agent_actor, agent_utxo, agent_state).output(
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
                    "remote",
                    observed.get("remote").expect("remote observed context exists"),
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
            .p2sh_signature_script("Player", "start_game", initial_a.clone(), args![leader_sig, owner_a_pk.to_vec(), 0, 7, 3])
            .expect("leader sigscript builds");
        let delegate_sigscript = builder
            .p2sh_signature_script("Player", "accept_start", initial_b.clone(), args![delegate_sig, owner_b_pk.to_vec()])
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
        sign_mutable_input(&tx, input_idx, keypair)
    }

    fn sign_mutable_input<T: AsRef<Transaction>>(tx: &MutableTransaction<T>, input_idx: usize, keypair: &Keypair) -> Vec<u8> {
        let reused_values = SigHashReusedValuesUnsync::new();
        let sig_hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("valid sighash message");
        let sig = keypair.sign_schnorr(msg);
        let mut signature = sig.as_ref().to_vec();
        signature.push(SIG_HASH_ALL.to_u8());
        signature
    }
}
