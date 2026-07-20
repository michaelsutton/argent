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
        emit::{emit_build, emit_build_app},
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
            covenant_id::covenant_id,
            sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
            sighash_type::SIG_HASH_ALL,
        },
        tx::{
            CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
            TransactionOutpoint, TransactionOutput, UtxoEntry,
        },
    };
    use kaspa_txscript::{opcodes::codes::OpTrue, parse_script, pay_to_script_hash_signature_script_with_flags};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    static ARTIFACT_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn subject_label(subject: &HiddenParamSubjectArtifact) -> &str {
        match subject {
            HiddenParamSubjectArtifact::Actor { actor } => actor,
            HiddenParamSubjectArtifact::ObservedActor { actor, .. } => actor,
            HiddenParamSubjectArtifact::SpawnActor { actor, .. } => actor,
            HiddenParamSubjectArtifact::ObservedOutputField { field, .. } => field,
            HiddenParamSubjectArtifact::RouteFamily { family_id } => family_id,
            HiddenParamSubjectArtifact::TemplateSelector { selector } => selector,
            HiddenParamSubjectArtifact::StateExpansion { memory_state, .. } => memory_state,
        }
    }

    fn entry_artifact<'a>(artifact: &'a Artifact, actor: &str, entry: &str) -> &'a crate::artifact::EntryArtifact {
        artifact
            .argent
            .actors
            .iter()
            .find(|candidate| candidate.name == actor)
            .and_then(|actor| actor.entries.iter().find(|candidate| candidate.name == entry))
            .unwrap_or_else(|| panic!("missing artifact entry `{actor}::{entry}`"))
    }

    fn route_family_table_bytes(artifact: &Artifact, family_id: &str) -> Vec<u8> {
        let family = artifact
            .argent
            .template_plan
            .route_families
            .iter()
            .find(|family| family.id == family_id)
            .unwrap_or_else(|| panic!("missing route family `{family_id}`"));
        let table = artifact
            .argent
            .template_plan
            .route_tables
            .iter()
            .find(|table| table.id == family.table_id)
            .unwrap_or_else(|| panic!("missing route table `{}`", family.table_id));
        let mut bytes = Vec::with_capacity(table.byte_len);
        for entry in &table.entries {
            let crate::artifact::RouteTemplateLeafArtifact::Template { actor, .. } = &entry.leaf else {
                panic!("test route table `{}` unexpectedly contains a nested family", table.id);
            };
            let contract = artifact.sil_abi.contract(actor).unwrap_or_else(|| panic!("missing contract `{actor}`"));
            bytes.extend_from_slice(&decode_hex(&contract.compiled.template.hash_hex).expect("template hash decodes"));
        }
        bytes
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

        let input_utxo = builder
            .covenant_utxo("Ticket", initial_state.clone(), input_value, 0, false, Some(covenant_id))
            .expect("ticket utxo builds");
        let context = TxContext::new()
            .argent_input(
                "Ticket",
                initial_state.clone(),
                EntryCall::new("redeem").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
                outpoint,
                input_utxo.clone(),
                0,
            )
            .argent_output("Ticket", redeemed_state, CovenantBinding::new(0, covenant_id), input_value);
        builder.build(&context).expect("valid redeem tx passes");

        let wrong_pk = keypair_from_byte(2).x_only_public_key().0.serialize().to_vec();
        let bad_args = TxContext::new()
            .argent_input(
                "Ticket",
                initial_state.clone(),
                EntryCall::new("redeem").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), wrong_pk.clone()]),
                outpoint,
                input_utxo.clone(),
                0,
            )
            .argent_output("Ticket", ticket_state(owner_hash.clone(), 7, 1), CovenantBinding::new(0, covenant_id), input_value);
        assert!(builder.build(&bad_args).is_err());

        let stale_output = TxContext::new()
            .argent_input(
                "Ticket",
                initial_state.clone(),
                EntryCall::new("redeem").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
                outpoint,
                input_utxo,
                0,
            )
            .argent_output("Ticket", initial_state, CovenantBinding::new(0, covenant_id), input_value);
        assert!(builder.build(&stale_output).is_err());
    }

    #[test]
    fn redeem_script_fills_hidden_template_state_from_artifact() {
        let artifact = tickets_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let actor = artifact.sil_abi.contract("Issuer").expect("issuer contract exists");
        let admin = keypair_from_byte(3);
        let admin_pk = admin.x_only_public_key().0.serialize().to_vec();
        let owner_pk = keypair_from_byte(4).x_only_public_key().0.serialize().to_vec();
        let source_state = state! {
            admin: blake2b32(&admin_pk),
            next_serial: 11,
        };
        let covenant_id = Hash::from_bytes([0x21; 32]);
        let input_utxo =
            builder.covenant_utxo("Issuer", source_state.clone(), 1_000, 0, false, Some(covenant_id)).expect("issuer UTXO builds");
        let context = TxContext::new()
            .argent_input(
                "Issuer",
                source_state.clone(),
                EntryCall::new("issue")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &admin), admin_pk.clone(), owner_pk.clone()]),
                TransactionOutpoint::new(TransactionId::from_bytes([0x22; 32]), 0),
                input_utxo,
                0,
            )
            .argent_output(
                "Issuer",
                state! {
                    admin: blake2b32(&admin_pk),
                    next_serial: 12,
                },
                CovenantBinding::new(0, covenant_id),
                1_000,
            )
            .argent_output("Ticket", ticket_state(blake2b32(&owner_pk), 11, 0), CovenantBinding::new(0, covenant_id), 500);
        let transaction = builder.build(&context).expect("issue transaction builds");
        let redeem_script = p2sh_redeem_script(&transaction.inputs[0].signature_script);
        let state_span = &actor.compiled.state_span;
        let state_script = &redeem_script[state_span.offset..state_span.offset + state_span.len];
        let decoded = crate::codec::decode_runtime_state_script(&actor.runtime_state, state_script).expect("state decodes");

        assert_eq!(decoded.get("admin"), source_state.get("admin"));
        assert_eq!(
            decoded.get("gen__ticket_template"),
            Some(&ArtifactValue::Bytes(
                decode_hex(&artifact.sil_abi.contract("Ticket").expect("ticket contract exists").compiled.template.hash_hex).unwrap()
            ))
        );
        assert!(!decoded.contains_key("gen__issuer_template"), "Issuer state should not carry its own template");

        let mut explicit_hidden_state = source_state;
        explicit_hidden_state.insert("gen__ticket_template".to_string(), ArtifactValue::Bytes(vec![0; 32]));
        let explicit_hidden =
            TxContext::new().argent_output("Issuer", explicit_hidden_state, CovenantBinding::new(0, covenant_id), 1_000);
        let err = builder.build(&explicit_hidden).expect_err("hidden runtime state fields must be filled by the runtime");
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
        let next_state = state! {
            owner_kind: 1,
            owner_id: Hash::from_bytes([0x31; 32]),
            policy: state! {
                nonce: 5,
            },
            balance: 100,
        };
        let asset_covenant_id = Hash::from_bytes([0x32; 32]);
        let owner_covenant_id = Hash::from_bytes([0x31; 32]);
        let owner_utxo = UtxoEntry::new(1, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, Some(owner_covenant_id));
        let asset_utxo = builder
            .covenant_utxo("ReserveAsset", state.clone(), 1_000, 0, false, Some(asset_covenant_id))
            .expect("ReserveAsset UTXO builds");
        let context = TxContext::new()
            .input(TransactionOutpoint::new(TransactionId::from_bytes([0x33; 32]), 0), owner_utxo, Vec::new(), 0)
            .argent_input(
                "ReserveAsset",
                state,
                EntryCall::new("settle").args(args![100]),
                TransactionOutpoint::new(TransactionId::from_bytes([0x34; 32]), 0),
                asset_utxo,
                0,
            )
            .argent_output("ReserveAsset", next_state, CovenantBinding::new(1, asset_covenant_id), 1_000);
        let transaction = builder.build(&context).expect("expanded actor transaction builds");
        let redeem_script = p2sh_redeem_script(&transaction.inputs[1].signature_script);
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
    fn context_entry_call_accepts_user_args_only() {
        let artifact = tickets_artifact();
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let owner = keypair_from_byte(1);
        let owner_pk = owner.x_only_public_key().0.serialize().to_vec();
        let source_state = ticket_state(blake2b32(&owner_pk), 7, 0);

        let covenant_id = Hash::from_bytes([0x41; 32]);
        let input_utxo =
            builder.covenant_utxo("Ticket", source_state.clone(), 1_000, 0, false, Some(covenant_id)).expect("ticket UTXO builds");
        let context = TxContext::new().argent_input(
            "Ticket",
            source_state,
            EntryCall::new("redeem").args(args![vec![1; 65], owner_pk, vec![2; 32], vec![3; 32]]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x42; 32]), 0),
            input_utxo,
            0,
        );
        let err = builder.build(&context).expect_err("user must not provide hidden prefix/suffix witnesses");

        assert!(matches!(err, BuilderError::Codec(CodecError::WrongArgumentCount { .. })));
    }

    #[test]
    fn context_builds_and_verifies_signed_single_output() {
        let artifact = inline_artifact(
            "context-counter",
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

        let context = TxContext::new()
            .argent_input(
                "Counter",
                initial.clone(),
                EntryCall::new("bump").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), 3]),
                outpoint,
                input_utxo.clone(),
                0,
            )
            .argent_output("Counter", next, CovenantBinding::new(0, covenant_id), input_value);
        let transaction = builder.build(&context).expect("context builds");

        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.outputs.len(), 1);
        assert_eq!(transaction.version, 1);
        assert!(transaction.inputs[0].compute_commit.compute_budget().is_some());
        assert_eq!(transaction.outputs[0].value, input_value);
        assert_eq!(transaction.outputs[0].covenant, Some(CovenantBinding { authorizing_input: 0, covenant_id }));

        let wrong_state = TxContext::new()
            .argent_input(
                "Counter",
                initial.clone(),
                EntryCall::new("bump").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), 3]),
                outpoint,
                input_utxo,
                0,
            )
            .argent_output("Counter", initial, CovenantBinding::new(0, covenant_id), input_value);
        let err = builder.build(&wrong_state).expect_err("incorrect expected state must fail contract execution");
        assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }), "unexpected error: {err}");
    }

    #[test]
    fn context_builds_paired_transfer_and_enforces_mass_limits() {
        let artifact = inline_artifact(
            "context-paired-transfer",
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

        let context = TxContext::new()
            .argent_input(
                "Left",
                left_initial,
                EntryCall::new("shift").args(args![3]),
                TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x61; 32]), index: 0 },
                left_utxo,
                0,
            )
            .argent_input(
                "Right",
                right_initial,
                "accept_shift",
                TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x62; 32]), index: 0 },
                right_utxo,
                0,
            )
            .argent_output("Left", state! { units: 7 }, CovenantBinding::new(0, covenant_id), 3_000)
            .argent_output("Right", state! { units: 4 }, CovenantBinding::new(0, covenant_id), 2_000);
        let transaction = builder.build(&context).expect("paired transition builds");

        assert_eq!(transaction.inputs.len(), 2);
        assert_eq!(transaction.outputs.len(), 2);
        assert!(transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));
        assert!(
            transaction
                .outputs
                .iter()
                .all(|output| { output.covenant == Some(CovenantBinding { authorizing_input: 0, covenant_id }) })
        );

        let mut oversized = transaction;
        oversized.outputs.extend((0..5).map(|_| TransactionOutput::new(1, ScriptPublicKey::from_vec(0, vec![0; 10_000]))));
        let err = execute_transaction_with_covenants(&mut oversized, entries.clone()).expect_err("oversized compute mass must fail");
        assert!(matches!(err, BuilderError::ComputeMassLimitExceeded { limit: 500_000, .. }), "unexpected error: {err}");

        oversized.outputs.truncate(2);
        oversized.payload = vec![0; 250_000];
        let err = execute_transaction_with_covenants(&mut oversized, entries).expect_err("oversized transient mass must fail");
        assert!(matches!(err, BuilderError::TransientMassLimitExceeded { limit: 1_000_000, .. }), "unexpected error: {err}");
    }

    #[test]
    fn context_builds_closed_icc_without_observed_context() {
        let controller_artifact =
            example_artifact("tests/fixtures/runtime/context_closed_icc/controller.ag", "context-closed-icc-controller");
        let asset_artifact = example_artifact("tests/fixtures/runtime/context_closed_icc/asset.ag", "context-closed-icc-asset");
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
            .covenant_utxo("badge_asset::Badge", badge_initial.clone(), 2_000, 0, false, Some(asset_covenant_id))
            .expect("badge UTXO builds");

        let context = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial.clone(),
                EntryCall::new("mint").args(args![asset_covenant_id, 7]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_input(
                "badge_asset::Badge",
                badge_initial.clone(),
                EntryCall::new("apply").args_with(|tx, input_idx| args![17, sign_mutable_input(tx, input_idx, &badge_owner)]),
                badge_outpoint,
                badge_utxo.clone(),
                0,
            )
            .argent_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
            .argent_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
        let context_tx = builder.build(&context).expect("context resolves the closed observed covenant");
        assert_eq!(context_tx.inputs.len(), 2);
        assert_eq!(context_tx.outputs.len(), 2);
        assert_eq!(context_tx.outputs[0].covenant.unwrap().authorizing_input, 0);
        assert_eq!(context_tx.outputs[1].covenant.unwrap().authorizing_input, 1);
        assert!(context_tx.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

        let extra_output = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial.clone(),
                EntryCall::new("mint").args(args![asset_covenant_id, 7]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_input(
                "badge_asset::Badge",
                badge_initial.clone(),
                EntryCall::new("apply").args(args![17, vec![0; 65]]),
                badge_outpoint,
                badge_utxo.clone(),
                0,
            )
            .argent_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
            .argent_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000)
            .argent_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
        let err = builder.build(&extra_output).expect_err("observed covenant output cardinality must be exact");
        assert!(
            matches!(
                err,
                BuilderError::ObservedCountMismatch { ref observe, side: Side::Out, expected: 1, found: 2 }
                    if observe == "asset"
            ),
            "unexpected error: {err}"
        );

        let ordinary_badge_script = builder
            .covenant_utxo("badge_asset::Badge", badge_next, 2_000, 0, false, Some(asset_covenant_id))
            .expect("ordinary output can reproduce the Badge script")
            .script_public_key;
        let missing_metadata = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial,
                EntryCall::new("mint").args(args![asset_covenant_id, 7]),
                controller_outpoint,
                controller_utxo,
                0,
            )
            .argent_input(
                "badge_asset::Badge",
                badge_initial,
                EntryCall::new("apply").args(args![17, vec![0; 65]]),
                badge_outpoint,
                badge_utxo,
                0,
            )
            .argent_output("Controller", controller_next, CovenantBinding::new(0, controller_covenant_id), 4_000)
            .output(ordinary_badge_script, Some(CovenantBinding::new(1, asset_covenant_id)), 2_000);
        let err = builder.build(&missing_metadata).expect_err("observed outputs must retain Argent metadata");
        assert!(
            matches!(
                err,
                BuilderError::MissingObservedActorMetadata {
                    ref observe,
                    side: Side::Out,
                    ref handle,
                    index: 1
                } if observe == "asset" && handle == "badge"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn context_spawns_genesis_covenant_outputs_with_rusty_kaspa_id() {
        let source = "tests/fixtures/runtime/context_genesis_spawn/app.ag";
        let controller_artifact = selected_app_artifact(source, "ControllerApp", "context-genesis-controller");
        let pair_artifact = selected_app_artifact(source, "PairApp", "context-genesis-pair");
        let bundle = ArtifactBundle::named("controller_app", &controller_artifact)
            .expect("controller bundle builds")
            .with_app("pair_app", &pair_artifact)
            .expect("pair app attaches");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts bundle");

        let controller_id = Hash::from_bytes([11; 32]);
        let controller_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([23; 32]), 17);
        let pair_type = builder.actor_type_handle("pair_app::Pair", "PairState").expect("pair type handle resolves");
        let controller_state = state! {
            pair_type: pair_type.clone(),
            launches: 0,
        };
        let next_controller_state = state! {
            pair_type: pair_type,
            launches: 1,
        };
        let left_pair_state = state! { value: 42 };
        let right_pair_state = state! { value: 43 };
        let controller_utxo = builder
            .covenant_utxo("controller_app::Controller", controller_state.clone(), 10_000, 0, false, Some(controller_id))
            .expect("controller UTXO builds");

        let unrelated_spk = ScriptPublicKey::new(0, vec![OpTrue].into());
        let callback_pair_id = std::cell::Cell::new(None);
        let context = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                controller_state,
                EntryCall::new("launch").args(args![42, 43]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_output(
                "controller_app::Controller",
                state_with(|ctx| {
                    callback_pair_id.set(Some(ctx.covenant_id(0, "spawns::new_pair")?));
                    Ok(next_controller_state.clone())
                }),
                CovenantBinding::new(0, controller_id),
                5_000,
            )
            .genesis_output(0, "spawns::new_pair", "pair_app::Pair", left_pair_state.clone(), 2_000)
            .output(unrelated_spk.clone(), None, 1_000)
            .genesis_output(0, "spawns::new_pair", "pair_app::Pair", right_pair_state.clone(), 2_000);
        let transaction = builder.build(&context).expect("context populates the declared spawn group");
        let pair_id = covenant_id(controller_outpoint, [(1, &transaction.outputs[1]), (3, &transaction.outputs[3])].into_iter());
        assert_eq!(callback_pair_id.get(), Some(pair_id));
        assert_eq!(transaction.outputs[1].covenant, Some(CovenantBinding::new(0, pair_id)));
        assert_eq!(transaction.outputs[3].covenant, Some(CovenantBinding::new(0, pair_id)));

        let unknown_spawn = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                state! { pair_type: builder.actor_type_handle("pair_app::Pair", "PairState").unwrap(), launches: 0 },
                EntryCall::new("launch").args(args![42, 43]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
            .genesis_output(0, "spawns::missing", "pair_app::Pair", left_pair_state.clone(), 2_000);
        let err = builder.build(&unknown_spawn).expect_err("spawn paths must name a clause on the authorizing entry");
        assert!(
            matches!(
                err,
                BuilderError::UnknownSpawnClause { input_index: 0, ref spawn, .. } if spawn == "missing"
            ),
            "unexpected error: {err}"
        );

        let invalid_authority = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                state! { pair_type: builder.actor_type_handle("pair_app::Pair", "PairState").unwrap(), launches: 0 },
                EntryCall::new("launch").args(args![42, 43]),
                controller_outpoint,
                controller_utxo,
                0,
            )
            .argent_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
            .genesis_output(1, "spawns::new_pair", "pair_app::Pair", left_pair_state, 2_000)
            .output(unrelated_spk, None, 1_000)
            .genesis_output(1, "spawns::new_pair", "pair_app::Pair", right_pair_state, 2_000);
        let err = builder.build(&invalid_authority).expect_err("spawn groups must be authorized by their named Argent input");
        assert!(
            matches!(
                err,
                BuilderError::SpawnGenesisRequiresArgentInput { authorizing_input: 1, ref spawn } if spawn == "new_pair"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn context_launches_genesis_covenant_from_an_ordinary_input() {
        let source = "tests/fixtures/runtime/context_genesis_spawn/app.ag";
        let pair_artifact = selected_app_artifact(source, "PairApp", "context-genesis-launch");
        let builder = TxBuilder::new(&pair_artifact).expect("builder accepts pair artifact");

        let funding_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x61; 32]), 4);
        let funding_script = ScriptPublicKey::new(0, vec![OpTrue].into());
        let funding_utxo = UtxoEntry::new(3_000, funding_script, 0, false, None);
        let context = TxContext::new().input(funding_outpoint, funding_utxo, Vec::new(), 0).genesis_output(
            0,
            "launch::pair",
            "Pair",
            state! { value: 7 },
            2_000,
        );

        let transaction = builder.build(&context).expect("ordinary input launches the pair covenant");
        let expected_id = covenant_id(funding_outpoint, [(0, &transaction.outputs[0])].into_iter());
        let launched = CovenantOutput::at(&transaction, 0).expect("launched output exposes a spendable handle");

        assert_eq!(transaction.outputs[0].covenant, Some(CovenantBinding::new(0, expected_id)));
        assert_eq!(launched.covenant_id, expected_id);
        assert_eq!(launched.outpoint, TransactionOutpoint::new(transaction.id(), 0));
        assert_eq!(launched.utxo.script_public_key, transaction.outputs[0].script_public_key);

        let invalid_path = TxContext::new()
            .input(
                funding_outpoint,
                UtxoEntry::new(3_000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, None),
                Vec::new(),
                0,
            )
            .genesis_output(0, "pair", "Pair", state! { value: 7 }, 2_000);
        let err = builder.build(&invalid_path).expect_err("genesis paths require a namespace");
        assert!(matches!(err, BuilderError::InvalidGenesisPath(ref path) if path == "pair"), "unexpected error: {err}");

        let missing_input = TxContext::new()
            .input(
                funding_outpoint,
                UtxoEntry::new(3_000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, None),
                Vec::new(),
                0,
            )
            .genesis_output(1, "launch::pair", "Pair", state! { value: 7 }, 2_000);
        let err = builder.build(&missing_input).expect_err("launch paths must name an existing authorizing input");
        assert!(
            matches!(err, BuilderError::UnknownGenesisAuthorizingInput { authorizing_input: 1, input_count: 1 }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn context_orders_multiple_spawn_groups_and_rejects_invalid_witnesses() {
        let source = "tests/fixtures/runtime/context_multiple_genesis_spawns/app.ag";
        let controller_artifact = selected_app_artifact(source, "ControllerApp", "context-multiple-spawns-controller");
        let pair_artifact = selected_app_artifact(source, "PairApp", "context-multiple-spawns-pair");
        let bundle = ArtifactBundle::named("controller_app", &controller_artifact)
            .expect("controller bundle builds")
            .with_app("pair_app", &pair_artifact)
            .expect("pair app attaches");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts bundle");

        let controller_id = Hash::from_bytes([0x81; 32]);
        let controller_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x82; 32]), 7);
        let pair_type = builder.actor_type_handle("pair_app::Pair", "PairState").expect("pair type handle resolves");
        let controller_state = state! { pair_type: pair_type.clone(), launches: 0 };
        let next_controller_state = state! { pair_type: pair_type, launches: 3 };
        let first_left_state = state! { value: 11 };
        let first_right_state = state! { value: 12 };
        let second_state = state! { value: 21 };
        // Matching states let the adversarial execution reuse the first group
        // for the third clause without failing output-state validation first.
        let third_left_state = first_left_state.clone();
        let third_right_state = first_right_state.clone();
        let controller_utxo = builder
            .covenant_utxo("controller_app::Controller", controller_state.clone(), 10_000, 0, false, Some(controller_id))
            .expect("controller UTXO builds");
        // The first group occupies global outputs 1 and 3, while the second
        // occupies output 2. Group identity, not adjacency, keeps each spawn together.
        let context = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                controller_state.clone(),
                EntryCall::new("launch").args(args![11, 12, 21, 11, 12]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_left_state.clone(), 2_000)
            .genesis_output(0, "spawns::second_pair", "pair_app::Pair", second_state.clone(), 3_000)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_right_state.clone(), 2_000)
            .genesis_output(0, "spawns::third_pair", "pair_app::Pair", third_left_state.clone(), 2_000)
            .genesis_output(0, "spawns::third_pair", "pair_app::Pair", third_right_state.clone(), 2_000);
        let transaction = builder.build(&context).expect("explicit paths resolve interleaved genesis groups");

        // Security regressions: bypass spawn resolution and invoke the generated Sil directly. The first and third clauses
        // use identical actor types, states, and values, allowing malicious indices to reuse or substitute their outputs
        // without failing template or state validation first.
        let controller_contract = controller_artifact.sil_abi.contract("Controller").expect("Controller contract exists");
        let launch_entry = controller_contract.entry("launch").expect("launch entry exists");
        let pair_template = &pair_artifact.sil_abi.contract("Pair").expect("Pair contract exists").compiled.template;
        let pair_prefix = decode_hex(&pair_template.prefix_hex).expect("Pair prefix decodes");
        let pair_suffix = decode_hex(&pair_template.suffix_hex).expect("Pair suffix decodes");
        let redeem_script = p2sh_redeem_script(&transaction.inputs[0].signature_script);

        // Hidden spawn indices select first=[1, 3], second=[2], and third=[1, 3], reusing the first group.
        let reused_group_args = vec![
            ArtifactValue::Int(11),
            ArtifactValue::Int(12),
            ArtifactValue::Int(21),
            ArtifactValue::Int(11),
            ArtifactValue::Int(12),
            ArtifactValue::Int(1),
            ArtifactValue::Int(3),
            ArtifactValue::Int(2),
            ArtifactValue::Int(1),
            ArtifactValue::Int(3),
            ArtifactValue::Bytes(pair_prefix.clone()),
            ArtifactValue::Bytes(pair_suffix.clone()),
        ];
        let reused_group_entry_sigscript =
            encode_entry_sig_script(&controller_artifact.sil_abi, controller_contract, launch_entry, &reused_group_args)
                .expect("reused-group entry sigscript encodes");
        let mut reused_group_tx = transaction.clone();
        reused_group_tx.inputs[0].signature_script = pay_to_script_hash_signature_script_with_flags(
            redeem_script.clone(),
            reused_group_entry_sigscript,
            covenant_engine_flags(),
        )
        .expect("reused-group P2SH sigscript builds");
        assert!(
            execute_input_with_covenants(&reused_group_tx, vec![controller_utxo.clone()], 0).is_err(),
            "generated Sil must reject reusing the first genesis group for the third spawn clause"
        );

        // Replace the first group's real right output at index 3 with the equivalent third-group output at index 5.
        // Ordering remains valid, so matching only the first output's ID must still reject the incomplete group preimage.
        // Hidden spawn indices select first=[1, 5], second=[2], and third=[4, 5].
        let incomplete_group_args = vec![
            ArtifactValue::Int(11),
            ArtifactValue::Int(12),
            ArtifactValue::Int(21),
            ArtifactValue::Int(11),
            ArtifactValue::Int(12),
            ArtifactValue::Int(1),
            ArtifactValue::Int(5),
            ArtifactValue::Int(2),
            ArtifactValue::Int(4),
            ArtifactValue::Int(5),
            ArtifactValue::Bytes(pair_prefix),
            ArtifactValue::Bytes(pair_suffix),
        ];
        let incomplete_group_entry_sigscript =
            encode_entry_sig_script(&controller_artifact.sil_abi, controller_contract, launch_entry, &incomplete_group_args)
                .expect("incomplete-group entry sigscript encodes");
        let mut incomplete_group_tx = transaction;
        incomplete_group_tx.inputs[0].signature_script =
            pay_to_script_hash_signature_script_with_flags(redeem_script, incomplete_group_entry_sigscript, covenant_engine_flags())
                .expect("incomplete-group P2SH sigscript builds");
        assert!(
            execute_input_with_covenants(&incomplete_group_tx, vec![controller_utxo.clone()], 0).is_err(),
            "generated Sil must reject an incomplete witnessed genesis group"
        );

        let reversed_groups = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                controller_state.clone(),
                EntryCall::new("launch").args(args![11, 12, 21, 11, 12]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
            .genesis_output(0, "spawns::second_pair", "pair_app::Pair", second_state.clone(), 3_000)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_left_state.clone(), 2_000)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_right_state.clone(), 2_000)
            .genesis_output(0, "spawns::third_pair", "pair_app::Pair", third_left_state.clone(), 2_000)
            .genesis_output(0, "spawns::third_pair", "pair_app::Pair", third_right_state.clone(), 2_000);
        let err = builder.build(&reversed_groups).expect_err("generated Sil must preserve spawn declaration order");
        assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }), "unexpected error: {err}");

        let wrong_count = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                controller_state,
                EntryCall::new("launch").args(args![11, 12, 21, 11, 12]),
                controller_outpoint,
                controller_utxo,
                0,
            )
            .argent_output("controller_app::Controller", next_controller_state, CovenantBinding::new(0, controller_id), 5_000)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_left_state, 2_000);
        let err = builder.build(&wrong_count).expect_err("spawn groups must contain every declared output");
        assert!(
            matches!(
                err,
                BuilderError::SpawnOutputCountMismatch { ref spawn, expected: 2, found: 1 } if spawn == "first_pair"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn context_resolves_explicit_spawns_among_unrelated_launches() {
        let source = "tests/fixtures/runtime/context_multiple_genesis_spawns/app.ag";
        let controller_artifact = selected_app_artifact(source, "ControllerApp", "context-subset-spawns-controller");
        let pair_artifact = selected_app_artifact(source, "PairApp", "context-subset-spawns-pair");
        let bundle = ArtifactBundle::named("controller_app", &controller_artifact)
            .expect("controller bundle builds")
            .with_app("pair_app", &pair_artifact)
            .expect("pair app attaches");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts bundle");

        let controller_id = Hash::from_bytes([0x91; 32]);
        let controller_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x92; 32]), 8);
        let pair_type = builder.actor_type_handle("pair_app::Pair", "PairState").expect("pair type handle resolves");
        let controller_state = state! { pair_type: pair_type.clone(), launches: 0 };
        let next_controller_state = state! { pair_type: pair_type, launches: 3 };
        let first_left_state = state! { value: 11 };
        let first_right_state = state! { value: 12 };
        let second_state = state! { value: 21 };
        let third_left_state = state! { value: 31 };
        let third_right_state = state! { value: 32 };
        let controller_utxo = builder
            .covenant_utxo("controller_app::Controller", controller_state.clone(), 10_000, 0, false, Some(controller_id))
            .expect("controller UTXO builds");

        // Two unrelated genesis groups precede or separate the three declared groups:
        // a same-size launch group of the wrong actor at [1,3], and another
        // launch group at [4]. The spawns are first=[2,5], second=[6], third=[7,8].

        let context = TxContext::new()
            .argent_input(
                "controller_app::Controller",
                controller_state.clone(),
                EntryCall::new("launch").args(args![11, 12, 21, 31, 32]),
                controller_outpoint,
                controller_utxo,
                0,
            )
            .argent_output("controller_app::Controller", next_controller_state, CovenantBinding::new(0, controller_id), 5_000)
            .genesis_output(0, "launch::extra_first", "controller_app::Controller", controller_state.clone(), 100)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_left_state, 2_000)
            .genesis_output(0, "launch::extra_first", "controller_app::Controller", controller_state, 200)
            .genesis_output(0, "launch::extra_middle", "pair_app::Pair", state! { value: 99 }, 300)
            .genesis_output(0, "spawns::first_pair", "pair_app::Pair", first_right_state, 2_000)
            .genesis_output(0, "spawns::second_pair", "pair_app::Pair", second_state, 3_000)
            .genesis_output(0, "spawns::third_pair", "pair_app::Pair", third_left_state, 2_000)
            .genesis_output(0, "spawns::third_pair", "pair_app::Pair", third_right_state, 2_000);

        builder.build(&context).expect("explicit spawn paths ignore unrelated launch groups");
    }

    #[test]
    fn context_builds_observed_co_spend_with_transaction_dependent_args() {
        let controller_artifact =
            example_artifact("tests/fixtures/runtime/context_signed_observed/controller.ag", "context-signed-observed-controller");
        let asset_artifact =
            example_artifact("tests/fixtures/runtime/context_signed_observed/asset.ag", "context-signed-observed-asset");
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
            .covenant_utxo("asset_app::Asset", asset_initial.clone(), 2_000, 0, false, Some(asset_covenant_id))
            .expect("asset UTXO builds");
        let controller_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x76; 32]), index: 0 };
        let asset_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x77; 32]), index: 0 };

        let context = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial.clone(),
                EntryCall::new("swap").args(args![asset_covenant_id, next_owner_pk.clone()]),
                controller_outpoint,
                controller_utxo.clone(),
                0,
            )
            .argent_input(
                "asset_app::Asset",
                asset_initial.clone(),
                EntryCall::new("transfer")
                    .args_with(|tx, input_idx| args![next_owner_pk.clone(), sign_mutable_input(tx, input_idx, &owner)]),
                asset_outpoint,
                asset_utxo.clone(),
                0,
            )
            .argent_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
            .argent_output("asset_app::Asset", asset_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
        let transaction = builder.build(&context).expect("signed observed co-spend builds");

        assert_eq!(transaction.inputs.len(), 2);
        assert_eq!(transaction.outputs.len(), 2);
        assert_eq!(transaction.outputs[1].covenant.unwrap().authorizing_input, 1);

        let invalid_signature = TxContext::new()
            .argent_input(
                "Controller",
                controller_initial,
                EntryCall::new("swap").args(args![asset_covenant_id, next_owner_pk.clone()]),
                controller_outpoint,
                controller_utxo,
                0,
            )
            .argent_input(
                "asset_app::Asset",
                asset_initial,
                EntryCall::new("transfer").args(args![next_owner_pk.clone(), vec![0; 65]]),
                asset_outpoint,
                asset_utxo,
                0,
            )
            .argent_output("Controller", controller_next, CovenantBinding::new(0, controller_covenant_id), 4_000)
            .argent_output("asset_app::Asset", asset_next, CovenantBinding::new(1, asset_covenant_id), 2_000);
        let err = builder.build(&invalid_signature).expect_err("invalid observed co-spend signature must fail");
        assert!(matches!(err, BuilderError::InputScript { input_index: 1, .. }), "unexpected error: {err}");
    }

    #[test]
    fn route_plan_builds_stones_start_game_and_rejects_bad_routes() {
        let artifact = example_artifact("examples/stones/app.ag", "stones-route-plan");
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let entry = entry_artifact(&artifact, "Player", "start_game");
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

        let accept_start = entry_artifact(&artifact, "Player", "accept_start");
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

        let undeclared_delegate = TxContext::new()
            .argent_input("Player", initial_a.clone(), EntryCall::new("retire"), outpoint_a, player_a_utxo.clone(), 0)
            .argent_input("Player", initial_b.clone(), EntryCall::new("accept_start"), outpoint_b, player_b_utxo.clone(), 0);
        let err = builder.build(&undeclared_delegate).expect_err("standalone leader entry must reject an undeclared delegate");
        assert!(
            matches!(
                err,
                BuilderError::LeaderActorInputCountMismatch {
                    input_index: 0,
                    expected: 1,
                    found: 2,
                    ref leader_for,
                    ..
                } if leader_for == &["Player::accept_start"]
            ),
            "unexpected error: {err}"
        );

        let context = TxContext::new()
            .argent_input(
                "Player",
                initial_a.clone(),
                EntryCall::new("start_game")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_a), owner_a_pk.clone(), 0, 7, 3]),
                outpoint_a,
                player_a_utxo.clone(),
                0,
            )
            .argent_input(
                "Player",
                initial_b.clone(),
                EntryCall::new("accept_start")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_b), owner_b_pk.clone()]),
                outpoint_b,
                player_b_utxo.clone(),
                0,
            )
            .argent_output("Player", next_a.clone(), CovenantBinding::new(0, covenant_id), input_a_value)
            .argent_output("Player", next_b.clone(), CovenantBinding::new(0, covenant_id), input_b_value)
            .argent_output("StonesGame", next_game.clone(), CovenantBinding::new(0, covenant_id), game_value);
        let tx = builder.build(&context).expect("leader and delegate inputs pass");

        let player_contract = artifact.sil_abi.contract("Player").expect("Player contract exists");
        let player_template = &player_contract.compiled.template;
        let wrong_delegate_sigscript = {
            let populated = MutableTransaction::with_entries(tx.clone(), entries.clone());
            let delegate_sig = sign_mutable_input(&populated, 1, &owner_b);
            let prefix_len = decode_hex(&player_template.prefix_hex).expect("prefix hex decodes").len() as i64;
            let suffix_len = decode_hex(&player_template.suffix_hex).expect("suffix hex decodes").len() as i64;
            let accept_entry = player_contract.entry("accept_start").expect("accept_start exists");
            let sigscript = encode_entry_sig_script(
                &artifact.sil_abi,
                player_contract,
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
                p2sh_redeem_script(&tx.inputs[1].signature_script),
                sigscript,
                covenant_engine_flags(),
            )
            .expect("bad delegate p2sh sigscript builds")
        };
        let mut wrong_length_tx = tx.clone();
        wrong_length_tx.inputs[1].signature_script = wrong_delegate_sigscript;
        assert!(
            execute_input_with_covenants(&wrong_length_tx, entries.clone(), 1).is_err(),
            "delegate input must reject a wrong read-only template prefix length"
        );

        let swapped_outputs = TxContext::new()
            .argent_input(
                "Player",
                initial_a.clone(),
                EntryCall::new("start_game")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_a), owner_a_pk.clone(), 0, 7, 3]),
                outpoint_a,
                player_a_utxo.clone(),
                0,
            )
            .argent_input(
                "Player",
                initial_b.clone(),
                EntryCall::new("accept_start")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_b), owner_b_pk.clone()]),
                outpoint_b,
                player_b_utxo,
                0,
            )
            .argent_output("Player", next_b, CovenantBinding::new(0, covenant_id), input_b_value)
            .argent_output("Player", next_a, CovenantBinding::new(0, covenant_id), input_a_value)
            .argent_output("StonesGame", next_game.clone(), CovenantBinding::new(0, covenant_id), game_value);
        assert!(builder.build(&swapped_outputs).is_err());

        let wrong_peer = builder
            .covenant_utxo("League", league_state(vec![0; 32], 7, 3), input_b_value, 0, false, Some(covenant_id))
            .expect("wrong-template peer utxo builds");
        let wrong_peer = TxContext::new()
            .argent_input(
                "Player",
                initial_a,
                EntryCall::new("start_game")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_a), owner_a_pk.clone(), 0, 7, 3]),
                outpoint_a,
                player_a_utxo,
                0,
            )
            .input(outpoint_b, wrong_peer, Vec::new(), 0)
            .argent_output(
                "Player",
                player_state(owner_a_hash, player_a_id, 1, 0, 0, 0),
                CovenantBinding::new(0, covenant_id),
                input_a_value,
            )
            .argent_output(
                "Player",
                player_state(owner_b_hash, player_b_id, 1, 0, 0, 0),
                CovenantBinding::new(0, covenant_id),
                input_b_value,
            )
            .argent_output("StonesGame", next_game, CovenantBinding::new(0, covenant_id), game_value);
        assert!(builder.build(&wrong_peer).is_err());
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
        let enter_mux = TxContext::new()
            .argent_input("Player", player_initial.clone(), "enter_mux", player_outpoint, player_utxo.clone(), 0)
            .argent_output("Mux", mux_initial.clone(), CovenantBinding::new(0, covenant_id), input_value);
        let enter_mux_tx = builder.build(&enter_mux).expect("Player can enter the mux family");

        let player_contract = artifact.sil_abi.contract("Player").expect("Player contract exists");
        let enter_mux = player_contract.entry("enter_mux").expect("enter_mux ABI exists");
        let mux_template = &artifact.sil_abi.contract("Mux").expect("Mux contract exists").compiled.template;
        let mut wrong_routes = route_family_table_bytes(&artifact, "route_family/BoardState/mux");
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
            p2sh_redeem_script(&enter_mux_tx.inputs[0].signature_script),
            bad_route_table_sigscript,
            covenant_engine_flags(),
        )
        .expect("bad route table p2sh sigscript builds");
        let mut bad_route_table_tx = enter_mux_tx;
        bad_route_table_tx.inputs[0].signature_script = bad_route_table_sigscript;
        assert!(
            execute_input_with_covenants(&bad_route_table_tx, vec![player_utxo], 0).is_err(),
            "Player must reject a route-family table that does not match the stored digest"
        );

        let pawn_next = board_state(7, 1);
        let mux_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x63; 32]), index: 0 };
        let mux_utxo =
            builder.covenant_utxo("Mux", mux_initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Mux utxo builds");
        let choose_pawn = TxContext::new()
            .argent_input("Mux", mux_initial.clone(), "choose_pawn", mux_outpoint, mux_utxo.clone(), 0)
            .argent_output("Pawn", pawn_next.clone(), CovenantBinding::new(0, covenant_id), input_value);
        builder.build(&choose_pawn).expect("Mux can route to Pawn by table slice");

        let dynamic_pawn_next = board_state(7, 1);
        let context = TxContext::new()
            .argent_input(
                "Mux",
                mux_initial.clone(),
                EntryCall::new("choose").args(args![actor("Pawn")]),
                mux_outpoint,
                mux_utxo.clone(),
                0,
            )
            .argent_output("Pawn", dynamic_pawn_next.clone(), CovenantBinding::new(0, covenant_id), input_value);
        let context_tx = builder.build(&context).expect("context builder resolves the dynamic route witnesses");
        assert!(context_tx.inputs[0].compute_commit.compute_budget().is_some());

        let dynamic_knight = TxContext::new()
            .argent_input(
                "Mux",
                mux_initial.clone(),
                EntryCall::new("choose").args(args![actor("Knight")]),
                mux_outpoint,
                mux_utxo.clone(),
                0,
            )
            .argent_output("Knight", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
        builder.build(&dynamic_knight).expect("Mux selector can choose the second table entry");

        let missing_selector = TxContext::new()
            .argent_input("Mux", mux_initial.clone(), EntryCall::new("choose").args(args![0]), mux_outpoint, mux_utxo.clone(), 0)
            .argent_output("Pawn", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
        let missing_selector = builder.build(&missing_selector).expect_err("selector entries require an explicit template choice");
        assert!(
            matches!(missing_selector, BuilderError::MissingTemplateSelectorChoice { ref selector } if selector == "target"),
            "unexpected error: {missing_selector}"
        );

        let invalid_selector = TxContext::new()
            .argent_input(
                "Mux",
                mux_initial.clone(),
                EntryCall::new("choose").args(args![actor("League")]),
                mux_outpoint,
                mux_utxo.clone(),
                0,
            )
            .argent_output("Pawn", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
        let invalid_selector = builder.build(&invalid_selector).expect_err("selector must choose one of the actor enum variants");
        assert!(
            matches!(
                invalid_selector,
                BuilderError::InvalidTemplateSelectorChoice { ref selector, ref actor }
                    if selector == "target" && actor == "League"
            ),
            "unexpected error: {invalid_selector}"
        );

        let wrong_selector = TxContext::new()
            .argent_input(
                "Mux",
                mux_initial.clone(),
                EntryCall::new("choose").args(args![actor("Knight")]),
                mux_outpoint,
                mux_utxo.clone(),
                0,
            )
            .argent_output("Pawn", dynamic_pawn_next, CovenantBinding::new(0, covenant_id), input_value);
        assert!(builder.build(&wrong_selector).is_err(), "selector witness must match the actor selected by table index");

        let const_knight = TxContext::new()
            .argent_input("Mux", mux_initial.clone(), "choose_knight_const", mux_outpoint, mux_utxo.clone(), 0)
            .argent_output("Knight", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
        builder.build(&const_knight).expect("fixed actor enum selector can route to Knight without caller selector metadata");

        let const_wrong_output = TxContext::new()
            .argent_input("Mux", mux_initial.clone(), "choose_knight_const", mux_outpoint, mux_utxo.clone(), 0)
            .argent_output("Pawn", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
        assert!(builder.build(&const_wrong_output).is_err(), "fixed actor enum selector must reject a non-Knight output");

        let wrong_worker = TxContext::new().argent_input("Mux", mux_initial, "choose_pawn", mux_outpoint, mux_utxo, 0).argent_output(
            "Knight",
            pawn_next,
            CovenantBinding::new(0, covenant_id),
            input_value,
        );
        assert!(builder.build(&wrong_worker).is_err(), "choose_pawn must reject an output using the wrong worker template");
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
        let foo_bump = entry_artifact(&artifact, "Foo", "bump");
        assert!(foo_bump.hidden_params.is_empty(), "same-template route should not need hidden template witnesses");

        let initial = count_state(4);
        let next = count_state(9);
        let covenant_id = Hash::from_bytes([0x51; 32]);
        let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x52; 32]), index: 0 };
        let input_value = 1_000;

        let input_utxo =
            builder.covenant_utxo("Foo", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("foo utxo builds");
        let context = TxContext::new()
            .argent_input("Foo", initial.clone(), EntryCall::new("bump").args(args![5]), outpoint, input_utxo.clone(), 0)
            .argent_output("Foo", next.clone(), CovenantBinding::new(0, covenant_id), input_value);
        builder.build(&context).expect("same-template transition passes");

        let wrong_template = TxContext::new()
            .argent_input("Foo", initial, EntryCall::new("bump").args(args![5]), outpoint, input_utxo, 0)
            .argent_output("Bar", next, CovenantBinding::new(0, covenant_id), input_value);
        assert!(builder.build(&wrong_template).is_err(), "same-template validation must reject a different actor template");
    }

    #[test]
    fn exact_continuation_shortcut_redeems_register_player_and_rejects_changed_state() {
        let artifact = example_artifact("examples/stones/app.ag", "stones-exact-continuation");
        let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
        let register_player = entry_artifact(&artifact, "League", "register_player");
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
        let context = TxContext::new()
            .argent_input(
                "League",
                league_initial.clone(),
                EntryCall::new("register_player")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
                outpoint,
                league_utxo.clone(),
                0,
            )
            .argent_output("League", league_initial.clone(), CovenantBinding::new(0, covenant_id), input_value)
            .argent_output("Player", player_next.clone(), CovenantBinding::new(0, covenant_id), player_value);
        let tx = builder.build(&context).expect("exact continuation register_player passes");

        let player_template = &artifact.sil_abi.contract("Player").expect("Player contract exists").compiled.template;
        let league_contract = artifact.sil_abi.contract("League").expect("League contract exists");
        let register_entry = league_contract.entry("register_player").expect("register_player exists");
        let mut bad_prefix = decode_hex(&player_template.prefix_hex).expect("player prefix decodes");
        bad_prefix.push(0);
        let bad_prefix_sigscript = encode_entry_sig_script(
            &artifact.sil_abi,
            league_contract,
            register_entry,
            &[
                ArtifactValue::Bytes(sign_mutable_input(
                    &MutableTransaction::with_entries(tx.clone(), vec![league_utxo.clone()]),
                    0,
                    &owner,
                )),
                ArtifactValue::Bytes(owner_pk.clone()),
                ArtifactValue::Bytes(bad_prefix),
                ArtifactValue::Bytes(decode_hex(&player_template.suffix_hex).expect("player suffix decodes")),
            ],
        )
        .expect("bad prefix sigscript encodes");
        let bad_prefix_sigscript = pay_to_script_hash_signature_script_with_flags(
            p2sh_redeem_script(&tx.inputs[0].signature_script),
            bad_prefix_sigscript,
            covenant_engine_flags(),
        )
        .expect("bad prefix p2sh sigscript builds");
        let mut bad_prefix_tx = tx;
        bad_prefix_tx.inputs[0].signature_script = bad_prefix_sigscript;
        assert!(
            execute_input_with_covenants(&bad_prefix_tx, vec![league_utxo.clone()], 0).is_err(),
            "register_player must reject a corrupted Player template prefix"
        );

        let changed_league_state = league_state(vec![0x56; 32], 7, 3);
        let changed_continuation = TxContext::new()
            .argent_input(
                "League",
                league_initial,
                EntryCall::new("register_player")
                    .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
                outpoint,
                league_utxo,
                0,
            )
            .argent_output("League", changed_league_state, CovenantBinding::new(0, covenant_id), input_value)
            .argent_output("Player", player_next, CovenantBinding::new(0, covenant_id), player_value);
        assert!(builder.build(&changed_continuation).is_err(), "exact continuation must reject a changed League state");
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
        let explicit_hidden_state = TxContext::new().argent_output(
            "Minter",
            explicit_observed_template_state,
            CovenantBinding::new(0, controller_covenant_id),
            minter_value,
        );
        let hidden_field_err =
            builder.build(&explicit_hidden_state).expect_err("observed template fields must be filled by the runtime");
        assert!(
            matches!(hidden_field_err, BuilderError::HiddenRuntimeFieldProvided { ref field, .. } if field == "gen__asset_kcc20_template"),
            "unexpected error: {hidden_field_err}"
        );

        let minter_utxo = builder
            .covenant_utxo("Minter", minter_initial.clone(), minter_value, 0, false, Some(controller_covenant_id))
            .expect("minter utxo builds");
        let proxy_utxo = builder
            .covenant_utxo("kcc20_asset::MinterProxy", proxy_state.clone(), proxy_value, 0, false, Some(asset_covenant_id))
            .expect("proxy utxo builds");
        let entries = vec![minter_utxo.clone(), proxy_utxo.clone()];
        let context = TxContext::new()
            .argent_input(
                "Minter",
                minter_initial.clone(),
                EntryCall::new("mint").args_with(|tx, input_idx| {
                    args![sign_mutable_input(tx, input_idx, &owner), recipient_owner.clone(), minted_amount]
                }),
                minter_outpoint,
                minter_utxo.clone(),
                0,
            )
            .argent_input(
                "kcc20_asset::MinterProxy",
                proxy_state.clone(),
                EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
                proxy_outpoint,
                proxy_utxo.clone(),
                0,
            )
            .argent_output("Minter", minter_next.clone(), CovenantBinding::new(0, controller_covenant_id), minter_value)
            .argent_output("kcc20_asset::MinterProxy", proxy_state.clone(), CovenantBinding::new(1, asset_covenant_id), proxy_value)
            .argent_output("kcc20_asset::KCC20", recipient_state.clone(), CovenantBinding::new(1, asset_covenant_id), recipient_value);
        let tx = builder.build(&context).expect("observed ICC mint passes");

        let minter_contract = controller_artifact.sil_abi.contract("Minter").expect("Minter contract exists");
        let minter_entry = minter_contract.entry("mint").expect("mint entry exists");
        let proxy_template = &asset_artifact.sil_abi.contract("MinterProxy").expect("MinterProxy contract exists").compiled.template;
        let proxy_prefix_len = decode_hex(&proxy_template.prefix_hex).expect("proxy prefix decodes").len() as i64;
        let bad_proxy_suffix_len = decode_hex(&proxy_template.suffix_hex).expect("proxy suffix decodes").len() as i64 + 1;
        let corrupt_hidden_sigscript = encode_entry_sig_script(
            &controller_artifact.sil_abi,
            minter_contract,
            minter_entry,
            &[
                ArtifactValue::Bytes(sign_mutable_input(&MutableTransaction::with_entries(tx.clone(), entries.clone()), 0, &owner)),
                ArtifactValue::Bytes(recipient_owner.clone()),
                ArtifactValue::Int(minted_amount),
                ArtifactValue::Int(proxy_prefix_len),
                ArtifactValue::Int(bad_proxy_suffix_len),
                ArtifactValue::Bytes(
                    decode_hex(&asset_artifact.sil_abi.contract("KCC20").expect("KCC20 contract exists").compiled.template.prefix_hex)
                        .expect("KCC20 prefix decodes"),
                ),
                ArtifactValue::Bytes(
                    decode_hex(&asset_artifact.sil_abi.contract("KCC20").expect("KCC20 contract exists").compiled.template.suffix_hex)
                        .expect("KCC20 suffix decodes"),
                ),
            ],
        )
        .expect("manual corrupt observed sigscript encodes");
        let corrupt_hidden_sigscript = pay_to_script_hash_signature_script_with_flags(
            p2sh_redeem_script(&tx.inputs[0].signature_script),
            corrupt_hidden_sigscript,
            covenant_engine_flags(),
        )
        .expect("corrupt P2SH sigscript builds");
        let mut corrupt_hidden_tx = tx;
        corrupt_hidden_tx.inputs[0].signature_script = corrupt_hidden_sigscript;
        assert!(execute_input_with_covenants(&corrupt_hidden_tx, entries.clone(), 0).is_err());

        let missing_proxy = TxContext::new()
            .argent_input(
                "Minter",
                minter_initial.clone(),
                EntryCall::new("mint").args(args![vec![0; 65], recipient_owner.clone(), minted_amount]),
                minter_outpoint,
                minter_utxo.clone(),
                0,
            )
            .argent_output("Minter", minter_next.clone(), CovenantBinding::new(0, controller_covenant_id), minter_value)
            .argent_output("kcc20_asset::MinterProxy", proxy_state.clone(), CovenantBinding::new(1, asset_covenant_id), proxy_value)
            .argent_output("kcc20_asset::KCC20", recipient_state.clone(), CovenantBinding::new(1, asset_covenant_id), recipient_value);
        let missing_proxy_err = builder.build(&missing_proxy).expect_err("missing observed input is rejected by the runtime");
        assert!(matches!(missing_proxy_err, BuilderError::ObservedCountMismatch { side: Side::In, expected: 1, found: 0, .. }));

        let wrong_proxy_state = minter_proxy_state(Hash::from_bytes([0xd0; 32]));
        let wrong_proxy = TxContext::new()
            .argent_input(
                "Minter",
                minter_initial.clone(),
                EntryCall::new("mint").args(args![vec![0; 65], recipient_owner.clone(), minted_amount]),
                minter_outpoint,
                minter_utxo.clone(),
                0,
            )
            .argent_input(
                "kcc20_asset::MinterProxy",
                wrong_proxy_state,
                EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
                proxy_outpoint,
                proxy_utxo.clone(),
                0,
            );
        let wrong_proxy_err = builder.build(&wrong_proxy).expect_err("observed input state must match its UTXO script");
        assert!(matches!(wrong_proxy_err, BuilderError::ArgentInputScriptMismatch { input_index: 1, .. }));

        let wrong_recipient = TxContext::new()
            .argent_input(
                "Minter",
                minter_initial.clone(),
                EntryCall::new("mint").args_with(|tx, input_idx| {
                    args![sign_mutable_input(tx, input_idx, &owner), recipient_owner.clone(), minted_amount]
                }),
                minter_outpoint,
                minter_utxo.clone(),
                0,
            )
            .argent_input(
                "kcc20_asset::MinterProxy",
                proxy_state.clone(),
                EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
                proxy_outpoint,
                proxy_utxo.clone(),
                0,
            )
            .argent_output("Minter", minter_next, CovenantBinding::new(0, controller_covenant_id), minter_value)
            .argent_output("kcc20_asset::MinterProxy", proxy_state.clone(), CovenantBinding::new(1, asset_covenant_id), proxy_value)
            .argent_output(
                "kcc20_asset::KCC20",
                kcc20_state(recipient_owner.clone(), minted_amount + 1),
                CovenantBinding::new(1, asset_covenant_id),
                recipient_value,
            );
        assert!(builder.build(&wrong_recipient).is_err());

        let wrong_asset_minter_initial = minter_state(owner_pk.clone(), wrong_asset_covenant_id, 100, true);
        let wrong_asset_minter_next = minter_state(owner_pk, wrong_asset_covenant_id, 83, true);
        let wrong_asset_minter_utxo = builder
            .covenant_utxo("Minter", wrong_asset_minter_initial.clone(), minter_value, 0, false, Some(controller_covenant_id))
            .expect("wrong-asset minter utxo builds");
        let wrong_asset = TxContext::new()
            .argent_input(
                "Minter",
                wrong_asset_minter_initial,
                EntryCall::new("mint").args(args![vec![0; 65], recipient_owner.clone(), minted_amount]),
                minter_outpoint,
                wrong_asset_minter_utxo,
                0,
            )
            .argent_input(
                "kcc20_asset::MinterProxy",
                proxy_state.clone(),
                EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
                proxy_outpoint,
                proxy_utxo,
                0,
            )
            .argent_output("Minter", wrong_asset_minter_next, CovenantBinding::new(0, controller_covenant_id), minter_value)
            .argent_output("kcc20_asset::MinterProxy", proxy_state, CovenantBinding::new(1, asset_covenant_id), proxy_value)
            .argent_output("kcc20_asset::KCC20", recipient_state, CovenantBinding::new(1, asset_covenant_id), recipient_value);
        assert!(builder.build(&wrong_asset).is_err());
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
        let bad_interface_context = TxContext::new().argent_output(
            "Minter",
            minter_state(vec![0x22; 32], Hash::from_bytes([0xa5; 32]), 1, true),
            CovenantBinding::new(0, Hash::from_bytes([0xc0; 32])),
            1_000,
        );
        let mismatch_err = bad_interface_builder
            .build(&bad_interface_context)
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

        let agent_utxo = builder
            .covenant_utxo("open_agent::Agent", agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("agent utxo builds");
        let cell_utxo = builder
            .covenant_utxo("Cell", cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("cell UTXO builds");

        let context = TxContext::new()
            .argent_input("Cell", cell_initial.clone(), "advance", cell_outpoint, cell_utxo.clone(), 0)
            .argent_input(
                "open_agent::Agent",
                agent_initial.clone(),
                EntryCall::new("step").args(args![agent_next.clone()]),
                agent_outpoint,
                agent_utxo.clone(),
                0,
            )
            .argent_output("Cell", cell_next.clone(), CovenantBinding::new(0, controller_covenant_id), cell_value)
            .argent_output("open_agent::Agent", agent_next.clone(), CovenantBinding::new(1, agent_covenant_id), agent_value);
        let transaction = builder.build(&context).expect("context resolves and executes the open observed actor");
        assert_eq!(transaction.inputs.len(), 2);
        assert_eq!(transaction.outputs.len(), 2);
        assert_eq!(transaction.outputs[0].covenant.unwrap().authorizing_input, 0);
        assert_eq!(transaction.outputs[1].covenant.unwrap().authorizing_input, 1);
        assert!(transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

        let missing_observed = TxContext::new()
            .argent_input("Cell", cell_initial.clone(), "advance", cell_outpoint, cell_utxo, 0)
            .argent_output("Cell", cell_next.clone(), CovenantBinding::new(0, controller_covenant_id), cell_value);
        let missing_observed_err = builder.build(&missing_observed).expect_err("the declared observed input/output pair is required");
        assert!(
            matches!(&missing_observed_err, BuilderError::ObservedCountMismatch { observe, side, expected: 1, found: 0 }
                if observe == "remote" && *side == Side::In),
            "unexpected error: {missing_observed_err}"
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
        let bad_layout_cell_utxo = bad_layout_builder
            .covenant_utxo("Cell", cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("bad-layout bundle still builds the Cell UTXO");
        let bad_layout_agent_utxo = bad_layout_builder
            .covenant_utxo("open_agent::Agent", agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("bad-layout bundle still builds the Agent UTXO");
        let bad_layout_context = TxContext::new()
            .argent_input("Cell", cell_initial.clone(), "advance", cell_outpoint, bad_layout_cell_utxo, 0)
            .argent_input(
                "open_agent::Agent",
                agent_initial.clone(),
                EntryCall::new("step").args(args![agent_next.clone()]),
                agent_outpoint,
                bad_layout_agent_utxo,
                0,
            )
            .argent_output("Cell", cell_next.clone(), CovenantBinding::new(0, controller_covenant_id), cell_value)
            .argent_output("open_agent::Agent", agent_next.clone(), CovenantBinding::new(1, agent_covenant_id), agent_value);
        let bad_layout_err =
            bad_layout_builder.build(&bad_layout_context).expect_err("open observed actor state layout mismatch is rejected");
        assert!(
            matches!(
                &bad_layout_err,
                BuilderError::ObservedStateLayoutMismatch { observe, side, handle, state, actor }
                    if observe == "remote" && *side == Side::In && handle == "agent" && state == "AgentCapsule" && actor == "Agent"
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
        let expanded_cell_next = expanded_cell_initial.clone();
        let expanded_agent_initial = expanded_open_agent_state(controller_covenant_id, 2, 5);
        let expanded_agent_next = expanded_open_agent_state(controller_covenant_id, 3, 4);
        let expanded_cell_utxo = expanded_builder
            .covenant_utxo("Cell", expanded_cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("expanded Cell UTXO builds");
        let expanded_agent_utxo = expanded_builder
            .covenant_utxo("open_agent::Forager", expanded_agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("expanded agent utxo builds");
        let expanded_context = TxContext::new()
            .argent_input("Cell", expanded_cell_initial, "advance", cell_outpoint, expanded_cell_utxo, 0)
            .argent_input(
                "open_agent::Forager",
                expanded_agent_initial.clone(),
                "step",
                agent_outpoint,
                expanded_agent_utxo.clone(),
                0,
            )
            .argent_output("Cell", expanded_cell_next, CovenantBinding::new(0, controller_covenant_id), cell_value)
            .argent_output("open_agent::Forager", expanded_agent_next, CovenantBinding::new(1, agent_covenant_id), agent_value);
        expanded_builder.build(&expanded_context).expect("open ICC accepts an actor state that expands the observed capsule");

        let mut flattened_forager_state = expanded_open_agent_state(controller_covenant_id, 2, 5);
        flattened_forager_state.remove("strategy");
        flattened_forager_state.insert("hunger".to_string(), ArtifactValue::Int(2));
        flattened_forager_state.insert("mood".to_string(), ArtifactValue::Int(1));
        flattened_forager_state.insert("target_agent_id".to_string(), ArtifactValue::Bytes(vec![0x55; 32]));
        let flattened_context = TxContext::new().argent_input(
            "open_agent::Forager",
            flattened_forager_state,
            "step",
            agent_outpoint,
            expanded_agent_utxo,
            0,
        );
        let flattened_err =
            expanded_builder.build(&flattened_context).expect_err("expanded agent state must provide slot-qualified source fields");
        assert!(
            matches!(&flattened_err, BuilderError::MissingStateExpansionPreimage { contract, field, memory_state }
                if contract == "Forager" && field == "strategy" && memory_state == "ForagerStrategy"),
            "unexpected error: {flattened_err}"
        );

        let forager_type =
            builder.actor_type_handle("open_agent::Forager", "AgentCapsule").expect("Forager exposes its AgentCapsule handle");
        let forager_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x53; 32]), index: 0 };
        let forager_initial = expanded_open_agent_state(controller_covenant_id, 2, 5);
        let forager_next = expanded_open_agent_state_at(controller_covenant_id, 3, 4, 0, 0);
        let forager_cell_initial = open_cell_state(agent_covenant_id, forager_type, 7);
        let forager_cell_utxo = builder
            .covenant_utxo("Cell", forager_cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("controller cell utxo builds");
        let forager_utxo = builder
            .covenant_utxo("open_agent::Forager", forager_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("Forager utxo builds");
        let forager_context = TxContext::new()
            .argent_input("Cell", forager_cell_initial.clone(), "advance", cell_outpoint, forager_cell_utxo, 0)
            .argent_input(
                "open_agent::Forager",
                forager_initial,
                EntryCall::new("step").args(args![0, 0, 4]),
                forager_outpoint,
                forager_utxo,
                0,
            )
            .argent_output("Cell", forager_cell_initial, CovenantBinding::new(0, controller_covenant_id), cell_value)
            .argent_output("open_agent::Forager", forager_next, CovenantBinding::new(1, agent_covenant_id), agent_value);
        builder.build(&forager_context).expect("Forager route executes with expanded-memory repacking");

        let wrong_agent_next = open_agent_state(controller_covenant_id, vec![0x77; 32], 5);
        let wrong_cell_utxo = builder
            .covenant_utxo("Cell", cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
            .expect("wrong-output Cell UTXO builds");
        let wrong_agent_utxo = builder
            .covenant_utxo("open_agent::Agent", agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
            .expect("wrong-output Agent UTXO builds");
        let wrong_context = TxContext::new()
            .argent_input("Cell", cell_initial, "advance", cell_outpoint, wrong_cell_utxo, 0)
            .argent_input(
                "open_agent::Agent",
                agent_initial,
                EntryCall::new("step").args(args![wrong_agent_next.clone()]),
                agent_outpoint,
                wrong_agent_utxo,
                0,
            )
            .argent_output("Cell", cell_next, CovenantBinding::new(0, controller_covenant_id), cell_value)
            .argent_output("open_agent::Agent", wrong_agent_next, CovenantBinding::new(1, agent_covenant_id), agent_value);
        assert!(builder.build(&wrong_context).is_err(), "core physics rejects an agent output that does not spend one energy");
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
            .covenant_utxo("agent_app::Agent", agent_state.clone(), 1_000, 0, false, Some(agent_covenant_id))
            .expect("observed Agent UTXO builds");
        let cell_utxo = builder
            .covenant_utxo("Cell", cell_state.clone(), 2_000, 0, false, Some(controller_covenant_id))
            .expect("Cell UTXO builds");
        let context = TxContext::new()
            .argent_input(
                "Cell",
                cell_state,
                "advance",
                TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x55; 32]), index: 0 },
                cell_utxo,
                0,
            )
            .argent_input(
                "agent_app::Agent",
                agent_state,
                EntryCall::new("step").args(args![next_agent_state.clone()]),
                TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x66; 32]), index: 0 },
                agent_utxo,
                0,
            )
            .argent_output("Cell", next_cell_state, CovenantBinding::new(0, controller_covenant_id), 2_000)
            .argent_output("agent_app::Agent", next_agent_state, CovenantBinding::new(1, agent_covenant_id), 1_000);
        let transaction = builder.build(&context).expect("anonymous open binding resolves and executes");
        let sigscript = &transaction.inputs[0].signature_script;
        let contract = core_artifact.sil_abi.contract("Cell").expect("Cell contract exists");
        let entry = contract.entry("advance").expect("advance entry exists");
        let expected_args = vec![
            ArtifactValue::Int(decode_hex(&agent_template.prefix_hex).expect("Agent prefix decodes").len() as i64),
            ArtifactValue::Int(decode_hex(&agent_template.suffix_hex).expect("Agent suffix decodes").len() as i64),
            ArtifactValue::Bytes(agent_template_hash),
        ];
        let expected_entry = encode_entry_sig_script(&core_artifact.sil_abi, contract, entry, &expected_args)
            .expect("expected entry sigscript encodes");
        let expected =
            pay_to_script_hash_signature_script_with_flags(p2sh_redeem_script(sigscript), expected_entry, covenant_engine_flags())
                .expect("expected P2SH sigscript builds");

        assert_eq!(sigscript, &expected);
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

    fn selected_app_artifact(input: &str, app: &str, name: &str) -> Artifact {
        let counter = ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let out_dir = std::env::temp_dir().join(format!("argent-{name}-{}-{counter}", std::process::id()));
        if out_dir.exists() {
            fs::remove_dir_all(&out_dir).expect("old temp dir removed");
        }
        let program = load_program(PathBuf::from(input).as_path()).expect("fixture source loads");
        emit_build_app(&program, app, &out_dir).expect("selected app artifact builds");
        let json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        let artifact = serde_json::from_str(&json).expect("artifact deserializes");
        fs::remove_dir_all(out_dir).expect("temp build dir removed");
        artifact
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

    fn stones_player_id(outpoint: &TransactionOutpoint) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"StonesPlayer");
        bytes.extend_from_slice(&outpoint.transaction_id.as_bytes());
        bytes.extend_from_slice(&outpoint.index.to_le_bytes());
        blake2b32(&bytes)
    }

    fn p2sh_redeem_script(signature_script: &[u8]) -> Vec<u8> {
        parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(signature_script)
            .last()
            .expect("P2SH sigscript has a redeem-script push")
            .expect("P2SH sigscript parses")
            .get_data()
            .to_vec()
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
