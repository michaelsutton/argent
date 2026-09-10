use super::*;
use crate::{
    artifact::{
        ActorTargetArtifact, ActorTemplateArtifact, ArtifactIdentityError, ArtifactVerificationError, HiddenParamPurposeArtifact,
        HiddenParamSubjectArtifact, ObservedTargetArtifact, SilAbiVerificationError, SilContractArtifact, TemplatePlanError,
        TypeArtifact, route_template_proof_receipt_id, route_template_table_receipt_id,
    },
    codec::{CodecError, decode_hex, encode_entry_sig_script},
    compiler::codegen::emit_build_app,
    compiler::loader::load_program,
};
use std::{
    cell::Cell,
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
        CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    opcodes::codes::OpTrue, parse_script, pay_to_script_hash_signature_script_with_flags, script_builder::ScriptBuilder,
};
use secp256k1::{Keypair, Secp256k1, SecretKey};

static ARTIFACT_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn artifact_verification(error: &BuilderError) -> (&str, &ArtifactVerificationError) {
    match error {
        BuilderError::ArtifactVerification { app, source } => (app, source),
        _ => panic!("expected artifact verification error, found: {error}"),
    }
}

fn byte_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() { 0 } else { haystack.windows(needle.len()).filter(|window| *window == needle).count() }
}

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

fn sil_template(contract: &SilContractArtifact) -> ActorTemplateArtifact {
    let compiled = &contract.compiled;
    let (prefix, _, suffix) = compiled.script_parts(&compiled.bytecode).expect("compiled state span is valid");
    ActorTemplateArtifact { prefix: prefix.to_vec(), suffix: suffix.to_vec(), hash: compiled.template_hash }
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
        bytes.extend_from_slice(&contract.compiled.template_hash);
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

    let input_utxo =
        builder.covenant_utxo("Ticket", initial_state.clone(), input_value, 0, false, Some(covenant_id)).expect("ticket utxo builds");
    let context = TxContext::new()
        .actor_input(
            "Ticket",
            initial_state.clone(),
            EntryCall::new("redeem").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
            outpoint,
            input_utxo.clone(),
            0,
        )
        .actor_output("Ticket", redeemed_state, CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&context).expect("valid redeem tx passes");

    let wrong_pk = keypair_from_byte(2).x_only_public_key().0.serialize().to_vec();
    let bad_args = TxContext::new()
        .actor_input(
            "Ticket",
            initial_state.clone(),
            EntryCall::new("redeem").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), wrong_pk.clone()]),
            outpoint,
            input_utxo.clone(),
            0,
        )
        .actor_output("Ticket", ticket_state(owner_hash.clone(), 7, 1), CovenantBinding::new(0, covenant_id), input_value);
    assert!(builder.build(&bad_args).is_err());

    let stale_output = TxContext::new()
        .actor_input(
            "Ticket",
            initial_state.clone(),
            EntryCall::new("redeem").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
            outpoint,
            input_utxo,
            0,
        )
        .actor_output("Ticket", initial_state, CovenantBinding::new(0, covenant_id), input_value);
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
        .actor_input(
            "Issuer",
            source_state.clone(),
            EntryCall::new("issue")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &admin), admin_pk.clone(), owner_pk.clone()]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x22; 32]), 0),
            input_utxo,
            0,
        )
        .actor_output(
            "Issuer",
            state! {
                admin: blake2b32(&admin_pk),
                next_serial: 12,
            },
            CovenantBinding::new(0, covenant_id),
            1_000,
        )
        .actor_output("Ticket", ticket_state(blake2b32(&owner_pk), 11, 0), CovenantBinding::new(0, covenant_id), 500);
    let transaction = builder.build(&context).expect("issue transaction builds");
    let redeem_script = p2sh_redeem_script(&transaction.inputs[0].signature_script);
    let state_span = &actor.compiled.state_span;
    let state_script = &redeem_script[state_span.offset..state_span.offset + state_span.len];
    let decoded =
        crate::codec::decode_runtime_state_script(&artifact.sil_abi, &actor.runtime_state, state_script).expect("state decodes");

    assert_eq!(decoded.get("admin"), source_state.get("admin"));
    assert_eq!(
        decoded.get("gen__ticket_template"),
        Some(&ArtifactValue::Bytes(
            artifact.sil_abi.contract("Ticket").expect("ticket contract exists").compiled.template_hash.to_vec()
        ))
    );
    assert!(!decoded.contains_key("gen__issuer_template"), "Issuer state should not carry its own template");

    let mut explicit_hidden_state = source_state;
    explicit_hidden_state.insert("gen__ticket_template".to_string(), ArtifactValue::Bytes(vec![0; 32]));
    let explicit_hidden = TxContext::new().actor_output("Issuer", explicit_hidden_state, CovenantBinding::new(0, covenant_id), 1_000);
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
        .actor_input(
            "ReserveAsset",
            state,
            EntryCall::new("settle").args(args![100]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x34; 32]), 0),
            asset_utxo,
            0,
        )
        .actor_output("ReserveAsset", next_state, CovenantBinding::new(1, asset_covenant_id), 1_000);
    let transaction = builder.build(&context).expect("expanded actor transaction builds");
    let redeem_script = p2sh_redeem_script(&transaction.inputs[1].signature_script);
    let receipt = artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|template| template.actor == "ReserveAsset")
        .expect("ReserveAsset template receipt exists");
    let handle = &receipt.actor_type_handle;
    let prefix = &handle.template.prefix;
    let suffix = &handle.template.suffix;

    assert!(redeem_script.starts_with(prefix));
    assert!(redeem_script.ends_with(suffix));
    assert_eq!(builder.actor_type_handle("ReserveAsset", "AssetCapsule").expect("capsule handle resolves"), handle.template.hash);
    assert_ne!(handle.template.hash, receipt.sil_template_hash);
    assert_eq!(
        builder.actor_type_handle("ReserveAsset", "ReserveAssetState").expect("expanded source view resolves"),
        handle.template.hash
    );
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
    let context = TxContext::new().actor_input(
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
fn context_executes_dynamic_byte_array_sigscript_arguments_at_varying_lengths() {
    let artifact = inline_artifact(
        "context-dynamic-byte-array-argument",
        r#"
            state BlobState {
                int size;
                byte[32] digest;
            }

            actor Blob owns BlobState {
                entry store(byte[] data) emits next: Blob {
                    unrestricted(next.value);
                    BlobState next_state = {
                        size: data.length,
                        digest: blake2b(byte[](data)),
                    };

                    become next <- Blob(next_state);
                }
            }

            app BlobApp {
                actor Blob;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
    let covenant_id = Hash::from_bytes([0x43; 32]);
    let input_value = 1_000;

    for (case, size) in [0usize, 1, 2, 16, 17, 75, 76, 255, 256].into_iter().enumerate() {
        let initial = state! { size: 0, digest: vec![0; 32] };
        let payload = vec![0; size];
        let digest = blake2b32(&payload);
        let input_utxo =
            builder.covenant_utxo("Blob", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Blob UTXO builds");
        let context = TxContext::new()
            .actor_input(
                "Blob",
                initial,
                EntryCall::new("store").args(args![payload]),
                TransactionOutpoint::new(TransactionId::from_bytes([0x50 + case as u8; 32]), 0),
                input_utxo,
                0,
            )
            .actor_output("Blob", state! { size: size as i64, digest: digest }, CovenantBinding::new(0, covenant_id), input_value);

        builder.build(&context).unwrap_or_else(|err| panic!("dynamic byte[] argument of length {size} failed: {err}"));
    }
}

#[test]
fn context_executes_expanded_bool_transition_to_false() {
    let artifact = inline_artifact(
        "context-expanded-bool-transition",
        r#"
            state Toggle {
                bool enabled;
            }

            state SwitchCapsule {
                virtual toggle;
                int revision;
            }

            state SwitchState expands SwitchCapsule {
                toggle: Toggle;
            }

            actor Switch owns SwitchState {
                entry set(bool enabled) emits next: Switch {
                    SwitchState next_state = {
                        toggle: Toggle {
                            enabled: enabled,
                        },
                        revision: revision + 1,
                    };

                    unrestricted(next.value);
                    become next <- Switch(next_state);
                }
            }

            app SwitchApp {
                actor Switch;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts expanded bool artifact");
    let covenant_id = Hash::from_bytes([0x44; 32]);
    let input_value = 1_000;
    let initial = state! {
        toggle: state! { enabled: true },
        revision: 0,
    };
    let next = state! {
        toggle: state! { enabled: false },
        revision: 1,
    };
    let input_utxo =
        builder.covenant_utxo("Switch", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Switch UTXO builds");
    let context = TxContext::new()
        .actor_input(
            "Switch",
            initial,
            EntryCall::new("set").args(args![false]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x45; 32]), 0),
            input_utxo,
            0,
        )
        .actor_output("Switch", next, CovenantBinding::new(0, covenant_id), input_value);

    builder.build(&context).expect("expanded bool transition executes");
}

#[test]
fn context_executes_expanded_scalar_byte_transition() {
    let artifact = inline_artifact(
        "context-expanded-scalar-byte-transition",
        r#"
            state Policy {
                int version;
                byte network;
                int limit;
            }

            state TokenCapsule {
                virtual policy;
            }

            state TokenState expands TokenCapsule {
                policy: Policy;
            }

            actor Token owns TokenState {
                entry set(byte expected_network, byte next_network) emits next: Token {
                    require(policy.network == expected_network);

                    TokenState next_state = {
                        policy: Policy {
                            version: policy.version + 1,
                            network: next_network,
                            limit: policy.limit,
                        },
                    };

                    unrestricted(next.value);
                    become next <- Token(next_state);
                }
            }

            app TokenApp {
                actor Token;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts expanded scalar-byte artifact");
    let covenant_id = Hash::from_bytes([0x52; 32]);
    let input_value = 1_000;
    let initial = state! {
        policy: state! {
            version: 11,
            network: 7u8,
            limit: 99,
        },
    };
    let next = state! {
        policy: state! {
            version: 12,
            network: 8u8,
            limit: 99,
        },
    };
    let input_utxo =
        builder.covenant_utxo("Token", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Token UTXO builds");
    let context = TxContext::new()
        .actor_input(
            "Token",
            initial,
            EntryCall::new("set").args(args![7u8, 8u8]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x53; 32]), 0),
            input_utxo,
            0,
        )
        .actor_output("Token", next, CovenantBinding::new(0, covenant_id), input_value);

    builder.build(&context).expect("expanded scalar-byte transition executes");
}

#[test]
fn context_executes_temporal_state_and_expansion_transition() {
    let artifact = inline_artifact(
        "context-temporal-transition",
        r#"
            state Timing {
                temporal nested_at;
            }

            state ClockCapsule {
                temporal updated_at;
                virtual timing;
            }

            state ClockState expands ClockCapsule {
                timing: Timing;
            }

            actor Clock owns ClockState {
                entry advance(temporal next_at, temporal[2] checkpoints, temporal[] history) emits next: Clock {
                    require(next_at > updated_at);
                    require(checkpoints[0] == updated_at);
                    require(checkpoints[1] == next_at);
                    require(history.length == 2);
                    require(history[0] == updated_at);
                    require(history[1] == next_at);
                    ClockState next_state = {
                        updated_at: next_at,
                        timing: Timing {
                            nested_at: next_at,
                        },
                    };

                    unrestricted(next.value);
                    become next <- Clock(next_state);
                }
            }

            app ClockApp {
                actor Clock;
            }
            "#,
    );
    let contract = artifact.sil_abi.contract("Clock").expect("Clock contract exists");
    assert_eq!(
        contract.runtime_state.fields.iter().find(|field| field.name == "updated_at").map(|field| &field.ty),
        Some(&TypeArtifact::Temporal)
    );
    let advance = contract.entry("advance").expect("advance entry exists");
    assert_eq!(
        advance.params.iter().take(3).map(|param| param.ty.clone()).collect::<Vec<_>>(),
        vec![
            TypeArtifact::Temporal,
            TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Temporal), len: 2 },
            TypeArtifact::dynamic_array(TypeArtifact::Temporal),
        ]
    );
    assert_eq!(
        artifact
            .sil_abi
            .structs
            .get("Timing")
            .and_then(|state| state.fields.iter().find(|field| field.name == "nested_at"))
            .map(|field| &field.ty),
        Some(&TypeArtifact::Temporal)
    );

    let builder = TxBuilder::new(&artifact).expect("builder accepts temporal artifact");
    let covenant_id = Hash::from_bytes([0x46; 32]);
    let input_value = 1_000;
    let initial = state! {
        updated_at: 1_000_i64,
        timing: state! { nested_at: 900_i64 },
    };
    let next = state! {
        updated_at: 2_000_i64,
        timing: state! { nested_at: 2_000_i64 },
    };
    let input_utxo =
        builder.covenant_utxo("Clock", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Clock UTXO builds");
    let context = TxContext::new()
        .actor_input(
            "Clock",
            initial,
            EntryCall::new("advance").args(args![
                2_000_i64,
                ArtifactValue::Array(vec![ArtifactValue::Int(1_000), ArtifactValue::Int(2_000)]),
                ArtifactValue::Array(vec![ArtifactValue::Int(1_000), ArtifactValue::Int(2_000)]),
            ]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x47; 32]), 0),
            input_utxo,
            0,
        )
        .actor_output("Clock", next, CovenantBinding::new(0, covenant_id), input_value);

    builder.build(&context).expect("temporal state and expansion transition executes");
}

#[test]
fn context_executes_source_state_arguments_without_exposing_generated_fields() {
    let artifact = inline_artifact(
        "context-source-state-arguments",
        r#"
            state NoteState {
                int nonce;
            }

            state ArchiveState {
                int nonce;
            }

            actor Note owns NoteState {
                entry choose_scalar(NoteState note) emits next: Note {
                    unrestricted(next.value);
                    become next <- Note((note));
                }

                entry choose_fixed(NoteState[2] notes) emits next: Note {
                    unrestricted(next.value);
                    require(notes[0].nonce < notes[1].nonce);
                    become next <- Note((notes[1]));
                }

                entry choose_dynamic(NoteState[] notes) emits next: Note {
                    unrestricted(next.value);
                    require(notes.length == 3);
                    become next <- Note(((notes[notes.length - 1])));
                }

                entry archive() emits saved: Archive {
                    unrestricted(saved.value);
                    ArchiveState archived = {
                        nonce: nonce,
                    };
                    become saved <- Archive(archived);
                }
            }

            actor Archive owns ArchiveState {
                entry hold() emits none {
                    require(nonce >= 0);
                }
            }

            app NoteApp {
                actor Note;
                actor Archive;
            }
            "#,
    );
    assert!(
        artifact
            .sil_abi
            .contract("Note")
            .expect("Note contract exists")
            .runtime_state
            .fields
            .iter()
            .any(|field| field.name == "gen__archive_template"),
        "the runtime test must exercise a current state with compiler-generated fields"
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts source-state parameters");
    let covenant_id = Hash::from_bytes([0x45; 32]);
    let input_value = 1_000;
    let initial = state! { nonce: 0 };
    let state_array = |nonces: &[i64]| nonces.iter().map(|nonce| state! { nonce: *nonce }).collect::<Vec<_>>();

    let scalar_utxo =
        builder.covenant_utxo("Note", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("scalar Note UTXO builds");
    let scalar = TxContext::new()
        .actor_input(
            "Note",
            initial.clone(),
            EntryCall::new("choose_scalar").args(args![state! { nonce: 4 }]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x48; 32]), 0),
            scalar_utxo,
            0,
        )
        .actor_output("Note", state! { nonce: 4 }, CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&scalar).expect("scalar current-state argument executes");

    let explicit_hidden_utxo = builder
        .covenant_utxo("Note", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("explicit-hidden-field Note UTXO builds");
    let explicit_hidden = TxContext::new()
        .actor_input(
            "Note",
            initial.clone(),
            EntryCall::new("choose_scalar").args(args![state! {
                nonce: 4,
                gen__archive_template: vec![0; 32],
            }]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x49; 32]), 0),
            explicit_hidden_utxo,
            0,
        )
        .actor_output("Note", state! { nonce: 4 }, CovenantBinding::new(0, covenant_id), input_value);
    let err = builder.build(&explicit_hidden).expect_err("entry arguments must not accept generated state fields");
    assert!(
        matches!(err, BuilderError::Codec(CodecError::UnknownField(ref field)) if field == "gen__archive_template"),
        "unexpected error: {err}"
    );

    let fixed_utxo = builder
        .covenant_utxo("Note", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("fixed-array Note UTXO builds");
    let fixed = TxContext::new()
        .actor_input(
            "Note",
            initial.clone(),
            EntryCall::new("choose_fixed").args(args![state_array(&[3, 7])]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x46; 32]), 0),
            fixed_utxo,
            0,
        )
        .actor_output("Note", state! { nonce: 7 }, CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&fixed).expect("fixed current-state array argument executes");

    let dynamic_utxo = builder
        .covenant_utxo("Note", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("dynamic-array Note UTXO builds");
    let dynamic_states = state_array(&[2, 5, 9]);
    let dynamic = TxContext::new()
        .actor_input(
            "Note",
            initial,
            EntryCall::new("choose_dynamic").args_with(|_, _| args![dynamic_states.as_slice()]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x47; 32]), 0),
            dynamic_utxo,
            0,
        )
        .actor_output("Note", state! { nonce: 9 }, CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&dynamic).expect("dynamic current-state array argument executes");
}

#[test]
fn generated_entries_reject_mismatched_dynamic_struct_array_leaf_counts() {
    let artifact = inline_artifact(
        "context-dynamic-struct-array-cardinality",
        r#"
            state VaultState {
                int nonce;
            }

            state Item {
                int number;
                byte[2] tag;
            }

            actor Vault owns VaultState {
                entry inspect(Item[] items) emits none {
                    require(items.length == 1);
                }
            }

            app VaultApp {
                actor Vault;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts dynamic struct-array artifact");
    let covenant_id = Hash::from_bytes([0x4a; 32]);
    let state = state! { nonce: 0 };
    let input_utxo = builder.covenant_utxo("Vault", state.clone(), 1_000, 0, false, Some(covenant_id)).expect("Vault UTXO builds");
    let context = TxContext::new().actor_input(
        "Vault",
        state,
        EntryCall::new("inspect").args(args![ArtifactValue::Array(vec![ArtifactValue::Object(state! {
            number: 7,
            tag: vec![1, 2],
        })])]),
        TransactionOutpoint::new(TransactionId::from_bytes([0x4b; 32]), 0),
        input_utxo.clone(),
        0,
    );
    let transaction = builder.build(&context).expect("canonical dynamic struct array executes");

    let contract = artifact.sil_abi.contract("Vault").expect("Vault contract exists");
    let entry = contract.entry("inspect").expect("inspect entry exists");
    let mut malformed_entry = ScriptBuilder::with_flags(covenant_engine_flags());
    malformed_entry.add_data(&[7, 0, 0, 0, 0, 0, 0, 0]).expect("number leaf push builds");
    malformed_entry.add_data(&[1, 2, 3, 4]).expect("two-item tag leaf push builds");
    malformed_entry.add_data(entry.dispatch_tag.as_bytes()).expect("dispatch tag push builds");

    let mut malformed = transaction;
    malformed.inputs[0].signature_script = pay_to_script_hash_signature_script_with_flags(
        p2sh_redeem_script(&malformed.inputs[0].signature_script),
        malformed_entry.drain(),
        covenant_engine_flags(),
    )
    .expect("malformed P2SH sigscript builds");
    assert!(
        execute_input_with_covenants(&malformed, vec![input_utxo], 0).is_err(),
        "generated Sil must reject struct-array leaves with different element counts"
    );
}

#[test]
fn context_executes_expanded_state_arguments_from_authored_values() {
    let artifact = inline_artifact(
        "context-expanded-state-arguments",
        r#"
            state Capsule {
                int nonce;
                virtual detail;
            }

            state Details {
                int count;
            }

            state Expanded expands Capsule {
                detail: Details;
            }

            state ArchiveState {
                int nonce;
            }

            actor Vault owns Expanded {
                entry replace_scalar(Expanded replacement) emits out: Vault {
                    unrestricted(out.value);
                    become out <- Vault((replacement));
                }

                entry replace_fixed(Expanded[2] replacements) emits out: Vault {
                    unrestricted(out.value);
                    become out <- Vault((replacements[1]));
                }

                entry replace_dynamic(Expanded[] replacements) emits out: Vault {
                    unrestricted(out.value);
                    require(replacements.length == 3);
                    become out <- Vault((replacements[2]));
                }

                entry archive() emits out: Archive {
                    unrestricted(out.value);
                    ArchiveState archived = { nonce: nonce };
                    become out <- Archive(archived);
                }
            }

            actor Archive owns ArchiveState {
                entry hold() emits none {
                    require(nonce >= 0);
                }
            }

            app ExpandedArgs {
                actor Vault;
                actor Archive;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts expanded-state arguments");
    let covenant_id = Hash::from_bytes([0x4a; 32]);
    let input_value = 1_000;
    let expanded = |nonce: i64, count: i64| {
        state! {
            nonce: nonce,
            detail: state! { count: count },
        }
    };
    let expanded_array = |values: &[(i64, i64)]| {
        ArtifactValue::Array(values.iter().map(|(nonce, count)| ArtifactValue::Object(expanded(*nonce, *count))).collect())
    };
    let initial = expanded(0, 0);

    let scalar_utxo =
        builder.covenant_utxo("Vault", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("scalar Vault UTXO builds");
    let scalar = TxContext::new()
        .actor_input(
            "Vault",
            initial.clone(),
            EntryCall::new("replace_scalar").args(args![expanded(4, 40)]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x4b; 32]), 0),
            scalar_utxo,
            0,
        )
        .actor_output("Vault", expanded(4, 40), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&scalar).expect("scalar expanded-state argument executes");

    let raw_digest_utxo = builder
        .covenant_utxo("Vault", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("raw-digest Vault UTXO builds");
    let raw_digest = TxContext::new()
        .actor_input(
            "Vault",
            initial.clone(),
            EntryCall::new("replace_scalar").args(args![state! {
                nonce: 4,
                detail: vec![0; 32],
            }]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x4e; 32]), 0),
            raw_digest_utxo,
            0,
        )
        .actor_output("Vault", expanded(4, 40), CovenantBinding::new(0, covenant_id), input_value);
    let err = builder.build(&raw_digest).expect_err("entry arguments must not expose expanded-state digest slots");
    assert!(
        matches!(
            err,
            BuilderError::Codec(CodecError::TypeMismatch { ref expected, ref actual })
                if expected == "object" && actual == "bytes"
        ),
        "unexpected error: {err}"
    );

    let fixed_utxo = builder
        .covenant_utxo("Vault", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("fixed-array Vault UTXO builds");
    let fixed = TxContext::new()
        .actor_input(
            "Vault",
            initial.clone(),
            EntryCall::new("replace_fixed").args(args![expanded_array(&[(2, 20), (5, 50)])]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x4c; 32]), 0),
            fixed_utxo,
            0,
        )
        .actor_output("Vault", expanded(5, 50), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&fixed).expect("fixed expanded-state array argument executes");

    let dynamic_utxo = builder
        .covenant_utxo("Vault", initial.clone(), input_value, 0, false, Some(covenant_id))
        .expect("dynamic-array Vault UTXO builds");
    let dynamic = TxContext::new()
        .actor_input(
            "Vault",
            initial,
            EntryCall::new("replace_dynamic").args(args![expanded_array(&[(3, 30), (6, 60), (9, 90)])]),
            TransactionOutpoint::new(TransactionId::from_bytes([0x4d; 32]), 0),
            dynamic_utxo,
            0,
        )
        .actor_output("Vault", expanded(9, 90), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&dynamic).expect("dynamic expanded-state array argument executes");
}

#[test]
fn context_executes_and_pins_invocation_uid() {
    let artifact = inline_artifact(
        "context-invocation-uid",
        r#"
            import "std::core";

            state IssuerState {
                byte[32] last_uid;
            }

            actor Issuer owns IssuerState {
                entry issue(byte[] domain, byte[32] expected) emits next: Issuer {
                    unrestricted(next.value);
                    byte[32] uid = invocation_uid(domain);
                    require(uid == expected);

                    IssuerState next_state = {
                        last_uid: uid,
                    };
                    become next <- Issuer(next_state);
                }
            }

            app IssuerApp {
                actor Issuer;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts std::core artifact");
    let covenant_id = Hash::from_bytes([0x62; 32]);
    let outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x61; 32]), 0x0102_0304);
    let expected_uid = decode_hex("80943ad8a6ca143ccafa47978a1e8f4f5d324c582b61934652f811b436a2712b").expect("UID vector decodes");
    let runtime_uid =
        argent_runtime::stdlib::core::invocation_uid(&outpoint, b"LeaguePlayerId").expect("pinned invocation UID domain is valid");
    assert_eq!(runtime_uid.as_bytes().as_slice(), expected_uid.as_slice());
    let initial = state! { last_uid: vec![0; 32] };
    let next = state! { last_uid: expected_uid.clone() };
    let input_value = 1_000;
    let input_utxo =
        builder.covenant_utxo("Issuer", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Issuer UTXO builds");
    let context = TxContext::new()
        .actor_input(
            "Issuer",
            initial,
            EntryCall::new("issue").args(args![b"LeaguePlayerId".to_vec(), expected_uid]),
            outpoint,
            input_utxo,
            0,
        )
        .actor_output("Issuer", next, CovenantBinding::new(0, covenant_id), input_value);

    builder.build(&context).expect("invocation_uid matches the pinned digest");
}

#[test]
fn context_executes_single_actor_self_consume_without_template_witnesses() {
    let artifact = example_artifact("tests/fixtures/emit/single_actor_self_consume/app.ag", "single-actor-self-consume");
    let builder = TxBuilder::new(&artifact).expect("builder accepts single-actor artifact");
    let merge = entry_artifact(&artifact, "Counter", "merge");
    assert!(merge.hidden_params.is_empty());
    assert!(merge.route_plan.witness_recipe_ids.is_empty());

    let covenant_id = Hash::from_bytes([0x47; 32]);
    let source_state = count_state(7);
    let other_state = count_state(5);
    let next_state = count_state(12);
    let source_value = 1_200;
    let other_value = 800;
    let source_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x48; 32]), 0);
    let other_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x49; 32]), 0);
    let source_utxo = builder
        .covenant_utxo("Counter", source_state.clone(), source_value, 0, false, Some(covenant_id))
        .expect("source Counter UTXO builds");
    let other_utxo = builder
        .covenant_utxo("Counter", other_state.clone(), other_value, 0, false, Some(covenant_id))
        .expect("consumed Counter UTXO builds");

    let context = TxContext::new()
        .actor_input("Counter", source_state.clone(), "merge", source_outpoint, source_utxo.clone(), 0)
        .actor_input("Counter", other_state.clone(), "hold", other_outpoint, other_utxo.clone(), 0)
        .actor_output("Counter", next_state, CovenantBinding::new(0, covenant_id), source_value + other_value);
    let transaction = builder.build(&context).expect("single-actor self-consume executes");
    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs.len(), 1);
    assert!(transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

    let wrong_state = TxContext::new()
        .actor_input("Counter", source_state, "merge", source_outpoint, source_utxo, 0)
        .actor_input("Counter", other_state, "hold", other_outpoint, other_utxo, 0)
        .actor_output("Counter", count_state(11), CovenantBinding::new(0, covenant_id), source_value + other_value);
    let err = builder.build(&wrong_state).expect_err("merge must read and add the consumed Counter state");
    assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }));
}

#[test]
fn context_executes_ranged_consume_and_emit_over_route_bearing_states() {
    let artifact = inline_artifact(
        "context-ranged-transition",
        r#"
            state BatchState { int marker; }
            state AccountState { int balance; }

            actor enum AccountRoute {
                Account;
                Frozen;
            }

            actor Batch owns BatchState {
                entry rebalance()
                consumes { accounts: Account[0..=3], }
                emits { next: Account[1..=4], } {
                    AccountState[] next_states;
                    AccountState reserve = { balance: 100, };
                    next_states = next_states.append(reserve);
                    require(next[0].value >= 0);
                    for (i, 0, accounts.length, 3) {
                        require(accounts[i].cov_id == self.cov_id);
                        AccountState source = state(accounts[i]);
                        AccountState next_state = { balance: source.balance + 1, };
                        next_states = next_states.append(next_state);
                        require(next[i + 1].value == accounts[i].value);
                    }
                    require(next.length == accounts.length + 1);
                    unrestricted(next[0].value);
                    become next <- Account[](next_states);
                }
            }

            actor Account owns AccountState {
                entry hold() emits none { require(balance >= 0); }
                entry reroute(AccountRoute target) emits next: AccountRoute {
                    unrestricted(next.value);
                    AccountState next_state = { balance: balance, };
                    become next <- target(next_state);
                }
            }

            actor Frozen owns AccountState {
                entry hold() emits none { require(balance >= 0); }
            }

            app RangedTransition {
                actor Batch;
                actor Account;
                actor Frozen;
            }
        "#,
    );
    let account_contract = artifact.sil_abi.contract("Account").expect("Account contract exists");
    assert!(
        account_contract.runtime_state.fields.iter().any(|field| field.name.starts_with("gen__")),
        "the consumed Account state must carry compiler-owned route data"
    );

    let builder = TxBuilder::new(&artifact).expect("builder accepts ranged transition artifact");
    let covenant_id = Hash::from_bytes([0x7a; 32]);
    let batch_state = state! { marker: 0 };
    let batch_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x70; 32]), 0);
    let batch_utxo =
        builder.covenant_utxo("Batch", batch_state.clone(), 10_000, 0, false, Some(covenant_id)).expect("Batch UTXO builds");

    let context_for = |input_count: usize,
                       output_count: usize,
                       wrong_input_actor: Option<usize>,
                       wrong_output_actor: Option<usize>,
                       wrong_output_state: Option<usize>| {
        let mut context =
            TxContext::new().actor_input("Batch", batch_state.clone(), "rebalance", batch_outpoint, batch_utxo.clone(), 0);
        for index in 0..input_count {
            let balance = 10 + index as i64;
            let value = 1_000 + index as u64;
            let state = state! { balance: balance };
            let actor = if wrong_input_actor == Some(index) { "Frozen" } else { "Account" };
            let utxo = builder
                .covenant_utxo(actor, state.clone(), value, 0, false, Some(covenant_id))
                .unwrap_or_else(|err| panic!("{actor} input UTXO builds: {err}"));
            context = context.actor_input(
                actor,
                state,
                "hold",
                TransactionOutpoint::new(TransactionId::from_bytes([0x71 + index as u8; 32]), 0),
                utxo,
                0,
            );
        }
        for position in 0..output_count {
            let (expected_balance, value) = if position == 0 {
                (100, 500)
            } else {
                let input_index = position - 1;
                (11 + input_index as i64, 1_000 + input_index as u64)
            };
            let balance = expected_balance + if wrong_output_state == Some(position) { 1 } else { 0 };
            let actor = if wrong_output_actor == Some(position) { "Frozen" } else { "Account" };
            context = context.actor_output(actor, state! { balance: balance }, CovenantBinding::new(0, covenant_id), value);
        }
        context
    };

    for input_count in 0..=3 {
        let output_count = input_count + 1;
        let transaction = builder.build(&context_for(input_count, output_count, None, None, None)).unwrap_or_else(|err| {
            panic!("valid independent ranges with {input_count} consumed inputs and {output_count} outputs must execute: {err}")
        });
        assert_eq!(transaction.inputs.len(), input_count + 1);
        assert_eq!(transaction.outputs.len(), output_count);
        assert!(transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));
    }

    for position in 0..=3 {
        let err = builder
            .build(&context_for(3, 4, None, None, Some(position)))
            .expect_err("wrong output state in the ranged loop must fail");
        assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }), "position {position}: {err}");
    }

    for position in 0..3 {
        let err =
            builder.build(&context_for(3, 4, Some(position), None, None)).expect_err("wrong input actor in the ranged loop must fail");
        assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }), "position {position}: {err}");
    }

    for position in [0, 2, 3] {
        let err = builder
            .build(&context_for(3, 4, None, Some(position), None))
            .expect_err("wrong output actor in the ranged loop must fail");
        assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }), "position {position}: {err}");
    }

    let too_many_inputs = builder
        .build(&context_for(4, 4, None, None, None))
        .expect_err("input maximum plus one must be rejected while the output count remains valid");
    assert!(matches!(
        too_many_inputs,
        BuilderError::InputScript { input_index: 0, .. } | BuilderError::LeaderActorInputCardinalityMismatch { input_index: 0, .. }
    ));

    let too_few_outputs = builder
        .build(&context_for(0, 0, None, None, None))
        .expect_err("output minimum minus one must be rejected while the input count remains valid");
    assert!(matches!(too_few_outputs, BuilderError::InputScript { input_index: 0, .. }));

    let too_many_outputs = builder
        .build(&context_for(3, 5, None, None, None))
        .expect_err("output maximum plus one must be rejected while the input count remains valid");
    assert!(matches!(too_many_outputs, BuilderError::InputScript { input_index: 0, .. }));
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
                entry bump(sig owner_sig, int delta) emits next: Counter {
                    unrestricted(next.value);
                    require(checkSig(owner_sig, owner));

                    CounterState next_state = {
                        owner: owner,
                        count: count + delta,
                    };

                    become next <- Counter(next_state);
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
        .actor_input(
            "Counter",
            initial.clone(),
            EntryCall::new("bump").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), 3]),
            outpoint,
            input_utxo.clone(),
            0,
        )
        .actor_output("Counter", next, CovenantBinding::new(0, covenant_id), input_value);
    let transaction = builder.build(&context).expect("context builds");

    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.version, 1);
    assert!(transaction.inputs[0].compute_commit.compute_budget().is_some());
    assert_eq!(transaction.outputs[0].value, input_value);
    assert_eq!(transaction.outputs[0].covenant, Some(CovenantBinding { authorizing_input: 0, covenant_id }));

    let wrong_state = TxContext::new()
        .actor_input(
            "Counter",
            initial.clone(),
            EntryCall::new("bump").args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), 3]),
            outpoint,
            input_utxo,
            0,
        )
        .actor_output("Counter", initial, CovenantBinding::new(0, covenant_id), input_value);
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
                entry shift(int amount) consumes {
                    peer: Right,
                } emits {
                    left_out: Left,
                    peer_out: Right,
                } {
                    unrestricted(left_out.value);
                    unrestricted(peer_out.value);
                    BoxState next_left = { units: units - amount, };
                    BoxState next_peer = { units: peer.units + amount, };

                    become {
                        left_out <- Left(next_left),
                        peer_out <- Right(next_peer),
                    };
                }
            }

            actor Right owns BoxState {
                delegate accept_shift() consumes {
                    leader: Left,
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
    let left_utxo = builder.covenant_utxo("Left", left_initial.clone(), 3_000, 0, false, Some(covenant_id)).expect("left UTXO builds");
    let right_utxo =
        builder.covenant_utxo("Right", right_initial.clone(), 2_000, 0, false, Some(covenant_id)).expect("right UTXO builds");
    let entries = vec![left_utxo.clone(), right_utxo.clone()];

    let context = TxContext::new()
        .actor_input(
            "Left",
            left_initial,
            EntryCall::new("shift").args(args![3]),
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x61; 32]), index: 0 },
            left_utxo,
            0,
        )
        .actor_input(
            "Right",
            right_initial,
            "accept_shift",
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x62; 32]), index: 0 },
            right_utxo,
            0,
        )
        .actor_output("Left", state! { units: 7 }, CovenantBinding::new(0, covenant_id), 3_000)
        .actor_output("Right", state! { units: 4 }, CovenantBinding::new(0, covenant_id), 2_000);
    let transaction = builder.build(&context).expect("paired transition builds");

    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs.len(), 2);
    assert!(transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));
    assert!(
        transaction.outputs.iter().all(|output| { output.covenant == Some(CovenantBinding { authorizing_input: 0, covenant_id }) })
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
fn context_executes_consumed_state_digest_commitment() {
    let artifact = inline_artifact(
        "context-consumed-state-digest",
        r#"
            state LeaderState {
                int nonce;
            }

            state PeerState {
                int left;
                int right;
            }

            state ArchiveState {
                int marker;
            }

            actor Leader owns LeaderState {
                entry verify(byte[32] expected_peer_digest)
                consumes {
                    peer: Peer,
                }
                emits next: Leader {
                    require(digest(state(peer)) == expected_peer_digest);
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            actor Peer owns PeerState {
                delegate participate() consumes {
                    leader: Leader,
                } {}

                entry archive() emits next: Archive {
                    ArchiveState next_state = {
                        marker: left + right,
                    };
                    unrestricted(next.value);
                    become next <- Archive(next_state);
                }
            }

            actor Archive owns ArchiveState {
                entry hold() emits none {
                    require(marker >= 0);
                }
            }

            app DigestApp {
                actor Leader;
                actor Peer;
                actor Archive;
            }
            "#,
    );
    assert!(
        artifact
            .sil_abi
            .contract("Peer")
            .expect("Peer contract exists")
            .runtime_state
            .fields
            .iter()
            .any(|field| field.name == "gen__archive_template"),
        "the runtime test must prove generated route fields are excluded from the authored digest"
    );

    let builder = TxBuilder::new(&artifact).expect("builder accepts consumed-state digest artifact");
    let covenant_id = Hash::from_bytes([0x67; 32]);
    let leader_state = state! { nonce: 3 };
    let peer_state = state! { left: 7, right: 11 };
    let leader_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x68; 32]), 0);
    let peer_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x69; 32]), 0);
    let leader_utxo =
        builder.covenant_utxo("Leader", leader_state.clone(), 3_000, 0, false, Some(covenant_id)).expect("Leader UTXO builds");
    let peer_utxo = builder
        .covenant_utxo("Peer", peer_state.clone(), 2_000, 0, false, Some(covenant_id))
        .expect("Peer UTXO with generated route context builds");

    let mut authored_payload = kaspa_txscript::serialize_i64(7, Some(8)).expect("left packs as a fixed-width Sil int").into_vec();
    authored_payload
        .extend_from_slice(&kaspa_txscript::serialize_i64(11, Some(8)).expect("right packs as a fixed-width Sil int").into_vec());
    let expected_digest = blake3::hash(&authored_payload).as_bytes().to_vec();
    let context = |digest: Vec<u8>| {
        TxContext::new()
            .actor_input(
                "Leader",
                leader_state.clone(),
                EntryCall::new("verify").args(args![digest]),
                leader_outpoint,
                leader_utxo.clone(),
                0,
            )
            .actor_input("Peer", peer_state.clone(), "participate", peer_outpoint, peer_utxo.clone(), 0)
            .actor_output("Leader", leader_state.clone(), CovenantBinding::new(0, covenant_id), 3_000)
    };

    builder.build(&context(expected_digest.clone())).expect("authenticated authored peer-state digest matches");

    let mut wrong_digest = expected_digest;
    wrong_digest[0] ^= 1;
    let err = builder.build(&context(wrong_digest)).expect_err("wrong authored peer-state digest must fail contract execution");
    assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }), "unexpected error: {err}");
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
        .actor_input(
            "Controller",
            controller_initial.clone(),
            EntryCall::new("mint").args(args![asset_covenant_id, 7]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_input(
            "badge_asset::Badge",
            badge_initial.clone(),
            EntryCall::new("apply").args_with(|tx, input_idx| args![17, sign_mutable_input(tx, input_idx, &badge_owner)]),
            badge_outpoint,
            badge_utxo.clone(),
            0,
        )
        .actor_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
        .actor_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
    let context_tx = builder.build(&context).expect("context resolves the closed observed covenant");
    assert_eq!(context_tx.inputs.len(), 2);
    assert_eq!(context_tx.outputs.len(), 2);
    assert_eq!(context_tx.outputs[0].covenant.unwrap().authorizing_input, 0);
    assert_eq!(context_tx.outputs[1].covenant.unwrap().authorizing_input, 1);
    assert!(context_tx.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

    let extra_output = TxContext::new()
        .actor_input(
            "Controller",
            controller_initial.clone(),
            EntryCall::new("mint").args(args![asset_covenant_id, 7]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_input(
            "badge_asset::Badge",
            badge_initial.clone(),
            EntryCall::new("apply").args(args![17, vec![0; 65]]),
            badge_outpoint,
            badge_utxo.clone(),
            0,
        )
        .actor_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
        .actor_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000)
        .actor_output("badge_asset::Badge", badge_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
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
        .actor_input(
            "Controller",
            controller_initial,
            EntryCall::new("mint").args(args![asset_covenant_id, 7]),
            controller_outpoint,
            controller_utxo,
            0,
        )
        .actor_input(
            "badge_asset::Badge",
            badge_initial,
            EntryCall::new("apply").args(args![17, vec![0; 65]]),
            badge_outpoint,
            badge_utxo,
            0,
        )
        .actor_output("Controller", controller_next, CovenantBinding::new(0, controller_covenant_id), 4_000)
        .output(ordinary_badge_script, Some(CovenantBinding::new(1, asset_covenant_id)), 2_000);
    let err = builder.build(&missing_metadata).expect_err("observed outputs must retain actor metadata");
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
fn actor_and_global_functions_execute_through_static_observation() {
    let artifact = example_artifact("tests/fixtures/emit/in_app_observe_routes/app.ag", "same-app-static-observe");
    let foreign_template =
        artifact.argent.template_plan.templates.iter().find(|template| template.actor == "Foreign").expect("Foreign template exists");
    assert_ne!(
        foreign_template.actor_type_handle.template.hash, foreign_template.sil_template_hash,
        "the test must distinguish the in-app template from the source-state handle"
    );
    let builder = TxBuilder::new(&artifact).expect("same-app static observation needs no imported interface");
    let local_covenant_id = Hash::from_bytes([0x74; 32]);
    let foreign_covenant_id = Hash::from_bytes([0x75; 32]);
    let local_initial = state! { foreign_id: foreign_covenant_id, steps: 0 };
    let local_next = state! { foreign_id: foreign_covenant_id, steps: 1 };
    let foreign_state = state! { amount: 7 };
    let local_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x76; 32]), 0);
    let foreign_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x77; 32]), 0);
    let local_utxo =
        builder.covenant_utxo("Local", local_initial.clone(), 2_000, 0, false, Some(local_covenant_id)).expect("local UTXO builds");
    let foreign_utxo = builder
        .covenant_utxo("Foreign", foreign_state.clone(), 1_000, 0, false, Some(foreign_covenant_id))
        .expect("foreign UTXO builds");
    let mut transaction = builder
        .build(
            &TxContext::new()
                .actor_input("Local", local_initial.clone(), "step", local_outpoint, local_utxo.clone(), 0)
                .actor_input("Foreign", foreign_state.clone(), "hold", foreign_outpoint, foreign_utxo.clone(), 0)
                .actor_output("Local", local_next, CovenantBinding::new(0, local_covenant_id), 2_000)
                .actor_output("Foreign", foreign_state.clone(), CovenantBinding::new(1, foreign_covenant_id), 1_000),
        )
        .expect("same-app static observation builds");

    execute_transaction_with_covenants(&mut transaction, vec![local_utxo.clone(), foreign_utxo.clone()])
        .expect("same-app static observation executes");

    let wrong_result = TxContext::new()
        .actor_input("Local", local_initial, "step", local_outpoint, local_utxo, 0)
        .actor_input("Foreign", foreign_state.clone(), "hold", foreign_outpoint, foreign_utxo, 0)
        .actor_output("Local", state! { foreign_id: foreign_covenant_id, steps: 2 }, CovenantBinding::new(0, local_covenant_id), 2_000)
        .actor_output("Foreign", foreign_state, CovenantBinding::new(1, foreign_covenant_id), 1_000);
    let err = builder.build(&wrong_result).expect_err("actor and global functions determine the next step count");
    assert!(matches!(err, BuilderError::InputScript { input_index: 0, .. }));
}

#[test]
fn context_launches_named_genesis_groups_from_an_ordinary_input() {
    let source = "tests/fixtures/runtime/context_genesis_spawn/app.ag";
    let pair_artifact = selected_app_artifact(source, "PairApp", "context-genesis-launch");
    let builder = TxBuilder::new(&pair_artifact).expect("builder accepts pair artifact");

    let funding_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x61; 32]), 4);
    let funding_script = ScriptPublicKey::new(0, vec![OpTrue].into());
    let funding_utxo = UtxoEntry::new(10_000, funding_script, 0, false, None);
    let unrelated_spk = ScriptPublicKey::new(0, vec![OpTrue].into());
    let genesis_spk = ScriptPublicKey::new(0, vec![OpTrue].into());
    let context = TxContext::new()
        .input(funding_outpoint, funding_utxo, Vec::new(), 0)
        .actor_genesis_output(0, "launch::pair", "Pair", state! { amount: 7 }, 2_000)
        .output(unrelated_spk, None, 1_000)
        .genesis_output(0, "launch::pair", genesis_spk.clone(), 500)
        .actor_genesis_output(0, "launch::pair", "Pair", state! { amount: 8 }, 2_000)
        .genesis_output(0, "launch::other", genesis_spk, 500);

    let transaction = builder.build(&context).expect("ordinary input launches both named covenant groups");
    let pair_id = covenant_id(
        funding_outpoint,
        [(0, &transaction.outputs[0]), (2, &transaction.outputs[2]), (3, &transaction.outputs[3])].into_iter(),
    );
    let other_id = covenant_id(funding_outpoint, [(4, &transaction.outputs[4])].into_iter());

    assert_eq!(transaction.outputs[0].covenant, Some(CovenantBinding::new(0, pair_id)));
    assert_eq!(transaction.outputs[1].covenant, None);
    assert_eq!(transaction.outputs[2].covenant, Some(CovenantBinding::new(0, pair_id)));
    assert_eq!(transaction.outputs[3].covenant, Some(CovenantBinding::new(0, pair_id)));
    assert_eq!(transaction.outputs[4].covenant, Some(CovenantBinding::new(0, other_id)));
    assert_ne!(pair_id, other_id);

    let invalid_path = TxContext::new()
        .input(funding_outpoint, UtxoEntry::new(3_000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, None), Vec::new(), 0)
        .actor_genesis_output(0, "pair", "Pair", state! { amount: 7 }, 2_000);
    let err = builder.build(&invalid_path).expect_err("genesis paths require the launch namespace");
    assert!(matches!(err, BuilderError::InvalidGenesisPath(ref path) if path == "pair"), "unexpected error: {err}");

    let missing_input = TxContext::new()
        .input(funding_outpoint, UtxoEntry::new(3_000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, None), Vec::new(), 0)
        .actor_genesis_output(1, "launch::pair", "Pair", state! { amount: 7 }, 2_000);
    let err = builder.build(&missing_input).expect_err("launch paths must name an existing authorizing input");
    assert!(
        matches!(err, BuilderError::GenesisAuthorizingInputOutOfRange { authorizing_input: 1, input_count: 1 }),
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
    let left_pair_state = state! { amount: 42 };
    let right_pair_state = state! { amount: 43 };
    let controller_utxo = builder
        .covenant_utxo("controller_app::Controller", controller_state.clone(), 10_000, 0, false, Some(controller_id))
        .expect("controller UTXO builds");

    let callback_pair_id = Cell::new(None);
    let unrelated_spk = ScriptPublicKey::new(0, vec![OpTrue].into());
    let context = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            controller_state,
            EntryCall::new("launch").args(args![42, 43]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_output(
            "controller_app::Controller",
            state_with(|state_context| {
                callback_pair_id.set(state_context.genesis_covenant_id(0, "spawn::new_pair"));
                next_controller_state.clone()
            }),
            CovenantBinding::new(0, controller_id),
            5_000,
        )
        .actor_genesis_output(0, "spawn::new_pair", "pair_app::Pair", left_pair_state.clone(), 2_000)
        .output(unrelated_spk.clone(), None, 1_000)
        .actor_genesis_output(0, "spawn::new_pair", "pair_app::Pair", right_pair_state.clone(), 2_000);
    let transaction = builder.build(&context).expect("explicit spawn group executes");
    let pair_id = transaction.outputs[1].covenant.expect("spawn output has a covenant binding").covenant_id;
    let expected_pair_id = covenant_id(controller_outpoint, [(1, &transaction.outputs[1]), (3, &transaction.outputs[3])].into_iter());
    assert_eq!(pair_id, expected_pair_id);
    assert_eq!(transaction.outputs[3].covenant, Some(CovenantBinding::new(0, pair_id)));
    assert_eq!(callback_pair_id.get(), Some(pair_id));

    let unknown_spawn = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            state! { pair_type: builder.actor_type_handle("pair_app::Pair", "PairState").unwrap(), launches: 0 },
            EntryCall::new("launch").args(args![42, 43]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "spawn::other", "pair_app::Pair", left_pair_state.clone(), 2_000)
        .output(unrelated_spk, None, 1_000)
        .actor_genesis_output(0, "spawn::other", "pair_app::Pair", right_pair_state.clone(), 2_000);
    let err = builder.build(&unknown_spawn).expect_err("spawn paths must name a clause on the selected entry");
    assert!(matches!(err, BuilderError::UnknownSpawn(0, ref spawn) if spawn == "other"), "unexpected error: {err}");

    let incomplete_spawn = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            state! { pair_type: builder.actor_type_handle("pair_app::Pair", "PairState").unwrap(), launches: 0 },
            EntryCall::new("launch").args(args![42, 43]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "spawn::new_pair", "pair_app::Pair", left_pair_state.clone(), 2_000);
    let err = builder.build(&incomplete_spawn).expect_err("spawn groups must contain every declared output");
    assert!(matches!(err, BuilderError::InvalidSpawnGroup(ref spawn, _) if spawn == "new_pair"), "unexpected error: {err}");

    let missing_spawn = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            state! { pair_type: builder.actor_type_handle("pair_app::Pair", "PairState").unwrap(), launches: 0 },
            EntryCall::new("launch").args(args![42, 43]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000);
    let err = builder.build(&missing_spawn).expect_err("every spawn clause requires an explicit named genesis group");
    assert!(matches!(err, BuilderError::MissingSpawnGroup(0, ref spawn) if spawn == "new_pair"), "unexpected error: {err}");

    let wrong_actor_state = state! { pair_type: builder.actor_type_handle("pair_app::Pair", "PairState").unwrap(), launches: 0 };
    let wrong_actor = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            wrong_actor_state.clone(),
            EntryCall::new("launch").args(args![42, 43]),
            controller_outpoint,
            controller_utxo,
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "spawn::new_pair", "controller_app::Controller", wrong_actor_state.clone(), 2_000)
        .actor_genesis_output(0, "spawn::new_pair", "controller_app::Controller", wrong_actor_state, 2_000);
    let err = builder.build(&wrong_actor).expect_err("spawn output actors must match the declared actor type");
    assert!(matches!(err, BuilderError::InvalidSpawnGroup(ref spawn, _) if spawn == "new_pair"), "unexpected error: {err}");

    let funding_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x24; 32]), 1);
    let funding_utxo = UtxoEntry::new(2_000, ScriptPublicKey::new(0, vec![OpTrue].into()), 0, false, None);
    let ordinary_spawn = TxContext::new().input(funding_outpoint, funding_utxo, Vec::new(), 0).actor_genesis_output(
        0,
        "spawn::new_pair",
        "pair_app::Pair",
        state! { amount: 42 },
        2_000,
    );
    let err = builder.build(&ordinary_spawn).expect_err("spawn paths require an actor authorizing input");
    assert!(
        matches!(err, BuilderError::SpawnAuthorizingInputNotActor(0, ref spawn) if spawn == "new_pair"),
        "unexpected error: {err}"
    );
}

#[test]
fn context_spawns_a_static_actor_without_an_actor_type_value() {
    let source = "tests/fixtures/runtime/context_static_actor_spawn/app.ag";
    let artifact = selected_app_artifact(source, "StaticActorSpawn", "context-static-actor-spawn");
    let builder = TxBuilder::new(&artifact).expect("builder accepts static-spawn artifact");

    let launcher_id = Hash::from_bytes([0x91; 32]);
    let launcher_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x92; 32]), 3);
    let child_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x93; 32]), 4);
    let launcher_state = state! { launches: 0 };
    let child_state = state! { amount: 10 };
    let launcher_utxo =
        builder.covenant_utxo("Launcher", launcher_state.clone(), 5_000, 0, false, Some(launcher_id)).expect("launcher UTXO builds");
    let child_utxo =
        builder.covenant_utxo("Child", child_state.clone(), 2_000, 0, false, Some(launcher_id)).expect("child UTXO builds");
    let context = TxContext::new()
        .actor_input(
            "Launcher",
            launcher_state.clone(),
            EntryCall::new("launch").args(args![32]),
            launcher_outpoint,
            launcher_utxo.clone(),
            0,
        )
        .actor_input("Child", child_state.clone(), "support_launch", child_outpoint, child_utxo.clone(), 0)
        .actor_output("Launcher", state! { launches: 1 }, CovenantBinding::new(0, launcher_id), 3_000)
        .actor_genesis_output(0, "spawn::child_group", "Child", state! { amount: 42 }, 2_000);

    let transaction = builder.build(&context).expect("static actor spawn executes");
    let child_id = covenant_id(launcher_outpoint, [(1, &transaction.outputs[1])].into_iter());
    assert_eq!(transaction.outputs[1].covenant, Some(CovenantBinding::new(0, child_id)));

    let wrong_actor = TxContext::new()
        .actor_input("Launcher", launcher_state, EntryCall::new("launch").args(args![32]), launcher_outpoint, launcher_utxo, 0)
        .actor_input("Child", child_state, "support_launch", child_outpoint, child_utxo, 0)
        .actor_output("Launcher", state! { launches: 1 }, CovenantBinding::new(0, launcher_id), 3_000)
        .actor_genesis_output(0, "spawn::child_group", "Launcher", state! { launches: 42 }, 2_000);
    let err = builder.build(&wrong_actor).expect_err("static spawn requires the declared actor template");
    assert!(matches!(err, BuilderError::InvalidSpawnGroup(ref spawn, _) if spawn == "child_group"), "unexpected error: {err}");
}

#[test]
fn linked_expanded_actor_uses_a_clean_state_qualified_physical_layout() {
    let temp = std::env::temp_dir().join(format!("argent-linked-expanded-state-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("temp dir created");

    std::fs::write(
        temp.join("child.ag"),
        r#"
state ChildStorage {
    int amount;
    temporal updated_at;
    virtual detail;
}

state ChildDetail {
    int count;
}

state ChildState expands ChildStorage {
    detail: ChildDetail;
}

actor Child owns ChildState {
    entry advance() emits next: Child {
        ChildState next_state = {
            amount: amount + 1,
            updated_at: updated_at + temporal(1),
            detail: ChildDetail { count: 1 },
        };
        unrestricted(next.value);
        become next <- Child(next_state);
    }

    entry archive() emits saved: Archive {
        ArchiveState archived = {
            amount: amount,
        };
        unrestricted(saved.value);
        become saved <- Archive(archived);
    }
}

state ArchiveState {
    int amount;
}

actor Archive owns ArchiveState {
    entry hold() emits none {
        require(amount >= 0);
    }
}

app ChildApp {
    actor Child;
    actor Archive;
}
"#,
    )
    .expect("child source written");
    std::fs::write(
        temp.join("launcher.ag"),
        r#"
import app ChildApp from "./child.ag";

state LauncherState {
    int launches;
}

actor Launcher owns LauncherState {
    entry launch(cov_id child_id)
    observes existing_child by child_id {
        inputs {
            before: ChildApp::Child,
        }
        outputs {
            after: ChildApp::Child,
        }
    }
    spawns children by children_id {
        outputs {
            child: ChildApp::Child,
        }
    }
    emits next: Launcher {
        ChildState child_state = {
            amount: existing_child.inputs.before.amount + 1,
            updated_at: existing_child.inputs.before.updated_at + temporal(1),
            detail: ChildDetail { count: 1 },
        };

        require existing_child.outputs become {
            after <- ChildApp::Child(child_state),
        };
        unrestricted(children.outputs.child.value);
        require children.outputs become {
            child <- ChildApp::Child(child_state),
        };

        LauncherState next_state = {
            launches: launches + 1,
        };
        unrestricted(next.value);
        become next <- Launcher(next_state);
    }
}

app LauncherApp {
    actor Launcher;
}
"#,
    )
    .expect("launcher source written");

    let out_dir = temp.join("build");
    let compiled = crate::build_file_app_bundle(temp.join("launcher.ag"), "LauncherApp", &out_dir)
        .expect("linked expanded observation and spawn compile");
    let sil = std::fs::read_to_string(out_dir.join("sil/Launcher.sil")).expect("Launcher Sil exists");
    assert!(sil.contains("struct Gen__PhysicalChildState"), "{sil}");
    assert!(!sil.contains("Gen__ChildApp::ChildState"), "{sil}");
    let linked_layout = sil
        .split_once("struct Gen__PhysicalChildState {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(layout, _)| layout)
        .expect("Launcher declares the linked Child physical state");
    let linked_fields = linked_layout.lines().map(str::trim).filter(|line| line.ends_with(';')).collect::<Vec<_>>();
    assert_eq!(
        linked_fields,
        ["int amount;", "temporal updated_at;", "byte[32] detail;"],
        "linked state layout must contain only physical storage fields"
    );

    let child_artifact = compiled.app("ChildApp").expect("compiled bundle contains ChildApp");
    let child_contract = child_artifact.sil_abi.contract("Child").expect("Child contract exists");
    assert_eq!(
        child_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["gen__archive_template", "amount", "updated_at", "detail"],
        "the defining Child contract must exercise an in-app route field before its storage fields"
    );
    let child_handle = child_artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|template| template.actor == "Child")
        .expect("Child exports an actor-type handle");
    assert_eq!(child_handle.actor_type_handle.state, "ChildStorage");
    assert_eq!(child_handle.actor_type_handle.context_fields, ["gen__archive_template"]);

    let bundle = compiled.runtime_bundle().expect("compiled artifacts form a runtime bundle");
    let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts the linked expanded-state bundle");
    let launcher_id = Hash::from_bytes([0xa1; 32]);
    let child_id = Hash::from_bytes([0xa2; 32]);
    let launcher_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0xa3; 32]), 0);
    let child_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0xa4; 32]), 0);
    let launcher_initial = state! { launches: 0 };
    let launcher_next = state! { launches: 1 };
    let child_initial = state! {
        amount: 4,
        updated_at: 100_i64,
        detail: state! { count: 0 },
    };
    let child_next = state! {
        amount: 5,
        updated_at: 101_i64,
        detail: state! { count: 1 },
    };
    let launcher_utxo =
        builder.covenant_utxo("Launcher", launcher_initial.clone(), 5_000, 0, false, Some(launcher_id)).expect("Launcher UTXO builds");
    let child_utxo = builder
        .covenant_utxo("child_app::Child", child_initial.clone(), 2_000, 0, false, Some(child_id))
        .expect("linked Child UTXO builds from its authored expanded state");
    let mut transaction = builder
        .build(
            &TxContext::new()
                .actor_input(
                    "Launcher",
                    launcher_initial,
                    EntryCall::new("launch").args(args![child_id]),
                    launcher_outpoint,
                    launcher_utxo.clone(),
                    0,
                )
                .actor_input("child_app::Child", child_initial, "advance", child_outpoint, child_utxo.clone(), 0)
                .actor_output("Launcher", launcher_next, CovenantBinding::new(0, launcher_id), 3_000)
                .actor_output("child_app::Child", child_next.clone(), CovenantBinding::new(1, child_id), 2_000)
                .actor_genesis_output(0, "spawn::children", "child_app::Child", child_next, 2_000),
        )
        .expect("linked expanded observation and spawn build");
    execute_transaction_with_covenants(&mut transaction, vec![launcher_utxo, child_utxo])
        .expect("linked expanded observation and spawn execute");

    let _ = std::fs::remove_dir_all(temp);
}

#[test]
fn context_spawns_a_static_actor_from_a_linked_app() {
    let fixture = "tests/fixtures/runtime/context_static_linked_spawn";
    let out_dir = std::env::temp_dir().join(format!(
        "argent-static-linked-spawn-{}-{}",
        std::process::id(),
        ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    // Relay routes to Launcher without mentioning ChildApp. Launcher must
    // own the linked Child template; Relay must construct its state without it.
    let compiled = crate::build_file_app_bundle(format!("{fixture}/launcher.ag"), "LauncherApp", &out_dir)
        .expect("launcher and child apps compile as one dependency bundle");
    let launcher_artifact = compiled.primary();
    let child_artifact = compiled.app("ChildApp").expect("compiled bundle contains ChildApp");
    let relay_contract = launcher_artifact.sil_abi.contract("Relay").expect("the in-app predecessor compiles");
    let child_template = &child_artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|template| template.actor == "Child")
        .expect("Child template is exported")
        .actor_type_handle
        .template
        .hash;
    assert_eq!(
        launcher_artifact
            .sil_abi
            .contract("Launcher")
            .expect("launcher contract exists")
            .compiled
            .bytecode
            .windows(child_template.len())
            .filter(|window| *window == child_template)
            .count(),
        1,
        "Launcher pushes the linked template constant onto the stack once"
    );
    assert_eq!(
        byte_occurrences(&relay_contract.compiled.bytecode, child_template),
        0,
        "an in-app predecessor does not inherit linked template dependencies"
    );
    let launch = entry_artifact(launcher_artifact, "Launcher", "launch");
    assert!(matches!(
        &launch.spawns[0].outputs[0].target,
        Some(ActorTargetArtifact::StaticActor { app, actor }) if app == "ChildApp" && actor == "Child"
    ));
    assert_eq!(
        launch.hidden_params.iter().map(|param| (param.name.as_str(), subject_label(&param.subject))).collect::<Vec<_>>(),
        vec![
            ("gen__child_app__child_prefix_len", "ChildApp::Child"),
            ("gen__child_app__child_suffix_len", "ChildApp::Child"),
            ("gen__children_child_output_idx", "ChildApp::Child"),
        ]
    );
    assert!(launcher_artifact.sil_abi.contract("Child").is_none(), "the importing app must not recompile Child");
    assert_eq!(
        launcher_artifact.argent.interfaces.imports[0].fingerprint_hex,
        child_artifact.argent.interfaces.exports[0].fingerprint_hex
    );
    launcher_artifact.check_template_plan_consistency().expect("linked static-spawn template plan verifies");
    let mut malformed_target = launcher_artifact.clone();
    let Some(ActorTargetArtifact::StaticActor { app, .. }) =
        &mut malformed_target.argent.actors[0].entries[0].spawns[0].outputs[0].target
    else {
        unreachable!("fixture records a linked static target");
    };
    *app = "OtherApp".to_string();
    assert!(
        matches!(malformed_target.check_template_plan_consistency(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
        "linked spawn metadata must agree with its shared actor-template witnesses"
    );
    assert_eq!(
        fs::read_to_string(out_dir.join("sil/Launcher.sil")).expect("generated launcher Sil exists"),
        include_str!("../../tests/fixtures/runtime/context_static_linked_spawn/Launcher.sil")
    );
    assert_eq!(
        fs::read_to_string(out_dir.join("sil/Relay.sil")).expect("generated relay Sil exists"),
        include_str!("../../tests/fixtures/runtime/context_static_linked_spawn/Relay.sil")
    );
    assert_eq!(
        fs::read_to_string(out_dir.join("apps/ChildApp/sil/Child.sil")).expect("generated child Sil exists"),
        include_str!("../../tests/fixtures/runtime/context_static_linked_spawn/Child.sil")
    );

    let bundle = compiled.runtime_bundle().expect("compiled artifacts form a runtime bundle");
    let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts the linked static-spawn bundle");
    let launcher_id = Hash::from_bytes([0x94; 32]);
    let source_child_id = Hash::from_bytes([0x96; 32]);
    let launcher_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x95; 32]), 5);
    let source_child_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x97; 32]), 6);
    let launcher_state = state! { launches: 0 };
    let source_child_state = state! { amount: 10 };
    let launcher_utxo = builder
        .covenant_utxo("Launcher", launcher_state.clone(), 5_000, 0, false, Some(launcher_id))
        .expect("launcher UTXO carries the imported Child template");
    let source_child_utxo = builder
        .covenant_utxo("child_app::Child", source_child_state.clone(), 2_000, 0, false, Some(source_child_id))
        .expect("source Child UTXO builds from the dependency artifact");
    let context = TxContext::new()
        .actor_input(
            "Launcher",
            launcher_state.clone(),
            EntryCall::new("launch").args(args![source_child_id, 32]),
            launcher_outpoint,
            launcher_utxo.clone(),
            0,
        )
        .actor_input("child_app::Child", source_child_state.clone(), "hold", source_child_outpoint, source_child_utxo.clone(), 0)
        .actor_output("Launcher", state! { launches: 1 }, CovenantBinding::new(0, launcher_id), 3_000)
        .actor_genesis_output(0, "spawn::children", "child_app::Child", state! { amount: 42 }, 2_000);

    let transaction = builder.build(&context).expect("linked static actor spawn executes");
    let child_id = covenant_id(launcher_outpoint, [(1, &transaction.outputs[1])].into_iter());
    assert_eq!(transaction.outputs[1].covenant, Some(CovenantBinding::new(0, child_id)));

    let wrong_actor = TxContext::new()
        .actor_input(
            "Launcher",
            launcher_state,
            EntryCall::new("launch").args(args![source_child_id, 32]),
            launcher_outpoint,
            launcher_utxo,
            0,
        )
        .actor_input("child_app::Child", source_child_state, "hold", source_child_outpoint, source_child_utxo, 0)
        .actor_output("Launcher", state! { launches: 1 }, CovenantBinding::new(0, launcher_id), 3_000)
        .actor_genesis_output(0, "spawn::children", "Launcher", state! { launches: 42 }, 2_000);
    let err = builder.build(&wrong_actor).expect_err("linked static spawn requires the dependency actor");
    assert!(matches!(err, BuilderError::InvalidSpawnGroup(ref spawn, _) if spawn == "children"), "unexpected error: {err}");
    fs::remove_dir_all(out_dir).expect("temporary bundle build is removed");
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
    let first_left_state = state! { amount: 11 };
    let first_right_state = state! { amount: 12 };
    let second_state = state! { amount: 21 };
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
        .actor_input(
            "controller_app::Controller",
            controller_state.clone(),
            EntryCall::new("launch").args(args![11, 12, 21, 11, 12]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_left_state.clone(), 2_000)
        .actor_genesis_output(0, "spawn::second_pair", "pair_app::Pair", second_state.clone(), 3_000)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_right_state.clone(), 2_000)
        .actor_genesis_output(0, "spawn::third_pair", "pair_app::Pair", third_left_state.clone(), 2_000)
        .actor_genesis_output(0, "spawn::third_pair", "pair_app::Pair", third_right_state.clone(), 2_000);
    let transaction = builder.build(&context).expect("explicit interleaved genesis groups resolve by clause name");

    // Security regressions: bypass spawn resolution and invoke the generated Sil directly. The first and third clauses
    // use identical actor types, states, and values, allowing malicious indices to reuse or substitute their outputs
    // without failing template or state validation first.
    let controller_contract = controller_artifact.sil_abi.contract("Controller").expect("Controller contract exists");
    let launch_entry = controller_contract.entry("launch").expect("launch entry exists");
    let pair_template = sil_template(pair_artifact.sil_abi.contract("Pair").expect("Pair contract exists"));
    let pair_prefix = pair_template.prefix;
    let pair_suffix = pair_template.suffix;
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
    let reused_group_entry_sigscript = encode_entry_sig_script(
        &controller_artifact.sil_abi,
        "Controller",
        controller_contract,
        "launch",
        launch_entry,
        &reused_group_args,
    )
    .expect("reused-group entry sigscript encodes");
    let mut reused_group_tx = transaction.clone();
    reused_group_tx.inputs[0].signature_script =
        pay_to_script_hash_signature_script_with_flags(redeem_script.clone(), reused_group_entry_sigscript, covenant_engine_flags())
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
    let incomplete_group_entry_sigscript = encode_entry_sig_script(
        &controller_artifact.sil_abi,
        "Controller",
        controller_contract,
        "launch",
        launch_entry,
        &incomplete_group_args,
    )
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
        .actor_input(
            "controller_app::Controller",
            controller_state.clone(),
            EntryCall::new("launch").args(args![11, 12, 21, 11, 12]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state.clone(), CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "spawn::second_pair", "pair_app::Pair", second_state.clone(), 3_000)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_left_state.clone(), 2_000)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_right_state.clone(), 2_000);
    let err = builder.build(&reversed_groups).expect_err("spawn groups must remain in declaration order");
    assert!(
        matches!(
            err,
            BuilderError::InvalidSpawnGroup(ref spawn, _) if spawn == "second_pair"
        ),
        "unexpected error: {err}"
    );

    let missing_metadata = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            controller_state,
            EntryCall::new("launch").args(args![11, 12, 21, 11, 12]),
            controller_outpoint,
            controller_utxo,
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state, CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_left_state, 2_000)
        .genesis_output(0, "spawn::first_pair", ScriptPublicKey::new(0, vec![OpTrue].into()), 2_000)
        .actor_genesis_output(0, "spawn::second_pair", "pair_app::Pair", second_state, 3_000);
    let err = builder.build(&missing_metadata).expect_err("spawn outputs must retain actor metadata");
    assert!(
        matches!(
            err,
            BuilderError::InvalidSpawnGroup(ref spawn, _) if spawn == "first_pair"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn context_keeps_launch_groups_independent_from_explicit_spawns() {
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
    let first_left_state = state! { amount: 11 };
    let first_right_state = state! { amount: 12 };
    let second_state = state! { amount: 21 };
    let third_left_state = state! { amount: 31 };
    let third_right_state = state! { amount: 32 };
    let controller_utxo = builder
        .covenant_utxo("controller_app::Controller", controller_state.clone(), 10_000, 0, false, Some(controller_id))
        .expect("controller UTXO builds");

    let unrelated_spk = ScriptPublicKey::new(0, vec![OpTrue].into());

    // Independent launch groups precede or separate the three named spawn
    // groups. Spawn resolution uses the explicit clause names, while each
    // launch remains a separate consensus-valid genesis group.
    let context = TxContext::new()
        .actor_input(
            "controller_app::Controller",
            controller_state.clone(),
            EntryCall::new("launch").args(args![11, 12, 21, 31, 32]),
            controller_outpoint,
            controller_utxo,
            0,
        )
        .actor_output("controller_app::Controller", next_controller_state, CovenantBinding::new(0, controller_id), 5_000)
        .actor_genesis_output(0, "launch::extra", "controller_app::Controller", controller_state.clone(), 100)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_left_state, 2_000)
        .actor_genesis_output(0, "launch::extra", "controller_app::Controller", controller_state, 200)
        .genesis_output(0, "launch::middle", unrelated_spk, 300)
        .actor_genesis_output(0, "spawn::first_pair", "pair_app::Pair", first_right_state, 2_000)
        .actor_genesis_output(0, "spawn::second_pair", "pair_app::Pair", second_state, 3_000)
        .actor_genesis_output(0, "spawn::third_pair", "pair_app::Pair", third_left_state, 2_000)
        .actor_genesis_output(0, "spawn::third_pair", "pair_app::Pair", third_right_state, 2_000);

    builder.build(&context).expect("independent launch groups do not participate in explicit spawn resolution");
}

#[test]
fn context_builds_observed_co_spend_with_transaction_dependent_args() {
    let controller_artifact =
        example_artifact("tests/fixtures/runtime/context_signed_observed/controller.ag", "context-signed-observed-controller");
    let asset_artifact = example_artifact("tests/fixtures/runtime/context_signed_observed/asset.ag", "context-signed-observed-asset");
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
        .actor_input(
            "Controller",
            controller_initial.clone(),
            EntryCall::new("swap").args(args![asset_covenant_id, next_owner_pk.clone()]),
            controller_outpoint,
            controller_utxo.clone(),
            0,
        )
        .actor_input(
            "asset_app::Asset",
            asset_initial.clone(),
            EntryCall::new("transfer")
                .args_with(|tx, input_idx| args![next_owner_pk.clone(), sign_mutable_input(tx, input_idx, &owner)]),
            asset_outpoint,
            asset_utxo.clone(),
            0,
        )
        .actor_output("Controller", controller_next.clone(), CovenantBinding::new(0, controller_covenant_id), 4_000)
        .actor_output("asset_app::Asset", asset_next.clone(), CovenantBinding::new(1, asset_covenant_id), 2_000);
    let transaction = builder.build(&context).expect("signed observed co-spend builds");

    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs.len(), 2);
    assert_eq!(transaction.outputs[1].covenant.unwrap().authorizing_input, 1);

    let invalid_signature = TxContext::new()
        .actor_input(
            "Controller",
            controller_initial,
            EntryCall::new("swap").args(args![asset_covenant_id, next_owner_pk.clone()]),
            controller_outpoint,
            controller_utxo,
            0,
        )
        .actor_input(
            "asset_app::Asset",
            asset_initial,
            EntryCall::new("transfer").args(args![next_owner_pk.clone(), vec![0; 65]]),
            asset_outpoint,
            asset_utxo,
            0,
        )
        .actor_output("Controller", controller_next, CovenantBinding::new(0, controller_covenant_id), 4_000)
        .actor_output("asset_app::Asset", asset_next, CovenantBinding::new(1, asset_covenant_id), 2_000);
    let err = builder.build(&invalid_signature).expect_err("invalid observed co-spend signature must fail");
    assert!(matches!(err, BuilderError::InputScript { input_index: 1, .. }), "unexpected error: {err}");
}

#[test]
fn context_reuses_source_actor_witness_across_observe_and_spawn() {
    let artifact = example_artifact("tests/fixtures/runtime/context_shared_actor_witness/app.ag", "context-shared-actor-witness");
    let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");

    let controller_id = Hash::from_bytes([0xa1; 32]);
    let pair_id = Hash::from_bytes([0xa2; 32]);
    let controller_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0xa3; 32]), 0);
    let anchor_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0xa4; 32]), 0);
    let pair_type = builder.actor_type_handle("Pair", "PairState").expect("pair actor type resolves");
    let controller_initial = state! { pair_type: pair_type.clone(), launches: 0 };
    let controller_next = state! { pair_type: pair_type, launches: 1 };
    let anchor_initial = state! { amount: 7 };
    let observed_next = state! { amount: 8 };
    let spawned = state! { amount: 9 };
    let controller_utxo = builder
        .covenant_utxo("Controller", controller_initial.clone(), 6_000, 0, false, Some(controller_id))
        .expect("controller UTXO builds");
    let anchor_utxo =
        builder.covenant_utxo("Anchor", anchor_initial.clone(), 2_000, 0, false, Some(pair_id)).expect("anchor UTXO builds");

    let context = TxContext::new()
        .actor_input(
            "Controller",
            controller_initial,
            EntryCall::new("advance").args(args![pair_id, 9]),
            controller_outpoint,
            controller_utxo,
            0,
        )
        .actor_input("Anchor", anchor_initial, "advance", anchor_outpoint, anchor_utxo, 0)
        .actor_output("Controller", controller_next, CovenantBinding::new(0, controller_id), 6_000)
        .actor_output("Pair", observed_next, CovenantBinding::new(1, pair_id), 2_000)
        .actor_genesis_output(0, "spawn::newborn", "Pair", spawned, 1_000);
    let transaction = builder.build(&context).expect("shared observed witness supplies the spawned template");

    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs.len(), 3);
    assert_eq!(transaction.outputs[1].covenant, Some(CovenantBinding::new(1, pair_id)));
    assert_eq!(transaction.outputs[2].covenant.expect("spawned output has a covenant").authorizing_input, 0);
}

#[test]
fn route_plan_builds_stones_start_game_and_rejects_bad_routes() {
    let artifact = example_artifact("examples/stones/app.ag", "stones-route-plan");
    let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
    let entry = entry_artifact(&artifact, "Player", "start_game");
    assert_eq!(entry.route_plan.leader_input.as_ref().map(|input| (input.actor.as_str(), input.cov_index)), Some(("Player", Some(0))));
    assert_eq!(entry.route_plan.consumes[0].name, "opponent");
    assert_eq!(entry.route_plan.consumes[0].actor, "Player");
    assert_eq!(entry.route_plan.consumes[0].cov_index, Some(1));
    assert_eq!(
        entry.route_plan.outputs.iter().map(|output| (output.name.as_str(), output.auth_index)).collect::<Vec<_>>(),
        vec![("self_out", Some(0)), ("opponent_out", Some(1)), ("game", Some(2))]
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
    let player_a_utxo =
        builder.covenant_utxo("Player", initial_a.clone(), input_a_value, 0, false, Some(covenant_id)).expect("player A utxo builds");
    let player_b_utxo =
        builder.covenant_utxo("Player", initial_b.clone(), input_b_value, 0, false, Some(covenant_id)).expect("player B utxo builds");
    let entries = vec![player_a_utxo.clone(), player_b_utxo.clone()];

    let undeclared_delegate = TxContext::new()
        .actor_input("Player", initial_a.clone(), EntryCall::new("retire"), outpoint_a, player_a_utxo.clone(), 0)
        .actor_input("Player", initial_b.clone(), EntryCall::new("accept_start"), outpoint_b, player_b_utxo.clone(), 0);
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
        .actor_input(
            "Player",
            initial_a.clone(),
            EntryCall::new("start_game")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_a), owner_a_pk.clone(), 0, 7, 3]),
            outpoint_a,
            player_a_utxo.clone(),
            0,
        )
        .actor_input(
            "Player",
            initial_b.clone(),
            EntryCall::new("accept_start")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_b), owner_b_pk.clone()]),
            outpoint_b,
            player_b_utxo.clone(),
            0,
        )
        .actor_output("Player", next_a.clone(), CovenantBinding::new(0, covenant_id), input_a_value)
        .actor_output("Player", next_b.clone(), CovenantBinding::new(0, covenant_id), input_b_value)
        .actor_output("StonesGame", next_game.clone(), CovenantBinding::new(0, covenant_id), game_value);
    let tx = builder.build(&context).expect("leader and delegate inputs pass");

    let player_contract = artifact.sil_abi.contract("Player").expect("Player contract exists");
    let player_template = sil_template(player_contract);
    let wrong_delegate_sigscript = {
        let populated = MutableTransaction::with_entries(tx.clone(), entries.clone());
        let delegate_sig = sign_mutable_input(&populated, 1, &owner_b);
        let prefix_len = player_template.prefix.len() as i64;
        let suffix_len = player_template.suffix.len() as i64;
        let accept_entry = player_contract.entry("accept_start").expect("accept_start exists");
        let sigscript = encode_entry_sig_script(
            &artifact.sil_abi,
            "Player",
            player_contract,
            "accept_start",
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
        .actor_input(
            "Player",
            initial_a.clone(),
            EntryCall::new("start_game")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_a), owner_a_pk.clone(), 0, 7, 3]),
            outpoint_a,
            player_a_utxo.clone(),
            0,
        )
        .actor_input(
            "Player",
            initial_b.clone(),
            EntryCall::new("accept_start")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_b), owner_b_pk.clone()]),
            outpoint_b,
            player_b_utxo,
            0,
        )
        .actor_output("Player", next_b, CovenantBinding::new(0, covenant_id), input_b_value)
        .actor_output("Player", next_a, CovenantBinding::new(0, covenant_id), input_a_value)
        .actor_output("StonesGame", next_game.clone(), CovenantBinding::new(0, covenant_id), game_value);
    assert!(builder.build(&swapped_outputs).is_err());

    let wrong_peer = builder
        .covenant_utxo("League", league_state(vec![0; 32], 7, 3), input_b_value, 0, false, Some(covenant_id))
        .expect("wrong-template peer utxo builds");
    let wrong_peer = TxContext::new()
        .actor_input(
            "Player",
            initial_a,
            EntryCall::new("start_game")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner_a), owner_a_pk.clone(), 0, 7, 3]),
            outpoint_a,
            player_a_utxo,
            0,
        )
        .input(outpoint_b, wrong_peer, Vec::new(), 0)
        .actor_output(
            "Player",
            player_state(owner_a_hash, player_a_id, 1, 0, 0, 0),
            CovenantBinding::new(0, covenant_id),
            input_a_value,
        )
        .actor_output(
            "Player",
            player_state(owner_b_hash, player_b_id, 1, 0, 0, 0),
            CovenantBinding::new(0, covenant_id),
            input_b_value,
        )
        .actor_output("StonesGame", next_game, CovenantBinding::new(0, covenant_id), game_value);
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
    let player_utxo =
        builder.covenant_utxo("Player", player_initial.clone(), input_value, 0, false, Some(covenant_id)).expect("Player utxo builds");
    let enter_mux = TxContext::new()
        .actor_input("Player", player_initial.clone(), "enter_mux", player_outpoint, player_utxo.clone(), 0)
        .actor_output("Mux", mux_initial.clone(), CovenantBinding::new(0, covenant_id), input_value);
    let enter_mux_tx = builder.build(&enter_mux).expect("Player can enter the mux family");

    let player_contract = artifact.sil_abi.contract("Player").expect("Player contract exists");
    let enter_mux = player_contract.entry("enter_mux").expect("enter_mux ABI exists");
    let mux_template = sil_template(artifact.sil_abi.contract("Mux").expect("Mux contract exists"));
    let mut wrong_routes = route_family_table_bytes(&artifact, "route_family/BoardState/mux");
    wrong_routes[0] ^= 1;
    let bad_route_table_sigscript = encode_entry_sig_script(
        &artifact.sil_abi,
        "Player",
        player_contract,
        "enter_mux",
        enter_mux,
        &[ArtifactValue::Bytes(mux_template.prefix), ArtifactValue::Bytes(mux_template.suffix), ArtifactValue::Bytes(wrong_routes)],
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
        .actor_input("Mux", mux_initial.clone(), "choose_pawn", mux_outpoint, mux_utxo.clone(), 0)
        .actor_output("Pawn", pawn_next.clone(), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&choose_pawn).expect("Mux can route to Pawn by table slice");

    let dynamic_pawn_next = board_state(7, 1);
    let context = TxContext::new()
        .actor_input(
            "Mux",
            mux_initial.clone(),
            EntryCall::new("choose").args(args![actor("Pawn")]),
            mux_outpoint,
            mux_utxo.clone(),
            0,
        )
        .actor_output("Pawn", dynamic_pawn_next.clone(), CovenantBinding::new(0, covenant_id), input_value);
    let context_tx = builder.build(&context).expect("context builder resolves the dynamic route witnesses");
    assert!(context_tx.inputs[0].compute_commit.compute_budget().is_some());

    let dynamic_knight = TxContext::new()
        .actor_input(
            "Mux",
            mux_initial.clone(),
            EntryCall::new("choose").args(args![actor("Knight")]),
            mux_outpoint,
            mux_utxo.clone(),
            0,
        )
        .actor_output("Knight", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&dynamic_knight).expect("Mux selector can choose the second table entry");

    let missing_selector = TxContext::new()
        .actor_input("Mux", mux_initial.clone(), EntryCall::new("choose").args(args![0]), mux_outpoint, mux_utxo.clone(), 0)
        .actor_output("Pawn", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
    let missing_selector = builder.build(&missing_selector).expect_err("selector entries require an explicit template choice");
    assert!(
        matches!(missing_selector, BuilderError::MissingTemplateSelectorChoice { ref selector } if selector == "target"),
        "unexpected error: {missing_selector}"
    );

    let invalid_selector = TxContext::new()
        .actor_input(
            "Mux",
            mux_initial.clone(),
            EntryCall::new("choose").args(args![actor("League")]),
            mux_outpoint,
            mux_utxo.clone(),
            0,
        )
        .actor_output("Pawn", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
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
        .actor_input(
            "Mux",
            mux_initial.clone(),
            EntryCall::new("choose").args(args![actor("Knight")]),
            mux_outpoint,
            mux_utxo.clone(),
            0,
        )
        .actor_output("Pawn", dynamic_pawn_next, CovenantBinding::new(0, covenant_id), input_value);
    assert!(builder.build(&wrong_selector).is_err(), "selector witness must match the actor selected by table index");

    let const_knight = TxContext::new()
        .actor_input("Mux", mux_initial.clone(), "choose_knight_const", mux_outpoint, mux_utxo.clone(), 0)
        .actor_output("Knight", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&const_knight).expect("fixed actor enum selector can route to Knight without caller selector metadata");

    let const_wrong_output = TxContext::new()
        .actor_input("Mux", mux_initial.clone(), "choose_knight_const", mux_outpoint, mux_utxo.clone(), 0)
        .actor_output("Pawn", board_state(7, 1), CovenantBinding::new(0, covenant_id), input_value);
    assert!(builder.build(&const_wrong_output).is_err(), "fixed actor enum selector must reject a non-Knight output");

    let wrong_worker = TxContext::new().actor_input("Mux", mux_initial, "choose_pawn", mux_outpoint, mux_utxo, 0).actor_output(
        "Knight",
        pawn_next,
        CovenantBinding::new(0, covenant_id),
        input_value,
    );
    assert!(builder.build(&wrong_worker).is_err(), "choose_pawn must reject an output using the wrong worker template");
}

#[test]
fn gate_less_route_family_rejects_selector_for_appended_rep() {
    let artifact = inline_artifact(
        "gate-less-selector-bound",
        r#"
            state BoardState {
                int ply;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Mux owns BoardState {
                entry choose(MoveActor target) emits next: MoveActor {
                    unrestricted(next.value);
                    BoardState next_state = {
                        ply: ply + 1,
                    };

                    become next <- target(next_state);
                }
            }

            actor Pawn owns BoardState {
                entry idle() emits none {
                    require(ply >= 0);
                }
            }

            actor Knight owns BoardState {
                entry idle() emits none {
                    require(ply >= 1);
                }
            }

            app GateLessSelectorBound {
                actor Mux;
                actor Pawn;
                actor Knight;
            }
            "#,
    );
    let builder = TxBuilder::new(&artifact).expect("builder accepts artifact");
    let covenant_id = Hash::from_bytes([0x71; 32]);
    let input_value = 1_000;
    let initial_state = state! { ply: 0 };
    let next_state = state! { ply: 1 };
    let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x72; 32]), index: 0 };
    let input_utxo =
        builder.covenant_utxo("Mux", initial_state.clone(), input_value, 0, false, Some(covenant_id)).expect("Mux utxo builds");
    let context = TxContext::new()
        .actor_input("Mux", initial_state, EntryCall::new("choose").args(args![actor("Pawn")]), outpoint, input_utxo.clone(), 0)
        .actor_output("Pawn", next_state.clone(), CovenantBinding::new(0, covenant_id), input_value);
    let mut tx = builder.build(&context).expect("valid selector transaction builds");

    // Make table slot 2 otherwise valid for Mux, then bypass the builder's
    // actor-enum check and pass the raw selector directly to the Sil entry.
    let mux_output =
        builder.covenant_utxo("Mux", next_state, input_value, 0, false, Some(covenant_id)).expect("Mux continuation output builds");
    tx.outputs[0].script_public_key = mux_output.script_public_key;

    let mux_contract = artifact.sil_abi.contract("Mux").expect("Mux contract exists");
    let choose = mux_contract.entry("choose").expect("choose entry exists");
    let mux_template = sil_template(mux_contract);
    let malicious_entry_sigscript = encode_entry_sig_script(
        &artifact.sil_abi,
        "Mux",
        mux_contract,
        "choose",
        choose,
        &[ArtifactValue::Int(2), ArtifactValue::Bytes(mux_template.prefix), ArtifactValue::Bytes(mux_template.suffix)],
    )
    .expect("raw selector sigscript encodes");
    tx.inputs[0].signature_script = pay_to_script_hash_signature_script_with_flags(
        p2sh_redeem_script(&tx.inputs[0].signature_script),
        malicious_entry_sigscript,
        covenant_engine_flags(),
    )
    .expect("raw selector P2SH sigscript builds");

    assert!(
        execute_input_with_covenants(&tx, vec![input_utxo], 0).is_err(),
        "Sil must reject selector 2 even though the representative occupies table slot 2"
    );
}

#[test]
fn builder_rejects_template_plan_hash_mismatch() {
    let mut artifact = tickets_artifact();
    artifact.check_template_plan_consistency().expect("fixture receipt verifies before mutation");
    let issuer_receipt = artifact
        .argent
        .template_plan
        .templates
        .iter_mut()
        .find(|template| template.actor == "Issuer")
        .expect("Issuer template receipt exists");
    issuer_receipt.sil_template_hash = [0; 32];

    let err = match TxBuilder::new(&artifact) {
        Ok(_) => panic!("builder must reject a corrupted template plan receipt"),
        Err(err) => err,
    };
    let (_, source) = artifact_verification(&err);
    assert!(
        matches!(
            source,
            ArtifactVerificationError::TemplatePlan(TemplatePlanError::TemplateHashMismatch { id, .. })
                if id == "template/issuer"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn builder_rejects_sil_template_hash_mismatch() {
    let mut artifact = tickets_artifact();
    artifact.check_sil_abi_consistency().expect("fixture Sil ABI is consistent before mutation");
    let issuer_contract = artifact.sil_abi.contracts.get_mut("Issuer").expect("Issuer Sil contract exists");
    issuer_contract.compiled.template_hash = [0; 32];
    let issuer_receipt = artifact
        .argent
        .template_plan
        .templates
        .iter_mut()
        .find(|template| template.actor == "Issuer")
        .expect("Issuer template receipt exists");
    issuer_receipt.sil_template_hash = issuer_contract.compiled.template_hash;

    let err = match TxBuilder::new(&artifact) {
        Ok(_) => panic!("builder must reject a Sil template hash that does not match its contract code"),
        Err(err) => err,
    };
    let (_, source) = artifact_verification(&err);
    assert!(
        matches!(
            source,
            ArtifactVerificationError::SilAbi(SilAbiVerificationError::TemplateHashMismatch { contract, .. })
                if contract == "Issuer"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn builder_rejects_route_template_table_mismatch() {
    let mut artifact = example_artifact("examples/toy_chess/app.ag", "toy-chess-route-table-plan");
    artifact.check_template_plan_consistency().expect("fixture receipt verifies before mutation");
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
    let (_, source) = artifact_verification(&err);
    assert!(
        matches!(
            source,
            ArtifactVerificationError::TemplatePlan(TemplatePlanError::RouteTableOffsetMismatch {
                    id,
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
    artifact.check_template_plan_consistency().expect("fixture receipt verifies before mutation");
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
    let (_, source) = artifact_verification(&err);
    assert!(
        matches!(
            source,
            ArtifactVerificationError::TemplatePlan(TemplatePlanError::RouteProofMismatch { id, index: 1, .. })
                if id == "route_proof/BoardState/gen__mux_routes"
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
                entry bump(int amount) emits next: Foo {
                    unrestricted(next.value);
                    FooState next_state = {
                        count: count + amount,
                    };
                    become next <- Foo(next_state);
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

    let input_utxo = builder.covenant_utxo("Foo", initial.clone(), input_value, 0, false, Some(covenant_id)).expect("foo utxo builds");
    let context = TxContext::new()
        .actor_input("Foo", initial.clone(), EntryCall::new("bump").args(args![5]), outpoint, input_utxo.clone(), 0)
        .actor_output("Foo", next.clone(), CovenantBinding::new(0, covenant_id), input_value);
    builder.build(&context).expect("same-template transition passes");

    let wrong_template = TxContext::new()
        .actor_input("Foo", initial, EntryCall::new("bump").args(args![5]), outpoint, input_utxo, 0)
        .actor_output("Bar", next, CovenantBinding::new(0, covenant_id), input_value);
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

    let league_utxo =
        builder.covenant_utxo("League", league_initial.clone(), input_value, 0, false, Some(covenant_id)).expect("league utxo builds");
    let context = TxContext::new()
        .actor_input(
            "League",
            league_initial.clone(),
            EntryCall::new("register_player")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
            outpoint,
            league_utxo.clone(),
            0,
        )
        .actor_output("League", league_initial.clone(), CovenantBinding::new(0, covenant_id), input_value)
        .actor_output("Player", player_next.clone(), CovenantBinding::new(0, covenant_id), player_value);
    let tx = builder.build(&context).expect("exact continuation register_player passes");

    let player_template = sil_template(artifact.sil_abi.contract("Player").expect("Player contract exists"));
    let league_contract = artifact.sil_abi.contract("League").expect("League contract exists");
    let register_entry = league_contract.entry("register_player").expect("register_player exists");
    let mut bad_prefix = player_template.prefix;
    bad_prefix.push(0);
    let bad_prefix_sigscript = encode_entry_sig_script(
        &artifact.sil_abi,
        "League",
        league_contract,
        "register_player",
        register_entry,
        &[
            ArtifactValue::Bytes(sign_mutable_input(
                &MutableTransaction::with_entries(tx.clone(), vec![league_utxo.clone()]),
                0,
                &owner,
            )),
            ArtifactValue::Bytes(owner_pk.clone()),
            ArtifactValue::Bytes(bad_prefix),
            ArtifactValue::Bytes(player_template.suffix),
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
        .actor_input(
            "League",
            league_initial,
            EntryCall::new("register_player")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), owner_pk.clone()]),
            outpoint,
            league_utxo,
            0,
        )
        .actor_output("League", changed_league_state, CovenantBinding::new(0, covenant_id), input_value)
        .actor_output("Player", player_next, CovenantBinding::new(0, covenant_id), player_value);
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

    let minter_utxo = builder
        .covenant_utxo("Minter", minter_initial.clone(), minter_value, 0, false, Some(controller_covenant_id))
        .expect("minter utxo builds");
    let proxy_utxo = builder
        .covenant_utxo("kcc20_asset::MinterProxy", proxy_state.clone(), proxy_value, 0, false, Some(asset_covenant_id))
        .expect("proxy utxo builds");
    let entries = vec![minter_utxo.clone(), proxy_utxo.clone()];
    let context = TxContext::new()
        .actor_input(
            "Minter",
            minter_initial.clone(),
            EntryCall::new("mint")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), recipient_owner.clone(), minted_amount]),
            minter_outpoint,
            minter_utxo.clone(),
            0,
        )
        .actor_input(
            "kcc20_asset::MinterProxy",
            proxy_state.clone(),
            EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
            proxy_outpoint,
            proxy_utxo.clone(),
            0,
        )
        .actor_output("Minter", minter_next.clone(), CovenantBinding::new(0, controller_covenant_id), minter_value)
        .actor_output("kcc20_asset::MinterProxy", proxy_state.clone(), CovenantBinding::new(1, asset_covenant_id), proxy_value)
        .actor_output("kcc20_asset::KCC20", recipient_state.clone(), CovenantBinding::new(1, asset_covenant_id), recipient_value);
    let tx = builder.build(&context).expect("observed ICC mint passes");

    let minter_contract = controller_artifact.sil_abi.contract("Minter").expect("Minter contract exists");
    let minter_entry = minter_contract.entry("mint").expect("mint entry exists");
    let proxy_template = sil_template(asset_artifact.sil_abi.contract("MinterProxy").expect("MinterProxy contract exists"));
    let proxy_prefix_len = proxy_template.prefix.len() as i64;
    let bad_proxy_suffix_len = proxy_template.suffix.len() as i64 + 1;
    let corrupt_hidden_sigscript = encode_entry_sig_script(
        &controller_artifact.sil_abi,
        "Minter",
        minter_contract,
        "mint",
        minter_entry,
        &[
            ArtifactValue::Bytes(sign_mutable_input(&MutableTransaction::with_entries(tx.clone(), entries.clone()), 0, &owner)),
            ArtifactValue::Bytes(recipient_owner.clone()),
            ArtifactValue::Int(minted_amount),
            ArtifactValue::Bytes(sil_template(asset_artifact.sil_abi.contract("KCC20").expect("KCC20 contract exists")).prefix),
            ArtifactValue::Bytes(sil_template(asset_artifact.sil_abi.contract("KCC20").expect("KCC20 contract exists")).suffix),
            ArtifactValue::Int(proxy_prefix_len),
            ArtifactValue::Int(bad_proxy_suffix_len),
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
        .actor_input(
            "Minter",
            minter_initial.clone(),
            EntryCall::new("mint").args(args![vec![0; 65], recipient_owner.clone(), minted_amount]),
            minter_outpoint,
            minter_utxo.clone(),
            0,
        )
        .actor_output("Minter", minter_next.clone(), CovenantBinding::new(0, controller_covenant_id), minter_value)
        .actor_output("kcc20_asset::MinterProxy", proxy_state.clone(), CovenantBinding::new(1, asset_covenant_id), proxy_value)
        .actor_output("kcc20_asset::KCC20", recipient_state.clone(), CovenantBinding::new(1, asset_covenant_id), recipient_value);
    let missing_proxy_err = builder.build(&missing_proxy).expect_err("missing observed input is rejected by the runtime");
    assert!(matches!(missing_proxy_err, BuilderError::ObservedCountMismatch { side: Side::In, expected: 1, found: 0, .. }));

    let wrong_proxy_state = minter_proxy_state(Hash::from_bytes([0xd0; 32]));
    let wrong_proxy = TxContext::new()
        .actor_input(
            "Minter",
            minter_initial.clone(),
            EntryCall::new("mint").args(args![vec![0; 65], recipient_owner.clone(), minted_amount]),
            minter_outpoint,
            minter_utxo.clone(),
            0,
        )
        .actor_input(
            "kcc20_asset::MinterProxy",
            wrong_proxy_state,
            EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
            proxy_outpoint,
            proxy_utxo.clone(),
            0,
        );
    let wrong_proxy_err = builder.build(&wrong_proxy).expect_err("observed input state must match its UTXO script");
    assert!(matches!(wrong_proxy_err, BuilderError::ActorInputScriptMismatch { input_index: 1, .. }));

    let wrong_recipient = TxContext::new()
        .actor_input(
            "Minter",
            minter_initial.clone(),
            EntryCall::new("mint")
                .args_with(|tx, input_idx| args![sign_mutable_input(tx, input_idx, &owner), recipient_owner.clone(), minted_amount]),
            minter_outpoint,
            minter_utxo.clone(),
            0,
        )
        .actor_input(
            "kcc20_asset::MinterProxy",
            proxy_state.clone(),
            EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
            proxy_outpoint,
            proxy_utxo.clone(),
            0,
        )
        .actor_output("Minter", minter_next, CovenantBinding::new(0, controller_covenant_id), minter_value)
        .actor_output("kcc20_asset::MinterProxy", proxy_state.clone(), CovenantBinding::new(1, asset_covenant_id), proxy_value)
        .actor_output(
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
        .actor_input(
            "Minter",
            wrong_asset_minter_initial,
            EntryCall::new("mint").args(args![vec![0; 65], recipient_owner.clone(), minted_amount]),
            minter_outpoint,
            wrong_asset_minter_utxo,
            0,
        )
        .actor_input(
            "kcc20_asset::MinterProxy",
            proxy_state.clone(),
            EntryCall::new("mint").args(args![proxy_state.clone(), recipient_state.clone()]),
            proxy_outpoint,
            proxy_utxo,
            0,
        )
        .actor_output("Minter", wrong_asset_minter_next, CovenantBinding::new(0, controller_covenant_id), minter_value)
        .actor_output("kcc20_asset::MinterProxy", proxy_state, CovenantBinding::new(1, asset_covenant_id), proxy_value)
        .actor_output("kcc20_asset::KCC20", recipient_state, CovenantBinding::new(1, asset_covenant_id), recipient_value);
    assert!(builder.build(&wrong_asset).is_err());
}

#[test]
fn artifact_bundle_rejects_bad_ids_dependency_ids_and_interface_mismatches() {
    let controller_artifact = icc_controller_artifact();
    let asset_artifact = icc_asset_artifact();

    controller_artifact.verify_id().expect("controller artifact id is stable");
    asset_artifact.verify_id().expect("asset artifact id is stable");
    let Err(missing_dependency_err) = TxBuilder::new(&controller_artifact) else {
        panic!("a builder must reject a missing app dependency");
    };
    assert!(
        matches!(
            missing_dependency_err,
            BuilderError::MissingDependencyArtifact { ref app, ref dependency, .. }
                if app == "KCC20MintController" && dependency == "KCC20Asset"
        ),
        "unexpected error: {missing_dependency_err}"
    );
    let bundle = ArtifactBundle::new(&controller_artifact)
        .expect("bundle accepts controller artifact")
        .with_app("kcc20_asset", &asset_artifact)
        .expect("matching observed artifact attaches");
    TxBuilder::from_bundle(&bundle).expect("builder accepts valid bundle");
    ArtifactBundle::named("kcc20_mint_controller", &controller_artifact).expect("bundle accepts an explicitly named primary artifact");

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
    let (app, source) = artifact_verification(&bad_id_err);
    assert_eq!(app, "kcc20_asset");
    assert!(matches!(source, ArtifactVerificationError::Identity(ArtifactIdentityError::ArtifactIdMismatch { .. })));

    let mut different_asset = asset_artifact.clone();
    different_asset.generator.version.push_str("-different");
    different_asset.id = different_asset.computed_id_hex().expect("different dependency artifact id computes");
    let different_bundle = ArtifactBundle::new(&controller_artifact)
        .expect("controller artifact remains valid")
        .with_app("kcc20_asset", &different_asset)
        .expect("individually valid dependency artifact attaches");
    let Err(different_err) = TxBuilder::from_bundle(&different_bundle) else {
        panic!("a different dependency artifact must be rejected");
    };
    assert!(matches!(
        different_err,
        BuilderError::DependencyArtifactMismatch {
            app,
            dependency,
            expected_artifact_id,
            found_dependency,
            found_artifact_id,
        }
            if app == "KCC20MintController"
                && dependency == "KCC20Asset"
                && expected_artifact_id == asset_artifact.id
                && found_dependency == "KCC20Asset"
                && found_artifact_id == different_asset.id
    ));

    let mut wrong_name_controller = controller_artifact.clone();
    wrong_name_controller
        .dependencies
        .iter_mut()
        .find(|dependency| dependency.app == "KCC20Asset")
        .expect("controller records its asset dependency")
        .app = "KCC20_Asset".to_string();
    wrong_name_controller.id = wrong_name_controller.computed_id_hex().expect("changed dependency app name computes");
    let wrong_name_bundle = ArtifactBundle::new(&wrong_name_controller)
        .expect("modified controller artifact remains valid")
        .with_app("kcc20_asset", &asset_artifact)
        .expect("dependency artifact uses the same normalized alias");
    let Err(wrong_name_err) = TxBuilder::from_bundle(&wrong_name_bundle) else {
        panic!("a different dependency app name must be rejected");
    };
    assert!(matches!(
        wrong_name_err,
        BuilderError::DependencyArtifactMismatch { dependency, found_dependency, .. }
            if dependency == "KCC20_Asset" && found_dependency == "KCC20Asset"
    ));

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
    let mut bad_interface_controller = controller_artifact.clone();
    bad_interface_controller
        .dependencies
        .iter_mut()
        .find(|dependency| dependency.app == "KCC20Asset")
        .expect("controller records its asset dependency")
        .artifact_id = bad_interface_asset.id.clone();
    bad_interface_controller.id = bad_interface_controller.computed_id_hex().expect("controller with replaced dependency id computes");
    let bad_interface_bundle = ArtifactBundle::new(&bad_interface_controller)
        .expect("modified controller artifact remains valid")
        .with_app("kcc20_asset", &bad_interface_asset)
        .expect("dependency artifact attaches before linked interfaces are checked");
    let Err(mismatch_err) = TxBuilder::from_bundle(&bad_interface_bundle) else {
        panic!("interface fingerprint mismatch must reject the builder");
    };
    assert!(
        matches!(&mismatch_err, BuilderError::InterfaceMismatch { app, actor, .. } if app == "kcc20_asset" && actor == "MinterProxy"),
        "unexpected error: {mismatch_err}"
    );
}

#[test]
fn observed_self_merge_actor_composes_with_its_defining_app() {
    let fixture = "tests/fixtures/runtime/context_observed_self_merge";
    for controller in ["controller.ag", "controller_app.ag"] {
        let out_dir = std::env::temp_dir().join(format!(
            "argent-observed-self-merge-bundle-{}-{}",
            std::process::id(),
            ARTIFACT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let compiled = crate::build_file_app_bundle(format!("{fixture}/{controller}"), "CtrlApp", &out_dir)
            .expect("controller and asset apps compile as one dependency bundle");
        let controller_artifact = compiled.primary();
        let asset_artifact = compiled.app("AssetApp").expect("compiled bundle contains AssetApp");
        assert!(out_dir.join("apps/AssetApp/artifact.json").is_file(), "dependency artifact is emitted in the bundle");
        assert!(controller_artifact.sil_abi.contract("Asset").is_none(), "controller must not recompile the imported actor");
        assert_eq!(
            controller_artifact.argent.interfaces.imports[0].fingerprint_hex,
            asset_artifact.argent.interfaces.exports[0].fingerprint_hex
        );
        let ctrl_template = controller_artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == "Ctrl")
            .expect("controller template exists");
        assert!(
            ctrl_template.actor_type_handle.context_fields.is_empty(),
            "linked templates are code constants, not actor state context"
        );
        let asset_template = asset_artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == "Asset")
            .expect("dependency template exists")
            .actor_type_handle
            .template
            .hash;
        let ctrl_contract = controller_artifact.sil_abi.contract("Ctrl").expect("controller contract exists");
        assert_eq!(
            byte_occurrences(&ctrl_contract.compiled.bytecode, &asset_template),
            1,
            "controller pushes the linked Asset template once"
        );
        let observed = &controller_artifact.argent.actors[0].entries[0].observes[0].inputs[0];
        assert!(matches!(
            &observed.target,
            ObservedTargetArtifact::StaticActor { app, actor } if app == "AssetApp" && actor == "Asset"
        ));
        let bundle = compiled.runtime_bundle().expect("compiled artifacts form a runtime bundle");
        let builder = TxBuilder::from_bundle(&bundle).expect("builder accepts the compiled artifact bundle");
        let controller_sil = fs::read_to_string(out_dir.join("sil/Ctrl.sil")).expect("generated controller Sil exists");
        let expected_controller_sil = match controller {
            "controller.ag" => include_str!("../../tests/fixtures/runtime/context_observed_self_merge/CtrlActorImport.sil"),
            "controller_app.ag" => include_str!("../../tests/fixtures/runtime/context_observed_self_merge/CtrlAppImport.sil"),
            _ => unreachable!("the test lists every controller fixture"),
        };
        assert_eq!(controller_sil, expected_controller_sil);
        let asset_sil = fs::read_to_string(out_dir.join("apps/AssetApp/sil/Asset.sil")).expect("generated dependency Sil exists");
        assert_eq!(asset_sil, include_str!("../../tests/fixtures/runtime/context_observed_self_merge/Asset.sil"));

        let signer = keypair_from_byte(0x41);
        let signer_pk = signer.x_only_public_key().0.serialize().to_vec();
        let next_owner = vec![0x42; 32];
        let controller_covenant_id = Hash::from_bytes([0x31; 32]);
        let asset_covenant_id = Hash::from_bytes([0x32; 32]);
        let controller_initial = state! { n: 0 };
        let controller_next = state! { n: 7 };
        let asset_initial = state! { owner: signer_pk.clone(), amount: 7 };
        let asset_next = state! { owner: next_owner.clone(), amount: 7 };
        let controller_utxo = builder
            .covenant_utxo("Ctrl", controller_initial.clone(), 2_000, 0, false, Some(controller_covenant_id))
            .expect("controller UTXO builds with the imported template context");
        let asset_utxo = builder
            .covenant_utxo("asset_app::Asset", asset_initial.clone(), 1_000, 0, false, Some(asset_covenant_id))
            .expect("foreign asset UTXO builds from its defining artifact");
        let context = TxContext::new()
            .actor_input(
                "Ctrl",
                controller_initial,
                EntryCall::new("act").args(args![asset_covenant_id, next_owner.clone()]),
                TransactionOutpoint::new(TransactionId::from_bytes([0x33; 32]), 0),
                controller_utxo,
                0,
            )
            .actor_input(
                "asset_app::Asset",
                asset_initial,
                EntryCall::new("transfer").args_with(|tx, input_idx| {
                    args![next_owner.clone(), sign_mutable_input(tx, input_idx, &signer), signer_pk.clone()]
                }),
                TransactionOutpoint::new(TransactionId::from_bytes([0x34; 32]), 0),
                asset_utxo,
                0,
            )
            .actor_output("Ctrl", controller_next, CovenantBinding::new(0, controller_covenant_id), 2_000)
            .actor_output("asset_app::Asset", asset_next, CovenantBinding::new(1, asset_covenant_id), 1_000);
        let transaction = builder.build(&context).expect("the exact cross-app self-transition executes");
        assert_eq!(transaction.inputs.len(), 2);
        assert_eq!(transaction.outputs.len(), 2);
        fs::remove_dir_all(out_dir).expect("temporary bundle build is removed");
    }
}

#[test]
fn foreign_source_actors_require_an_app_import() {
    let fixture = "tests/fixtures/runtime/context_observed_self_merge";
    let direct =
        crate::build_file(format!("{fixture}/controller_direct.ag"), std::env::temp_dir().join("argent-invalid-direct-actor-import"))
            .expect_err("a direct actor import cannot add a foreign actor to the selected app");
    assert!(
        direct
            .to_string()
            .contains("direct actor import `Asset` is not part of selected app `CtrlApp`; use `import actor AssetApp::Asset"),
        "unexpected error: {direct}"
    );

    let module = crate::build_file(
        format!("{fixture}/controller_module.ag"),
        std::env::temp_dir().join("argent-invalid-module-actor-reference"),
    )
    .expect_err("a module import cannot bypass foreign app identity");
    assert!(
        module
            .to_string()
            .contains("references actor `Asset` outside selected app `CtrlApp`; foreign actors must be imported through their app"),
        "unexpected error: {module}"
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
    let agent_type = agent_artifact.sil_abi.contract("Agent").expect("Agent ABI exists").compiled.template_hash.to_vec();

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
        .actor_input("Cell", cell_initial.clone(), "advance", cell_outpoint, cell_utxo.clone(), 0)
        .actor_input(
            "open_agent::Agent",
            agent_initial.clone(),
            EntryCall::new("step").args(args![agent_next.clone()]),
            agent_outpoint,
            agent_utxo.clone(),
            0,
        )
        .actor_output("Cell", cell_next.clone(), CovenantBinding::new(0, controller_covenant_id), cell_value)
        .actor_output("open_agent::Agent", agent_next.clone(), CovenantBinding::new(1, agent_covenant_id), agent_value);
    let transaction = builder.build(&context).expect("context resolves and executes the open observed actor");
    assert_eq!(transaction.inputs.len(), 2);
    assert_eq!(transaction.outputs.len(), 2);
    assert_eq!(transaction.outputs[0].covenant.unwrap().authorizing_input, 0);
    assert_eq!(transaction.outputs[1].covenant.unwrap().authorizing_input, 1);
    assert!(transaction.inputs.iter().all(|input| input.compute_commit.compute_budget().is_some()));

    let missing_observed = TxContext::new()
        .actor_input("Cell", cell_initial.clone(), "advance", cell_outpoint, cell_utxo, 0)
        .actor_output("Cell", cell_next.clone(), CovenantBinding::new(0, controller_covenant_id), cell_value);
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
    let bad_layout_err = ArtifactBundle::new(&core_artifact)
        .expect("core artifact is valid")
        .with_app("open_agent", &bad_layout_agent_artifact)
        .expect_err("the imported artifact's own state-layout mismatch is rejected");
    let (app, source) = artifact_verification(&bad_layout_err);
    assert_eq!(app, "open_agent");
    assert!(matches!(source, ArtifactVerificationError::TemplatePlan(TemplatePlanError::ActorTypeHandleMismatch { .. })));

    let expanded_agent_artifact = open_icc_expanded_agent_artifact();
    let expanded_bundle = ArtifactBundle::new(&core_artifact)
        .expect("core artifact is valid")
        .with_app("open_agent", &expanded_agent_artifact)
        .expect("expanded agent artifact attaches under the same app alias");
    let expanded_builder = TxBuilder::from_bundle(&expanded_bundle).expect("builder accepts expanded agent bundle");
    let expanded_agent_type =
        expanded_builder.actor_type_handle("open_agent::Forager", "AgentCapsule").expect("Forager exposes its AgentCapsule handle");
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
        .actor_input("Cell", expanded_cell_initial, "advance", cell_outpoint, expanded_cell_utxo, 0)
        .actor_input("open_agent::Forager", expanded_agent_initial.clone(), "step", agent_outpoint, expanded_agent_utxo.clone(), 0)
        .actor_output("Cell", expanded_cell_next, CovenantBinding::new(0, controller_covenant_id), cell_value)
        .actor_output("open_agent::Forager", expanded_agent_next, CovenantBinding::new(1, agent_covenant_id), agent_value);
    expanded_builder.build(&expanded_context).expect("open ICC accepts an actor state that expands the observed capsule");

    let mut flattened_forager_state = expanded_open_agent_state(controller_covenant_id, 2, 5);
    flattened_forager_state.remove("strategy");
    flattened_forager_state.insert("hunger".to_string(), ArtifactValue::Int(2));
    flattened_forager_state.insert("mood".to_string(), ArtifactValue::Int(1));
    flattened_forager_state.insert("target_agent_id".to_string(), ArtifactValue::Bytes(vec![0x55; 32]));
    let flattened_context =
        TxContext::new().actor_input("open_agent::Forager", flattened_forager_state, "step", agent_outpoint, expanded_agent_utxo, 0);
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
        .actor_input("Cell", forager_cell_initial.clone(), "advance", cell_outpoint, forager_cell_utxo, 0)
        .actor_input(
            "open_agent::Forager",
            forager_initial,
            EntryCall::new("step").args(args![0, 0, 4]),
            forager_outpoint,
            forager_utxo,
            0,
        )
        .actor_output("Cell", forager_cell_initial, CovenantBinding::new(0, controller_covenant_id), cell_value)
        .actor_output("open_agent::Forager", forager_next, CovenantBinding::new(1, agent_covenant_id), agent_value);
    builder.build(&forager_context).expect("Forager route executes with expanded-memory repacking");

    let wrong_agent_next = open_agent_state(controller_covenant_id, vec![0x77; 32], 5);
    let wrong_cell_utxo = builder
        .covenant_utxo("Cell", cell_initial.clone(), cell_value, 0, false, Some(controller_covenant_id))
        .expect("wrong-output Cell UTXO builds");
    let wrong_agent_utxo = builder
        .covenant_utxo("open_agent::Agent", agent_initial.clone(), agent_value, 0, false, Some(agent_covenant_id))
        .expect("wrong-output Agent UTXO builds");
    let wrong_context = TxContext::new()
        .actor_input("Cell", cell_initial, "advance", cell_outpoint, wrong_cell_utxo, 0)
        .actor_input(
            "open_agent::Agent",
            agent_initial,
            EntryCall::new("step").args(args![wrong_agent_next.clone()]),
            agent_outpoint,
            wrong_agent_utxo,
            0,
        )
        .actor_output("Cell", cell_next, CovenantBinding::new(0, controller_covenant_id), cell_value)
        .actor_output("open_agent::Agent", wrong_agent_next, CovenantBinding::new(1, agent_covenant_id), agent_value);
    assert!(builder.build(&wrong_context).is_err(), "core physics rejects an agent output that does not spend one energy");
}

#[test]
fn anonymous_open_binding_fills_template_hash_and_executes() {
    let core_artifact = example_artifact("tests/fixtures/emit/open_observed_actor_binding/app.ag", "anonymous-open-binding-core");
    let agent_artifact = inline_artifact(
        "anonymous-open-binding-agent",
        r#"
            state AgentCapsule {
                cov_id controller_id;
                byte[32] caps_digest;
                int energy;
            }

            actor Agent owns AgentCapsule {
                entry step(AgentCapsule next_state) emits next: Agent {
                    unrestricted(next.value);
                    require(controller_id.co_spent());
                    become next <- Agent(next_state);
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

    let agent_template = sil_template(agent_artifact.sil_abi.contract("Agent").expect("Agent contract exists"));
    let agent_template_hash = agent_template.hash.to_vec();
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
    let cell_utxo =
        builder.covenant_utxo("Cell", cell_state.clone(), 2_000, 0, false, Some(controller_covenant_id)).expect("Cell UTXO builds");
    let context = TxContext::new()
        .actor_input(
            "Cell",
            cell_state,
            "advance",
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x55; 32]), index: 0 },
            cell_utxo,
            0,
        )
        .actor_input(
            "agent_app::Agent",
            agent_state,
            EntryCall::new("step").args(args![next_agent_state.clone()]),
            TransactionOutpoint { transaction_id: TransactionId::from_bytes([0x66; 32]), index: 0 },
            agent_utxo,
            0,
        )
        .actor_output("Cell", next_cell_state, CovenantBinding::new(0, controller_covenant_id), 2_000)
        .actor_output("agent_app::Agent", next_agent_state, CovenantBinding::new(1, agent_covenant_id), 1_000);
    let transaction = builder.build(&context).expect("anonymous open binding resolves and executes");
    let sigscript = &transaction.inputs[0].signature_script;
    let contract = core_artifact.sil_abi.contract("Cell").expect("Cell contract exists");
    let entry = contract.entry("advance").expect("advance entry exists");
    let expected_args = vec![
        ArtifactValue::Int(agent_template.prefix.len() as i64),
        ArtifactValue::Int(agent_template.suffix.len() as i64),
        ArtifactValue::Bytes(agent_template_hash),
    ];
    let expected_entry = encode_entry_sig_script(&core_artifact.sil_abi, "Cell", contract, "advance", entry, &expected_args)
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

                cov_id controller_id;
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
                    agent: Forager,
                } {
                    unrestricted(agent.value);
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
    crate::build_file(&input, &out_dir).expect("example artifact builds")
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
    argent_runtime::stdlib::core::invocation_uid(outpoint, b"StonesPlayer").expect("Stones player domain is valid").as_bytes().to_vec()
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
