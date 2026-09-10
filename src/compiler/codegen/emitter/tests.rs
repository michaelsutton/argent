use std::{
    fs,
    path::{Path, PathBuf},
};

use kaspa_txscript::opcodes::codes::OpPushData1;

use super::*;
use crate::compiler::model::{CompilerRouteTransition, RouteRootLeaf};
use crate::routing::{CommitmentNode, RouteGraph, SelectorRequirement};

#[test]
fn rejects_route_outside_named_output_union() {
    let mut program = test_program();
    set_entry_body(&mut program.modules[0].actors[0].entries[0], "become next <- Game(next_game);");

    let err = Model::from_program(&program).expect_err("route must be rejected");
    assert!(err.to_string().contains("routes output `next` to `Game`"), "unexpected error: {err}");
}

#[test]
fn accepts_route_inside_named_output_union() {
    let mut program = test_program();
    program.modules[0].actors[0].entries[0].emits = EmitSpec::Outputs(vec![EmitOutput {
        name: "next".to_string(),
        actors: vec!["Player".to_string(), "Game".to_string()],
        cardinality: Cardinality::One,
        auth_index: 0,
    }]);
    set_entry_body(&mut program.modules[0].actors[0].entries[0], "become next <- Game(next_game);");

    Model::from_program(&program).expect("route should be accepted");
}

#[test]
fn output_cardinality_requires_matching_become_arity() {
    let ranged_scalar = parse_and_validate(
        r#"
            state BatchState {}
            state AccountState {}

            actor Batch owns BatchState {
                entry distribute(AccountState[] states)
                emits next: Account[1..=3] {
                    unrestricted(next[0].value);
                    become next <- Account(states);
                }
            }

            actor Account owns AccountState {}
            app Test { actor Batch; actor Account; }
        "#,
    )
    .expect_err("a range output must reject scalar become syntax");
    assert!(ranged_scalar.to_string().contains("must use bulk become syntax"), "unexpected error: {ranged_scalar}");

    let singleton_bulk = parse_and_validate(
        r#"
            state BatchState {}
            state AccountState {}

            actor Batch owns BatchState {
                entry distribute(AccountState state)
                emits next: Account {
                    unrestricted(next.value);
                    become next <- Account[](state);
                }
            }

            actor Account owns AccountState {}
            app Test { actor Batch; actor Account; }
        "#,
    )
    .expect_err("a singleton output must reject bulk become syntax");
    assert!(singleton_bulk.to_string().contains("must use scalar become syntax"), "unexpected error: {singleton_bulk}");
}

#[test]
fn singleton_observed_output_rejects_bulk_become_syntax() {
    let err = emit_inline_error(
        r#"
            state ObserverState {
                int nonce;
            }
            state AssetState {
                int amount;
            }

            actor Observer owns ObserverState {
                entry follow(cov_id remote_id)
                observes remote by remote_id {
                    outputs {
                        asset: Asset,
                    }
                }
                emits none {
                    require remote.outputs become {
                        asset <- Asset[](AssetState {
                            amount: 1,
                        }),
                    };
                }
            }

            actor Asset owns AssetState {}

            app Test {
                actor Observer;
                actor Asset;
            }
        "#,
    );

    assert!(err.to_string().contains("must use scalar become syntax"), "unexpected error: {err}");
}

#[test]
fn singleton_spawned_output_rejects_bulk_become_syntax() {
    let err = emit_inline_error(
        r#"
            state LauncherState {
                int launches;
            }
            state ChildState {
                int amount;
            }

            actor Launcher owns LauncherState {
                entry launch()
                spawns children by children_id {
                    outputs {
                        child: Child,
                    }
                }
                emits none {
                    unrestricted(children.outputs.child.value);
                    require children.outputs become {
                        child <- Child[](ChildState {
                            amount: 1,
                        }),
                    };
                }
            }

            actor Child owns ChildState {}

            app Test {
                actor Launcher;
                actor Child;
            }
        "#,
    );

    assert!(err.to_string().contains("must use scalar become syntax"), "unexpected error: {err}");
}

#[test]
fn delegate_consume_ranges_are_rejected_at_the_sil_codegen_boundary() {
    let err = emit_inline_error(
        r#"
            const int MAX_PEERS = 2;

            state CounterState {}

            actor Counter owns CounterState {
                delegate combine()
                consumes {
                    leader: Counter,
                    peers: Counter[0..=MAX_PEERS],
                }
                {}
            }

            app Test {
                actor Counter;
            }
            "#,
    );

    assert!(err.to_string().contains("cannot use range `peers` in `consumes` yet"), "unexpected error: {err}");
}

#[test]
fn observed_ranges_are_rejected_at_the_sil_codegen_boundary() {
    let err = emit_inline_error(
        r#"
            const int MAX_ACCOUNTS = 2;

            state BatchState {
                cov_id source_id;
            }
            state AccountState {}

            actor Batch owns BatchState {
                entry inspect()
                observes source by self.source_id {
                    inputs {
                        accounts: Account[0..=MAX_ACCOUNTS],
                    }
                    outputs {}
                }
                emits none {}
            }

            actor Account owns AccountState {}
            app Test { actor Batch; actor Account; }
        "#,
    );

    assert!(err.to_string().contains("range code generation is not implemented yet"), "unexpected error: {err}");
}

#[test]
fn spawn_ranges_are_rejected_at_the_sil_codegen_boundary() {
    let err = emit_inline_error(
        r#"
            const int MAX_ACCOUNTS = 2;

            state BatchState {}
            state AccountState {}

            actor Batch owns BatchState {
                entry launch(AccountState[] states)
                spawns children by child_id {
                    outputs {
                        accounts: Account[1..=MAX_ACCOUNTS],
                    }
                }
                emits none {
                    require children.outputs become {
                        accounts <- Account(states),
                    };
                }
            }

            actor Account owns AccountState {}
            app Test { actor Batch; actor Account; }
        "#,
    );

    assert!(err.to_string().contains("range code generation is not implemented yet"), "unexpected error: {err}");
}

#[test]
fn artifacts_record_resolved_cardinality_for_every_interaction_kind() {
    let path = PathBuf::from("artifact-cardinality.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            const int MAX_ACCOUNTS = 3;

            state BatchState {
                cov_id source_id;
            }

            state AccountState {
                int balance;
            }

            actor Batch owns BatchState {
                entry rebalance()
                consumes {
                    accounts: Account[1..=MAX_ACCOUNTS],
                }
                observes existing by self.source_id {
                    inputs {
                        previous: Account[0..=MAX_ACCOUNTS],
                    }
                    outputs {
                        observed: Account[1..=MAX_ACCOUNTS],
                    }
                }
                spawns created by created_id {
                    outputs {
                        children: Account[1..=2],
                    }
                }
                emits next: Account[1..=MAX_ACCOUNTS] {
                    AccountState next_state = {
                        balance: 1,
                    };
                    AccountState[] next_states;
                    next_states = next_states.append(next_state);

                    unrestricted(created.outputs.children.value);
                    require created.outputs become {
                        children <- Account(next_state),
                    };

                    require existing.outputs become {
                        observed <- Account(next_state),
                    };

                    unrestricted(next[0].value);
                    become next <- Account[](next_states);
                }
            }

            actor Account owns AccountState {}

            app Test {
                actor Batch;
                actor Account;
            }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model builds");
    let actor = model.actor("Batch").expect("actor exists");
    let entry = entry_artifact(actor, &actor.entries[0], &model).expect("entry artifact builds");

    assert_eq!(entry.consumes[0].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 3 });
    let EmitArtifact::Outputs { outputs } = &entry.emits else {
        panic!("entry emits outputs");
    };
    assert_eq!(outputs[0].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 3 });
    assert_eq!(entry.observes[0].inputs[0].cardinality, CardinalityArtifact::Range { minimum: 0, maximum: 3 });
    assert_eq!(entry.observes[0].outputs[0].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 3 });
    assert_eq!(entry.spawns[0].outputs[0].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 2 });
}

#[test]
fn lowers_planned_singleton_locations_to_section_indices() {
    assert_eq!(lower_singleton_interaction_index(InteractionLocation::FromStart(2), "count", 1).expect("leading location"), "3");
    assert_eq!(
        lower_singleton_interaction_index(InteractionLocation::FromEnd(2), "count", 0).expect("trailing location"),
        "count - 2"
    );
    assert_eq!(
        lower_singleton_interaction_index(InteractionLocation::FromEnd(1), "count", 1).expect("offset trailing location"),
        "count - 1"
    );
    assert!(lower_singleton_interaction_index(InteractionLocation::Range { start: 1, singleton_count: 2 }, "count", 0).is_err());
}

#[test]
fn planning_uses_declared_emit_domain_not_body_routes() {
    let path = PathBuf::from("declared-emit-domain.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state SourceState {
                int nonce;
            }

            state TargetState {
                int nonce;
            }

            actor Source owns SourceState {
                entry choose_a() emits next: A | B {
                    unrestricted(next.value);
                    TargetState next_state = {
                        nonce: nonce,
                    };
                    become next <- A(next_state);
                }
            }

            actor A owns TargetState {}
            actor B owns TargetState {}

            app DeclaredEmitDomain {
                actor Source;
                actor A;
                actor B;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };

    let model = Model::from_program(&program).expect("declared emit domain plans");
    let source = model.actor("Source").expect("Source exists");
    let entry = &source.entries[0];
    assert_eq!(
        model
            .entry_model(source, entry)
            .expect("entry model exists")
            .expanded_routes()
            .iter()
            .map(resolved_constructed_actor)
            .collect::<Vec<_>>(),
        ["A"]
    );
    assert!(model.route_transitions.contains_key(&("Source".to_string(), "A".to_string())));
    assert!(model.route_transitions.contains_key(&("Source".to_string(), "B".to_string())));
    assert_eq!(model.route_leaves_by_actor["Source"], [RouteRootLeaf::Actor("A".to_string()), RouteRootLeaf::Actor("B".to_string())]);
}

#[test]
fn rejects_user_state_named_state() {
    let err = parse_and_validate(
        r#"
            state State {}

            actor Foo owns State {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Foo;
            }
            "#,
    )
    .expect_err("source `State` must be reserved");

    assert!(err.to_string().contains("reserved for generated Silverscript state"), "unexpected error: {err}");
}

#[test]
fn rejects_missing_named_output_coverage() {
    let mut program = test_program();
    program.modules[0].actors[0].entries[0].emits = EmitSpec::Outputs(vec![
        EmitOutput { name: "a".to_string(), actors: vec!["Player".to_string()], cardinality: Cardinality::One, auth_index: 0 },
        EmitOutput { name: "b".to_string(), actors: vec!["Player".to_string()], cardinality: Cardinality::One, auth_index: 1 },
    ]);
    set_entry_body(&mut program.modules[0].actors[0].entries[0], "become a <- Player(next_a);");

    let err = Model::from_program(&program).expect_err("missing output coverage must be rejected");
    assert!(err.to_string().contains("does not validate output `b`"), "unexpected error: {err}");
}

#[test]
fn rejects_source_with_missing_named_output_coverage() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits {
                    a: Foo,
                    b: Foo,
                } {
                    unrestricted(a.value);
                    unrestricted(b.value);
                    become a <- Foo(next_a);
                }
            }

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };

    let err = Model::from_program(&program).expect_err("missing output coverage must be rejected");
    assert!(err.to_string().contains("does not validate output `b`"), "unexpected error: {err}");
}

#[test]
fn rejects_explicit_auth_output_index_syntax() {
    let err = parse_and_validate(
        r#"
            state FooState {
                int amount;
            }

            actor Foo owns FooState {
                entry bump() emits {
                    next: Foo at auth[0],
                } {
                    unrestricted(next.value);
                    State next_state = {
                        amount: amount + 1,
                    };

                    become next <- Foo(next_state);
                }
            }

            app Test {
                actor Foo;
            }
            "#,
    )
    .expect_err("explicit auth output indexes must not be source syntax");

    assert!(err.to_string().contains("expected `,` or `}`"), "unexpected error: {err}");
}

#[test]
fn rejects_duplicate_named_output_coverage() {
    let mut program = test_program();
    set_entry_body(
        &mut program.modules[0].actors[0].entries[0],
        "become { next <- Player(next_player), next <- Player(other_player) };",
    );

    let err = Model::from_program(&program).expect_err("duplicate output coverage must be rejected");
    assert!(err.to_string().contains("validates output `next` more than once"), "unexpected error: {err}");
}

#[test]
fn rejects_delegate_become() {
    let mut program = test_program();
    program.modules[0].actors[0].entries[0].kind = EntryKind::Delegate;
    program.modules[0].actors[0].entries[0].consumes.push(ConsumeDecl {
        name: "leader".to_string(),
        actor: "Player".to_string(),
        cardinality: Cardinality::One,
    });
    program.modules[0].actors[0].entries[0].emits = EmitSpec::None;
    set_entry_body(&mut program.modules[0].actors[0].entries[0], "become next <- Player(next_player);");

    let err = Model::from_program(&program).expect_err("delegate become must be rejected");
    assert!(err.to_string().contains("cannot use `become`"), "unexpected error: {err}");
}

#[test]
fn rejects_delegate_without_a_declared_leader() {
    let err = parse_and_validate(
        r#"
            state WorkerState {}

            actor Worker owns WorkerState {
                delegate assist() {
                    require(1 == 1);
                }
            }

            app Test {
                actor Worker;
            }
            "#,
    )
    .expect_err("delegates must name a leader");

    assert!(err.to_string().contains("must declare its leader as the first `consumes` actor"), "unexpected error: {err}");
}

#[test]
fn leader_actors_close_all_leader_input_groups() {
    let source = r#"
            state LeaderState {
                int amount;
            }

            state WorkerState {
                int amount;
            }

            state UnrelatedState {
                int amount;
            }

            actor Leader owns LeaderState {
                entry standalone() emits next: Leader {
                    unrestricted(next.value);
                    become next <- self;
                }

                entry coordinated() consumes {
                    worker: Worker,
                } emits next: Leader {
                    unrestricted(next.value);
                    require(worker.value >= 0);
                    become next <- self;
                }
            }

            actor Worker owns WorkerState {
                delegate assist() consumes {
                    leader: Leader,
                } {
                    require(leader.value >= 0);
                }
            }

            actor Unrelated owns UnrelatedState {
                entry standalone() emits next: Unrelated {
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            app Test {
                actor Leader;
                actor Worker;
                actor Unrelated;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");

    let leader_sil = emit_actor(model.actor("Leader").expect("Leader exists"), &model).expect("Leader emits");
    assert!(leader_sil.contains("// :: leader entry (1:N)\n    entry standalone("), "{leader_sil}");
    assert!(leader_sil.contains("// :: leader entry (M:N)\n    entry coordinated("), "{leader_sil}");
    assert!(leader_sil.contains("require(OpCovInputCount(gen__cov_id) == 1);"), "{leader_sil}");
    assert!(leader_sil.contains("require(OpCovInputCount(gen__cov_id) == 2);"), "{leader_sil}");

    let worker_sil = emit_actor(model.actor("Worker").expect("Worker exists"), &model).expect("Worker emits");
    assert!(worker_sil.contains("// :: delegate entry\n    entry assist("), "{worker_sil}");

    let unrelated_sil = emit_actor(model.actor("Unrelated").expect("Unrelated exists"), &model).expect("Unrelated emits");
    assert!(!unrelated_sil.contains("OpCovInputCount"), "{unrelated_sil}");

    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");
    let leader = artifact.argent.actors.iter().find(|actor| actor.name == "Leader").expect("Leader artifact exists");
    assert_eq!(leader.leader_for, vec![EntryRefArtifact { actor: "Worker".to_string(), entry: "assist".to_string() }]);
    let unrelated = artifact.argent.actors.iter().find(|actor| actor.name == "Unrelated").expect("Unrelated artifact exists");
    assert!(unrelated.leader_for.is_empty());
}

#[test]
fn rejects_duplicate_state_declarations() {
    let mut program = test_program();
    let mut duplicate = empty_module("second.ag");
    duplicate.states.push(StateDecl { name: "PlayerState".to_string(), fields: Vec::new(), expansion: None });
    program.modules.push(duplicate);

    let err = Model::from_program(&program).expect_err("duplicate state declaration must be rejected");
    assert_duplicate_top_level_error(&err, "state", "PlayerState");
}

#[test]
fn rejects_duplicate_actor_declarations() {
    let mut program = test_program();
    let mut duplicate = empty_module("second.ag");
    duplicate.actors.push(ActorDecl {
        name: "Player".to_string(),
        state: "PlayerState".to_string(),
        functions: Vec::new(),
        entries: Vec::new(),
    });
    program.modules.push(duplicate);

    let err = Model::from_program(&program).expect_err("duplicate actor declaration must be rejected");
    assert_duplicate_top_level_error(&err, "actor", "Player");
}

#[test]
fn rejects_duplicate_const_declarations() {
    let mut program = test_program();
    program.modules[0].consts.push(ConstDecl { ty: TypeRef::new("int"), name: "Limit".to_string(), value: "1".to_string() });
    let mut duplicate = empty_module("second.ag");
    duplicate.consts.push(ConstDecl { ty: TypeRef::new("int"), name: "Limit".to_string(), value: "2".to_string() });
    program.modules.push(duplicate);

    let err = Model::from_program(&program).expect_err("duplicate const declaration must be rejected");
    assert_duplicate_top_level_error(&err, "const", "Limit");
}

#[test]
fn rejects_duplicate_function_declarations() {
    let mut program = test_program();
    program.modules[0].functions.push(FunctionDecl {
        name: "helper".to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "1".to_string(),
    });
    let mut duplicate = empty_module("second.ag");
    duplicate.functions.push(FunctionDecl {
        name: "helper".to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "2".to_string(),
    });
    program.modules.push(duplicate);

    let err = Model::from_program(&program).expect_err("duplicate function declaration must be rejected");
    assert_duplicate_top_level_error(&err, "fn", "helper");
}

#[test]
fn rejects_function_named_unrestricted() {
    let mut program = test_program();
    program.modules[0].functions.push(FunctionDecl {
        name: word::UNRESTRICTED.to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "0".to_string(),
    });

    let err = Model::from_program(&program).expect_err("the output-value declaration must not be shadowed");
    assert!(
        err.to_string().contains("function identifier `unrestricted` is reserved for output-value declarations"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_global_and_actor_functions_named_state() {
    for (label, declaration) in [
        (
            "global",
            r#"
                fn state(int value) -> int { return value; }
                actor Wallet owns WalletState {}
            "#,
        ),
        (
            "actor",
            r#"
                actor Wallet owns WalletState {
                    fn state(int value) -> int { return value; }
                }
            "#,
        ),
    ] {
        let source = format!(
            r#"
                state WalletState {{ int balance; }}
                {declaration}
                app Test {{ actor Wallet; }}
            "#
        );
        let err = parse_and_validate(&source).expect_err("state reconstruction builtin must not be shadowed");
        assert!(
            err.to_string().contains("function identifier `state` is reserved for authored input-state reconstruction"),
            "unexpected {label} error: {err}"
        );
    }
}

#[test]
fn rejects_global_and_actor_functions_named_digest() {
    for (label, declaration) in [
        (
            "global",
            r#"
                fn digest(int value) -> int { return value; }
                actor Wallet owns WalletState {}
            "#,
        ),
        (
            "actor",
            r#"
                actor Wallet owns WalletState {
                    fn digest(int value) -> int { return value; }
                }
            "#,
        ),
    ] {
        let source = format!(
            r#"
                state WalletState {{ int balance; }}
                {declaration}
                app Test {{ actor Wallet; }}
            "#
        );
        let err = parse_and_validate(&source).expect_err("state digest builtin must not be shadowed");
        assert!(
            err.to_string().contains("function identifier `digest` is reserved for authored state digests"),
            "unexpected {label} error: {err}"
        );
    }
}

#[test]
fn rejects_global_and_actor_functions_with_the_same_name() {
    let mut program = test_program();
    program.modules[0].actors[0].entries.clear();
    program.modules[0].functions.push(FunctionDecl {
        name: "helper".to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "return 1;".to_string(),
    });
    program.modules[0].actors[0].functions.push(FunctionDecl {
        name: "helper".to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "return 2;".to_string(),
    });

    let err = Model::from_program(&program).expect_err("global and actor functions share the generated contract namespace");

    assert_eq!(err.message, "actor `Player` function `helper` conflicts with a global function of the same name");
}

#[test]
fn rejects_global_calls_to_actor_functions() {
    let mut program = test_program();
    program.modules[0].actors[0].entries.clear();
    program.modules[0].functions.push(FunctionDecl {
        name: "global_helper".to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "return actor_helper();".to_string(),
    });
    program.modules[0].actors[1].functions.push(FunctionDecl {
        name: "actor_helper".to_string(),
        params: Vec::new(),
        return_ty: Some(TypeRef::new("int")),
        body: "return 2;".to_string(),
    });
    let model = Model::from_program(&program).expect("function declarations form distinct namespaces");

    let err = emit_actor(model.actor("Player").expect("Player exists"), &model)
        .expect_err("global functions must not depend on actor functions");

    assert_eq!(err.message, "global function `global_helper` cannot call actor function `actor_helper`");
}

#[test]
fn allows_the_same_function_name_on_different_actors() {
    let mut program = test_program();
    for actor in &mut program.modules[0].actors {
        actor.entries.clear();
        actor.functions.push(FunctionDecl {
            name: "helper".to_string(),
            params: Vec::new(),
            return_ty: Some(TypeRef::new("int")),
            body: "return 1;".to_string(),
        });
    }

    Model::from_program(&program).expect("actor-local function names may repeat across contracts");
}

#[test]
fn emits_actor_functions_only_in_their_owning_contract() {
    let path = PathBuf::from("actor-functions.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            const int BIAS = 1;

            state CounterState {
                int cycles;
            }

            state OtherState {
                int amount;
            }

            fn add_bias(int value) -> int {
                return value + BIAS;
            }

            actor Counter owns CounterState {
                fn current() -> int {
                    return cycles;
                }

                fn adjusted(int delta) -> int {
                    return add_bias(current() + delta);
                }

                fn ensure_nonnegative() {
                    require(current() >= 0);
                }

                entry check() emits none {
                    ensure_nonnegative();
                    require(adjusted(1) == cycles + 2);
                }
            }

            actor Other owns OtherState {
                fn adjusted(int delta) -> int {
                    return amount - delta;
                }

                entry check() emits none {
                    require(adjusted(1) == amount - 1);
                }
            }

            app FunctionsApp {
                actor Counter;
                actor Other;
            }
            "#
        .to_string(),
    )
    .expect("actor-function source parses");
    let program = Program { root: path, modules: vec![module] };
    let out_dir = std::env::temp_dir().join(format!("argent-actor-functions-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    emit_build(&program, &out_dir).expect("actor functions compile in their owning contracts");
    let counter = fs::read_to_string(out_dir.join("sil/Counter.sil")).expect("generated Counter Sil exists");
    let other = fs::read_to_string(out_dir.join("sil/Other.sil")).expect("generated Other Sil exists");

    assert!(counter.contains("// :: actor functions"), "{counter}");
    assert!(counter.contains("function current() : int"), "{counter}");
    assert!(counter.contains("return cycles;"), "{counter}");
    assert!(counter.contains("function adjusted(int delta) : int"), "{counter}");
    assert!(counter.contains("return add_bias(current() + delta);"), "{counter}");
    assert!(counter.contains("function ensure_nonnegative()"), "{counter}");
    assert!(!other.contains("function current()"), "{other}");
    assert!(other.contains("return amount - delta;"), "{other}");

    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn global_function_variables_do_not_collide_with_actor_fields() {
    let program = global_function_program(
        r#"
            fn increment(int cycles) -> int {
                int result = cycles + 1;
                return result;
            }
        "#,
        "increment(cycles) > cycles",
    );
    let out_dir = std::env::temp_dir().join(format!("argent-global-function-scope-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    emit_build(&program, &out_dir).expect("global function with actor-field name collisions builds");
    let sil = fs::read_to_string(out_dir.join("sil/Counter.sil")).expect("generated Counter Sil exists");
    assert!(sil.contains("function increment(int gen__glob_cycles) : int"), "{sil}");
    assert!(sil.contains("int gen__glob_result = gen__glob_cycles + 1;"), "{sil}");
    assert!(sil.contains("return gen__glob_result;"), "{sil}");
    assert!(sil.contains("require(increment(cycles) > cycles);"), "{sil}");

    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn global_function_bare_names_do_not_capture_actor_fields() {
    let program = global_function_program(
        r#"
            fn read_cycles() -> int {
                return cycles;
            }
        "#,
        "read_cycles() >= 0",
    );
    let model = Model::from_program(&program).expect("program models");
    let counter = model.actor("Counter").expect("Counter exists");
    let err = emit_actor(counter, &model).expect_err("undeclared global-function name must not capture an actor field");
    assert!(
        err.to_string().contains("global function `read_cycles` cannot access unresolved identifier `cycles`"),
        "unexpected error: {err}"
    );
}

#[test]
fn global_function_assignments_do_not_capture_actor_fields() {
    let program = global_function_program(
        r#"
            fn write_cycles() {
                cycles = 1;
            }
        "#,
        "true",
    );
    let model = Model::from_program(&program).expect("program models");
    let counter = model.actor("Counter").expect("Counter exists");
    let err = emit_actor(counter, &model).expect_err("global-function assignment must not capture an actor field");
    assert!(
        err.to_string().contains("global function `write_cycles` assigns unresolved identifier `cycles`"),
        "unexpected error: {err}"
    );
}

#[test]
fn global_function_contextual_names_and_literals_are_lowered_by_sil_syntax() {
    let program = global_function_program(
        r#"
            fn echo(int seconds) -> int {
                byte[2] marker = byte[_](0xaabb);
                int grouped = 1_000;
                require(marker == byte[_](0xaabb));
                return seconds + grouped - 1_000;
            }
        "#,
        "echo(seconds) >= seconds",
    );
    let out_dir = std::env::temp_dir().join(format!("argent-global-function-syntax-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    emit_build(&program, &out_dir).expect("contextual names and complete Sil literals build");
    let sil = fs::read_to_string(out_dir.join("sil/Counter.sil")).expect("generated Counter Sil exists");
    assert!(sil.contains("function echo(int gen__glob_seconds) : int"), "{sil}");
    assert!(sil.contains("byte[2] gen__glob_marker = byte[_](0xaabb);"), "{sil}");
    assert!(sil.contains("int gen__glob_grouped = 1_000;"), "{sil}");
    assert!(sil.contains("return gen__glob_seconds + gen__glob_grouped - 1_000;"), "{sil}");

    let _ = fs::remove_dir_all(out_dir);
}

fn global_function_program(function: &str, requirement: &str) -> Program {
    let path = PathBuf::from("global-function-scope.ag");
    let source = format!(
        r#"
            state CounterState {{
                int cycles;
                int seconds;
            }}

            {function}

            actor Counter owns CounterState {{
                entry check() emits none {{
                    require({requirement});
                }}
            }}

            app CounterApp {{
                actor Counter;
            }}
        "#
    );
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source).expect("scope test source parses");
    Program { root: path, modules: vec![module] }
}

#[test]
fn rejects_duplicate_app_declarations() {
    let mut program = test_program();
    let mut duplicate = empty_module("second.ag");
    duplicate.apps.push(AppDecl { name: "Test".to_string(), actors: vec!["Player".to_string()] });
    program.modules.push(duplicate);

    let err = Model::from_program(&program).expect_err("duplicate app declaration must be rejected");
    assert_duplicate_top_level_error(&err, "app", "Test");
}

#[test]
fn rejects_reserved_state_field_from_model() {
    let mut program = test_program();
    program.modules[0].states[0].fields.push(FieldDecl {
        ty: TypeRef::new("int"),
        name: "gen__player_template".to_string(),
        virtual_slot: false,
    });

    let err = Model::from_program(&program).expect_err("reserved state field must be rejected");
    assert!(err.to_string().contains("reserved generated namespace"), "unexpected error: {err}");
}

#[test]
fn rejects_reserved_self_members_on_owned_state_surface() {
    for member in word::RESERVED_SELF_MEMBERS {
        let source = format!(
            r#"
                state WalletState {{
                    int {member};
                }}

                actor Wallet owns WalletState {{}}

                app Test {{
                    actor Wallet;
                }}
                "#
        );
        let err = parse_and_validate(&source).expect_err("reserved self member must be rejected on an owned state");
        assert!(
            err.to_string().contains(&format!("actor `Wallet` owned state `WalletState` exposes field `{member}` as `self.{member}`")),
            "unexpected error for `{member}`: {err}"
        );
    }
}

#[test]
fn allows_reserved_self_member_names_in_nested_state_values() {
    parse_and_validate(
        r#"
            state Payload {
                int value;
                int ref;
                int state;
            }

            state WalletState {
                Payload payload;
            }

            actor Wallet owns WalletState {}

            app Test {
                actor Wallet;
            }
            "#,
    )
    .expect("reserved self member names are valid below the actor state surface");
}

#[test]
fn rejects_reserved_self_member_in_expanded_base_state() {
    let err = parse_and_validate(
        r#"
            state Capsule {
                virtual state;
            }

            state Memory {
                int counter;
            }

            state Expanded expands Capsule {
                state: Memory;
            }

            actor Worker owns Expanded {}

            app Test {
                actor Worker;
            }
            "#,
    )
    .expect_err("expanded base fields remain on the owned state surface");

    assert!(
        err.to_string().contains("actor `Worker` owned state `Expanded` exposes field `state` as `self.state`"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_reserved_entry_parameter_from_model() {
    let mut program = test_program();
    program.modules[0].actors[0].entries[0]
        .params
        .push(ParamDecl { name: "gen__next_output_idx".to_string(), ty: TypeRef::new("int") });

    let err = Model::from_program(&program).expect_err("reserved entry parameter must be rejected");
    assert!(err.to_string().contains("reserved generated namespace"), "unexpected error: {err}");
}

#[test]
fn rejects_physical_state_entry_parameters_in_aligned_and_augmented_contracts() {
    for (layout, actors, emits, body) in [
        ("aligned", "", "emits none", "require(1 == 1);"),
        (
            "augmented",
            r#"
                state PeerState { int count; }
                actor Peer owns PeerState {}
            "#,
            "emits next: Peer",
            r#"
                unrestricted(next.value);
                become next <- Peer(PeerState { count: count });
            "#,
        ),
    ] {
        for ty in ["State", "State[2]", "State[]"] {
            let source = format!(
                r#"
                    state CounterState {{ int count; }}

                    actor Counter owns CounterState {{
                        entry inspect({ty} supplied) {emits} {{
                            {body}
                        }}
                    }}

                    {actors}
                    app Test {{ actor Counter; {} }}
                "#,
                if layout == "augmented" { "actor Peer;" } else { "" }
            );
            let err = parse_and_validate(&source).expect_err("physical State must not cross an external entry boundary");
            assert!(
                err.to_string()
                    .contains(&format!("entry `Counter::inspect` parameter `supplied` uses compiler-owned physical type `{ty}`")),
                "{layout} {ty}: unexpected error: {err}"
            );
            assert!(
                err.to_string().contains("entry parameters must use an Argent-authored state type"),
                "{layout} {ty}: unexpected error: {err}"
            );
        }
    }
}

#[test]
fn rejects_self_as_an_entry_parameter() {
    let err = parse_and_validate(
        r#"
            state CounterState { int count; }

            actor Counter owns CounterState {
                entry inspect(int self) emits none {
                    require(self.count >= 0);
                }
            }

            app Test { actor Counter; }
        "#,
    )
    .expect_err("`self` must remain the current actor context");

    assert!(
        err.to_string().contains("entry `Counter::inspect` parameter identifier `self` is reserved for the current actor context"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_self_as_an_entry_body_binding() {
    let cases = [
        ("local", "int self = 7; require(self.count >= 0);"),
        ("loop", "for (self, 0, 1, 1) { require(self.count >= 0); }"),
        ("tuple", "(int self, int other) = pair(); require(self.count >= 0);"),
        ("destructuring", "CounterState { count: int self } = current; require(self.count >= 0);"),
    ];

    for (case, body) in cases {
        let source = format!(
            r#"
                state CounterState {{ int count; }}

                actor Counter owns CounterState {{
                    entry inspect() emits none {{
                        {body}
                    }}
                }}

                app Test {{ actor Counter; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(
            err.to_string().contains("entry binding `self` collides with current actor context of the same name"),
            "{case}: unexpected error: {err}"
        );
    }
}

#[test]
fn rejects_entry_body_bindings_that_collide_with_handles_or_parameters() {
    let cases = [
        ("emit local", "", "", "emits next: Counter", "CounterState next = state(self); become next <- self;", "emit handle"),
        ("emit parameter", "int next", "", "emits next: Counter", "become next <- self;", "emit handle"),
        ("consume local", "", "consumes { peer: Peer, }", "emits none", "int peer = 1;", "consume handle"),
        ("consume loop", "", "consumes { peer: Peer, }", "emits none", "for (peer, 0, 1, 1) { require(1 == 1); }", "consume handle"),
        ("consume tuple", "", "consumes { peer: Peer, }", "emits none", "(int peer, int other) = pair();", "consume handle"),
        (
            "consume destructuring",
            "",
            "consumes { peer: Peer, }",
            "emits none",
            "CounterState { count: int peer } = state(self);",
            "consume handle",
        ),
        ("parameter nested local", "int amount", "", "emits none", "{ int amount = 1; }", "entry parameter"),
    ];

    for (case, params, clauses, emits, body, role) in cases {
        let source = format!(
            r#"
                state CounterState {{ int count; }}
                state PeerState {{ int amount; }}

                actor Counter owns CounterState {{
                    entry inspect({params}) {clauses} {emits} {{
                        {body}
                    }}
                }}

                actor Peer owns PeerState {{}}
                app Test {{ actor Counter; actor Peer; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(err.to_string().contains(&format!("collides with {role} of the same name")), "{case}: unexpected error: {err}");
    }
}

#[test]
fn rejects_reserved_output_handle_from_model() {
    let mut program = test_program();
    program.modules[0].actors[0].entries[0].emits = EmitSpec::Outputs(vec![EmitOutput {
        name: "gen__next".to_string(),
        actors: vec!["Player".to_string()],
        cardinality: Cardinality::One,
        auth_index: 0,
    }]);
    set_entry_body(&mut program.modules[0].actors[0].entries[0], "become gen__next <- Player(next_player);");

    let err = Model::from_program(&program).expect_err("reserved output handle must be rejected");
    assert!(err.to_string().contains("reserved generated namespace"), "unexpected error: {err}");
}

#[test]
fn rejects_template_actor_snake_case_collision() {
    let mut program = test_program();
    program.modules[0].actors[0].name = "FooBar".to_string();
    program.modules[0].actors[1].name = "Foo_Bar".to_string();
    program.modules[0].actors[0].entries.clear();
    program.modules[0].apps[0].actors = vec!["FooBar".to_string(), "Foo_Bar".to_string()];

    let err = Model::from_program(&program).expect_err("snake-case generated names must not collide");
    assert!(err.to_string().contains("both map to generated suffix `foo_bar`"), "unexpected error: {err}");
}

#[test]
fn allows_legacy_template_like_user_field_after_namespace_move() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state FooState {
                int template_foo;
            }

            actor Foo owns FooState {}

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };

    Model::from_program(&program).expect("ordinary template-like names should be legal");
}

#[test]
fn emits_reserved_generated_namespace_names() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits next: Foo {
                    require(next.value == self.value);
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor("Foo").expect("actor exists");
    let sil = emit_actor(actor, &model).expect("actor emits");
    let manifest = emit_manifest(&program, &model);

    assert!(!sil.contains("byte[32] gen__init_foo_template"), "{sil}");
    assert!(!sil.contains("byte[32] gen__foo_template = gen__init_foo_template;"), "{sil}");
    assert!(sil.contains("int gen__next_output_idx = OpAuthOutputIdx"), "{sil}");
    assert!(sil.contains("tx.outputs[gen__next_output_idx].value"), "{sil}");
    assert!(sil.contains("tx.outputs[gen__next_output_idx].scriptPubKey"), "{sil}");
    assert!(sil.contains("== tx.inputs[this.activeInputIndex].scriptPubKey"), "{sil}");
    assert!(manifest.contains(r#""symbol": "gen__foo_template""#), "{manifest}");
    assert!(!sil.contains("byte[32] init_template_foo"), "{sil}");
    assert!(!sil.contains("int next_output_idx ="), "{sil}");
    assert!(!sil.contains("byte[] foo_prefix"), "{sil}");
    assert!(!sil.contains("byte[] gen__foo_prefix"), "{sil}");
    assert!(!sil.contains("gen__state_foo_state"), "{sil}");
    assert!(!sil.contains("__argent_"), "{sil}");
}

#[test]
fn rejects_emit_output_without_value_policy() {
    let err = emit_inline_error(
        r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits next: Foo {
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
            "#,
    );

    let message = err.to_string();
    assert!(message.contains("must reference output value `next.value`"), "unexpected error: {err}");
    assert!(message.contains("if intentionally unrestricted, add `unrestricted(next.value);`"), "unexpected error: {err}");
}

#[test]
fn commented_output_value_does_not_satisfy_the_reference_check() {
    let err = emit_inline_error(
        r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits next: Foo {
                    require(1 == 1 /* next.value */);
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
            "#,
    );

    assert!(err.to_string().contains("must reference output value `next.value`"), "unexpected error: {err}");
}

#[test]
fn output_value_reference_anywhere_in_the_entry_satisfies_the_check() {
    let source = r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits next: Foo {
                    int output_value = next.value;
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Foo").expect("actor exists"), &model).expect("actor emits");

    assert!(sil.contains("int output_value = tx.outputs[gen__next_output_idx].value;"), "{sil}");
}

#[test]
fn unrestricted_output_value_policy_is_compile_time_only() {
    let source = r#"
            state FooState {}

            actor Foo owns FooState {
                entry allow() emits next: Foo {
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Foo").expect("actor exists"), &model).expect("actor emits");

    assert!(!sil.contains(word::UNRESTRICTED), "{sil}");
}

#[test]
fn unrestricted_output_value_policy_requires_a_current_output_handle() {
    let err = emit_inline_error(
        r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits next: Foo {
                    unrestricted(self.value);
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
            "#,
    );

    assert!(
        err.to_string()
            .contains("`unrestricted(...)` expects exactly one current emit or spawn output value; `self.value` is not one"),
        "unexpected error: {err}"
    );
}

#[test]
fn spawn_output_value_can_be_constrained_by_qualified_handle() {
    let source = r#"
            state LauncherState {}
            state ChildState {}

            actor Launcher owns LauncherState {
                entry launch()
                spawns children by children_id {
                    outputs {
                        child: Child,
                    }
                }
                emits next: Launcher {
                    unrestricted(next.value);
                    require(children.outputs.child.value > 0);
                    require children.outputs become {
                        child <- Child(ChildState {}),
                    };
                    become next <- self;
                }
            }

            actor Child owns ChildState {}

            app Test {
                actor Launcher;
                actor Child;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Launcher").expect("actor exists"), &model).expect("actor emits");

    assert!(sil.contains("require(tx.outputs[gen__children_child_output_idx].value > 0);"), "{sil}");
}

#[test]
fn rejects_spawn_output_without_value_policy() {
    let err = emit_inline_error(
        r#"
            state LauncherState {}
            state ChildState {}

            actor Launcher owns LauncherState {
                entry launch()
                spawns children by children_id {
                    outputs {
                        child: Child,
                    }
                }
                emits next: Launcher {
                    unrestricted(next.value);
                    require children.outputs become {
                        child <- Child(ChildState {}),
                    };
                    become next <- self;
                }
            }

            actor Child owns ChildState {}

            app Test {
                actor Launcher;
                actor Child;
            }
            "#,
    );

    assert!(err.to_string().contains("must reference output value `children.outputs.child.value`"), "unexpected error: {err}");
}

#[test]
fn qualified_spawn_value_does_not_cover_emit_value() {
    let err = emit_inline_error(
        r#"
            state LauncherState {}
            state ChildState {}

            actor Launcher owns LauncherState {
                entry launch()
                spawns children by children_id {
                    outputs {
                        child: Child,
                    }
                }
                emits launcher: Launcher {
                    require(children.outputs.child.value > 0);
                    require children.outputs become {
                        child <- Child(ChildState {}),
                    };
                    become launcher <- self;
                }
            }

            actor Child owns ChildState {}

            app Test {
                actor Launcher;
                actor Child;
            }
            "#,
    );

    let message = err.to_string();
    assert!(message.contains("must reference output value `launcher.value`"), "unexpected error: {err}");
    assert!(!message.contains("`children.outputs.child.value`,"), "unexpected error: {err}");
}

#[test]
fn observed_output_value_is_the_emitter_contracts_responsibility() {
    let source = r#"
            state ObserverState {}
            state AssetState {}

            actor Observer owns ObserverState {
                entry follow(cov_id remote_id)
                observes remote by remote_id {
                    outputs {
                        asset: Asset,
                    }
                }
                emits none {
                    require remote.outputs become {
                        asset <- Asset(AssetState {}),
                    };
                }
            }

            actor Asset owns AssetState {}

            app Test {
                actor Observer;
                actor Asset;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");

    emit_actor(model.actor("Observer").expect("actor exists"), &model).expect("observed output needs no local value policy");
}

#[test]
fn self_cov_id_lowers_to_the_active_input_covenant_id() {
    let source = r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits next: Foo {
                    unrestricted(next.value);
                    require(self.cov_id == self.cov_id);
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Foo").expect("actor exists"), &model).expect("actor emits");

    assert!(sil.contains("require(OpInputCovenantId(this.activeInputIndex) == OpInputCovenantId(this.activeInputIndex));"), "{sil}");
}

#[test]
fn self_member_prefixes_remain_state_field_refs() {
    let source = r#"
            state FooState {
                int value_note;
                int cov_id_note;
            }
            state PeerState {}

            actor Foo owns FooState {
                entry step()
                consumes {
                    foo_self: Peer,
                }
                emits next: Foo {
                    unrestricted(next.value);
                    require(self.value_note == value_note);
                    require(self.cov_id_note == cov_id_note);
                    require(foo_self.value >= 0);
                    become next <- self;
                }
            }

            actor Peer owns PeerState {}

            app Test {
                actor Foo;
                actor Peer;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Foo").expect("actor exists"), &model).expect("actor emits");

    assert!(sil.contains("require(value_note == value_note);"), "{sil}");
    assert!(sil.contains("require(cov_id_note == cov_id_note);"), "{sil}");
    assert!(sil.contains("require(tx.inputs[gen__foo_self_input_idx].value >= 0);"), "{sil}");
}

#[test]
fn self_transition_uses_same_template_shortcut() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
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

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor("Foo").expect("actor exists");
    let sil = emit_actor(actor, &model).expect("actor emits");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");

    assert!(!sil.contains("FooState"), "{sil}");
    assert!(sil.contains("State next_state = State {"), "{sil}");
    assert!(sil.contains("validateOutputState(gen__next_output_idx, next_state);"), "{sil}");
    assert!(!sil.contains("validateOutputStateWithTemplate"), "{sil}");
    assert!(!sil.contains("byte[] gen__foo_prefix"), "{sil}");

    let foo = artifact.argent.actors.iter().find(|actor| actor.name == "Foo").expect("Foo actor is present");
    let bump = foo.entries.iter().find(|entry| entry.name == "bump").expect("bump entry is present");
    assert!(bump.hidden_params.is_empty());
    assert!(bump.witnesses.is_empty());
    assert!(bump.route_plan.witness_recipe_ids.is_empty());

    let sil_foo = artifact.sil_abi.contract("Foo").expect("Foo Sil ABI exists");
    let sil_bump = sil_foo.entry("bump").expect("bump Sil ABI exists");
    assert_eq!(sil_bump.params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(), ["amount"]);
}

#[test]
fn output_template_proofs_are_independent_of_physical_state_type() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "output-template-proof-matrix",
        r#"
            state BoardState { int ply; }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Mux owns BoardState {
                entry hold() emits next: Mux {
                    BoardState next_state = { ply: ply + 1 };
                    unrestricted(next.value);
                    become next <- Mux(next_state);
                }

                entry handoff()
                consumes {
                    prior: Pawn,
                }
                emits next: Pawn {
                    BoardState next_state = { ply: prior.ply + 1 };
                    unrestricted(next.value);
                    become next <- Pawn(next_state);
                }

                entry choose(MoveActor target) emits next: MoveActor {
                    BoardState next_state = { ply: ply + 1 };
                    unrestricted(next.value);
                    become next <- target(next_state);
                }
            }

            actor Pawn owns BoardState {
                delegate accept() consumes {
                    leader: Mux,
                } {}
            }

            actor Knight owns BoardState {
                entry hold() emits none { require(ply >= 0); }
            }

            app Test {
                actor Mux;
                actor Pawn;
                actor Knight;
            }
        "#,
    );
    let sil = &actor_sil["Mux"];
    let hold = sil.split_once("entry hold()").expect("hold entry exists").1.split_once("entry handoff(").expect("handoff follows").0;
    let handoff =
        sil.split_once("entry handoff(").expect("handoff entry exists").1.split_once("entry choose(").expect("choose follows").0;
    let choose = sil.split_once("entry choose(").expect("choose entry exists").1;

    assert!(hold.contains("State gen__state_next_state = State {"), "{hold}");
    assert!(hold.contains("validateOutputState(gen__next_output_idx, gen__state_next_state);"), "{hold}");

    assert!(handoff.contains("State gen__state_next_state = State {"), "{handoff}");
    assert!(handoff.contains("Gen__PawnState gen__prior_state = readInputStateWithTemplate("), "{handoff}");
    assert!(handoff.contains("validateOutputStateWithInputTemplate("), "{handoff}");
    assert!(handoff.contains("gen__prior_input_idx,"), "{handoff}");

    assert!(choose.contains("State gen__state_next_state = State {"), "{choose}");
    assert!(choose.contains("validateOutputStateWithTemplate("), "{choose}");
    assert!(choose.contains("gen__target_template"), "{choose}");
}

#[test]
fn state_returning_function_initializes_an_authored_local_once() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "state-function-local",
        r#"
            state CounterState {
                int left;
                int right;
            }

            actor Counter owns CounterState {
                fn successor() -> CounterState {
                    return CounterState {
                        left: left + 1,
                        right: right + 1,
                    };
                }

                entry bump() emits next: Counter {
                    CounterState candidate = successor();
                    unrestricted(next.value);
                    become next <- Counter(candidate);
                }
            }

            app Test {
                actor Counter;
            }
        "#,
    );

    let sil = actor_sil.get("Counter").expect("Counter emits");
    assert!(!sil.contains("CounterState"), "{sil}");
    assert!(sil.contains("function successor() : State"), "{sil}");
    assert!(sil.contains("State candidate = successor();"), "{sil}");
    assert!(!sil.contains("successor().left"), "{sil}");
    assert!(!sil.contains("successor().right"), "{sil}");
    assert!(sil.contains("validateOutputState(gen__next_output_idx, candidate);"), "{sil}");
}

#[test]
fn named_exact_self_coexists_with_a_constructed_route() {
    let (actor_sil, artifact) = inline_actor_sil_and_artifact(
        "exact-self-mixed",
        r#"
            state CurrentState { int nonce; }
            state PeerState { int nonce; }

            actor Current owns CurrentState {
                entry step() emits {
                    current: Current,
                    peer: Peer,
                } {
                    unrestricted(current.value);
                    unrestricted(peer.value);
                    PeerState next_peer = PeerState {
                        nonce: nonce,
                    };
                    become {
                        current <- self,
                        peer <- Peer(next_peer),
                    };
                }
            }

            actor Peer owns PeerState {
                entry hold() emits none {
                    require(nonce >= 0);
                }
            }

            app Test {
                actor Current;
                actor Peer;
            }
        "#,
    );

    let sil = actor_sil.get("Current").expect("Current emits");
    assert!(sil.contains("// :: become Current"), "{sil}");
    assert!(sil.contains("tx.outputs[gen__current_output_idx].scriptPubKey"), "{sil}");
    assert!(sil.contains("== tx.inputs[this.activeInputIndex].scriptPubKey"), "{sil}");
    assert!(sil.contains("// :: become Peer"), "{sil}");
    assert_eq!(sil.matches("validateOutputStateWithTemplate(").count(), 1, "{sil}");

    let entry = artifact
        .argent
        .actors
        .iter()
        .find(|actor| actor.name == "Current")
        .and_then(|actor| actor.entries.iter().find(|entry| entry.name == "step"))
        .expect("Current::step artifact exists");
    assert_eq!(entry.routes[0].output, "current");
    assert!(matches!(entry.routes[0].successor, RouteSuccessorArtifact::ExactSelf));
    assert_eq!(artifact_constructed_actor(&entry.routes[1]), "Peer");
    artifact.check_template_plan_consistency().expect("exact and constructed successor metadata verifies");
}

#[test]
fn exact_self_requires_an_output_handle_and_checks_its_actor_domain() {
    let bare = parse_and_validate(
        r#"
            state CurrentState {}

            actor Current owns CurrentState {
                entry step() emits next: Current {
                    unrestricted(next.value);
                    become self;
                }
            }

            app Test { actor Current; }
        "#,
    )
    .expect_err("exact self must name an output like every other successor");
    assert!(bare.to_string().contains("every `become` route must name its output"), "unexpected error: {bare}");

    let incompatible = parse_and_validate(
        r#"
            state CurrentState {}
            state PeerState {}

            actor Current owns CurrentState {
                entry step() emits next: Peer {
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            actor Peer owns PeerState {}

            app Test {
                actor Current;
                actor Peer;
            }
        "#,
    )
    .expect_err("named exact self must target a compatible output");
    assert!(incompatible.to_string().contains("cannot preserve exact self through output `next`"), "unexpected error: {incompatible}");

    parse_and_validate(
        r#"
            state SharedState {}
            state OtherState {}

            actor enum CurrentDomain {
                Current;
                Peer;
            }

            actor Current owns SharedState {
                entry step() emits {
                    current: CurrentDomain,
                    other: Other,
                } {
                    unrestricted(current.value);
                    unrestricted(other.value);
                    become {
                        current <- self,
                        other <- Other(OtherState {}),
                    };
                }
            }

            actor Peer owns SharedState {}
            actor Other owns OtherState {}

            app Test {
                actor Current;
                actor Peer;
                actor Other;
            }
        "#,
    )
    .expect("an actor-enum output permits its current-actor variant for a named exact successor");
}

#[test]
fn exact_self_is_rejected_for_external_covenant_outputs() {
    let spawn = parse_and_validate(
        r#"
            state LauncherState {}
            state ChildState {}

            actor Launcher owns LauncherState {
                entry launch()
                spawns children by children_id {
                    outputs {
                        child: Child,
                    }
                }
                emits next: Launcher {
                    unrestricted(next.value);
                    require children.outputs become {
                        child <- self,
                    };
                    become next <- self;
                }
            }

            actor Child owns ChildState {}

            app Test {
                actor Launcher;
                actor Child;
            }
        "#,
    )
    .expect_err("spawn output validation cannot preserve the active input exactly");
    assert!(
        spawn.to_string().contains("cannot use exact successor `self` for observe or spawn `children` outputs"),
        "unexpected error: {spawn}"
    );

    let observed = parse_and_validate(
        r#"
            state ObserverState {}
            state PeerState {}

            actor Observer owns ObserverState {
                entry inspect(cov_id remote_id)
                observes remote by remote_id {
                    outputs {
                        peer: Peer,
                    }
                }
                emits none {
                    require remote.outputs become {
                        peer <- self,
                    };
                }
            }

            actor Peer owns PeerState {}

            app Test {
                actor Observer;
                actor Peer;
            }
        "#,
    )
    .expect_err("observed output validation cannot preserve the active input exactly");
    assert!(
        observed.to_string().contains("cannot use exact successor `self` for observe or spawn `remote` outputs"),
        "unexpected error: {observed}"
    );
}

#[test]
fn state_valued_functions_are_characterized_in_aligned_and_augmented_contexts() {
    let fixture = "tests/fixtures/state_layout/function_contexts/app.ag";
    let (aligned_sil, artifact) = emit_selected_fixture(fixture, "Test", "Aligned");
    let (routed_sil, _) = emit_selected_fixture(fixture, "Test", "Routed");
    let (reader_sil, _) = emit_selected_fixture(fixture, "Test", "Reader");

    assert_eq!(aligned_sil, include_str!("../../../../tests/fixtures/state_layout/function_contexts/Aligned.sil"));
    assert_eq!(routed_sil, include_str!("../../../../tests/fixtures/state_layout/function_contexts/Routed.sil"));
    assert_eq!(reader_sil, include_str!("../../../../tests/fixtures/state_layout/function_contexts/Reader.sil"));

    assert!(!aligned_sil.contains("SharedState"), "{aligned_sil}");
    assert!(!aligned_sil.contains("struct SharedState"), "{aligned_sil}");
    assert!(aligned_sil.contains("function global_identity(State gen__glob_value) : State"), "{aligned_sil}");
    assert!(aligned_sil.contains("function global_fixed(State[2] gen__glob_values) : State[2]"), "{aligned_sil}");
    assert!(aligned_sil.contains("function global_dynamic(State[] gen__glob_values) : State[]"), "{aligned_sil}");
    assert!(aligned_sil.contains("function actor_identity(State value) : State"), "{aligned_sil}");
    assert!(aligned_sil.contains("function actor_fixed(State[2] values) : State[2]"), "{aligned_sil}");
    assert!(aligned_sil.contains("function actor_dynamic(State[] values) : State[]"), "{aligned_sil}");
    assert!(aligned_sil.contains("State[2] gen__glob_fixed_literal = State[2]"), "{aligned_sil}");
    assert!(aligned_sil.contains("State[_] gen__glob_inferred_literal = State[_]"), "{aligned_sil}");
    assert!(aligned_sil.contains("State[SHARED_COUNT] gen__glob_symbolic_literal = State[SHARED_COUNT]"), "{aligned_sil}");
    assert!(aligned_sil.contains("State[] gen__glob_dynamic_literal = State[]"), "{aligned_sil}");
    assert!(aligned_sil.contains("State constructed = State {"), "{aligned_sil}");

    assert!(routed_sil.contains("struct SharedState"), "{routed_sil}");
    assert!(routed_sil.contains("function global_identity(SharedState gen__glob_value) : SharedState"), "{routed_sil}");
    assert!(routed_sil.contains("function global_fixed(SharedState[2] gen__glob_values) : SharedState[2]"), "{routed_sil}");
    assert!(routed_sil.contains("function global_dynamic(SharedState[] gen__glob_values) : SharedState[]"), "{routed_sil}");
    assert!(routed_sil.contains("function actor_identity(SharedState value) : SharedState"), "{routed_sil}");
    assert!(routed_sil.contains("SharedState constructed = SharedState {"), "{routed_sil}");
    assert!(!routed_sil.contains("State constructed = State {"), "{routed_sil}");
    assert!(aligned_sil.contains("reassigned = global_identity(value);"), "{aligned_sil}");
    assert!(aligned_sil.contains("} = reassigned;"), "{aligned_sil}");

    let advance = routed_sil
        .split_once("entry advance")
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.split_once("// :: leader entry (1:N)\n    entry export").map(|(body, _)| body))
        .expect("advance entry is delimited in the generated SIL");
    assert_eq!(advance.matches("actor_identity(global_identity(value))").count(), 1, "{advance}");
    assert_eq!(advance.matches("actor_fixed(global_fixed(fixed))").count(), 1, "{advance}");
    assert_eq!(advance.matches("actor_dynamic(global_dynamic(dynamic))").count(), 1, "{advance}");
    assert_eq!(advance.matches("actor_identity(scalar)").count(), 1, "{advance}");
    assert!(!advance.contains("actor_identity(scalar).left"), "{advance}");
    assert!(!advance.contains("actor_identity(scalar).right"), "{advance}");
    assert!(advance.contains("SharedState gen__source_next_shared_state = actor_identity(scalar);"), "{advance}");
    assert!(advance.contains("validateOutputState(gen__next_output_idx, gen__state_next_state);"), "{advance}");
    assert!(routed_sil.contains("validateOutputStateWithTemplate("), "{routed_sil}");

    let inspect = reader_sil.split_once("entry inspect").map(|(_, body)| body).expect("Reader inspect entry is emitted");
    assert_eq!(inspect.matches("readInputStateWithTemplate(").count(), 1, "{inspect}");
    assert!(inspect.contains("SharedState[2] fixed_from_peer = SharedState[_]{ value, SharedState {"), "{inspect}");
    assert!(inspect.contains("SharedState[] dynamic_from_peer = SharedState[]{ SharedState {"), "{inspect}");
    assert!(inspect.contains("SharedState[3] fixed_appended = fixed.append(SharedState {"), "{inspect}");
    assert!(inspect.contains("SharedState[] appended = dynamic.append(SharedState {"), "{inspect}");
    assert!(inspect.contains("appended = appended.append(SharedState {"), "{inspect}");
    assert!(!inspect.contains("dynamic.append(peer)"), "{inspect}");
    assert!(inspect.contains("require(dynamic.append(SharedState {"), "{inspect}");
    assert!(inspect.contains("require(SharedState[]{ SharedState {"), "{inspect}");
    assert_eq!(inspect.matches("global_fixed(fixed)").count(), 1, "{inspect}");
    assert_eq!(inspect.matches("global_dynamic(dynamic)").count(), 1, "{inspect}");
    assert!(inspect.contains("SharedState indexed = global_fixed(fixed)[0];"), "{inspect}");
    assert!(inspect.contains("SharedState passed = global_identity(global_dynamic(dynamic)[0]);"), "{inspect}");

    let shared = artifact.argent.states.iter().find(|state| state.name == "SharedState").expect("SharedState is recorded");
    assert_eq!(shared.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["left", "right"]);

    let aligned = artifact.sil_abi.contract("Aligned").expect("Aligned contract exists");
    assert_eq!(aligned.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["left", "right"]);
    assert!(runtime_state_plan(&artifact, "Aligned").is_none());

    let routed = artifact.sil_abi.contract("Routed").expect("Routed contract exists");
    assert_eq!(
        routed.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["gen__foreign_template", "left", "right"]
    );
    assert_eq!(
        runtime_state_plan(&artifact, "Routed")
            .expect("Routed physical plan exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        [("gen__foreign_template", RuntimeFieldRoleArtifact::Template { contract: "Foreign".to_string() })]
    );

    let templates = &artifact.argent.template_plan.templates;
    let aligned_template = templates.iter().find(|template| template.actor == "Aligned").expect("Aligned template exists");
    let routed_template = templates.iter().find(|template| template.actor == "Routed").expect("Routed template exists");
    assert_eq!(encode_hex(&aligned_template.sil_template_hash), "93509ef29827d95b79f405cf30f2c651fadbd01c06f0a7c73088678a10dfb4ef");
    assert_eq!(encode_hex(&routed_template.sil_template_hash), "51b73db36d9fa9d0cdd8ef0ee1567c8507a5051b8075fd7a596567d875a6e261");
    assert!(aligned_template.actor_type_handle.context_fields.is_empty());
    assert_eq!(routed_template.actor_type_handle.context_fields, ["gen__foreign_template"]);
}

#[test]
fn equivalent_state_shared_constants_use_the_contract_plan() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "equivalent-state-shared-constant",
        r#"
            const CounterState INITIAL = CounterState {
                count: 1,
            };

            state CounterState {
                int count;
            }

            state TargetState {
                int count;
            }

            actor Counter owns CounterState {
                entry inspect() emits none {
                    require(INITIAL.count >= count);
                }
            }

            actor Routed owns CounterState {
                entry advance() emits next: Target {
                    unrestricted(next.value);
                    become next <- Target(TargetState {
                        count: INITIAL.count,
                    });
                }
            }

            actor Target owns TargetState {
                entry inspect() emits none {
                    require(count >= 0);
                }
            }

            app Test {
                actor Counter;
                actor Routed;
                actor Target;
            }
        "#,
    );
    let sil = &actor_sil["Counter"];
    let routed = &actor_sil["Routed"];

    assert!(sil.contains("State constant INITIAL = State {"), "{sil}");
    assert!(!sil.contains("CounterState"), "{sil}");
    assert!(routed.contains("CounterState constant INITIAL = CounterState {"), "{routed}");
    assert!(!routed.contains("State constant INITIAL = State {"), "{routed}");
}

#[test]
fn equivalent_state_literals_lower_in_plain_entry_statements() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "equivalent-state-plain-expression",
        r#"
            state CounterState {
                int count;
            }

            actor Counter owns CounterState {
                entry inspect() emits none {
                    require(CounterState[]{ CounterState { count: count } }.length == 1);
                }
            }

            app Test {
                actor Counter;
            }
        "#,
    );
    let sil = &actor_sil["Counter"];

    assert!(sil.contains("require(State[]{ State {"), "{sil}");
    assert!(sil.contains("}.length == 1);"), "{sil}");
    assert!(!sil.contains("CounterState"), "{sil}");
}

#[test]
fn equivalent_state_assignment_retains_parenthesized_postfix_cast() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "equivalent-state-parenthesized-postfix-cast",
        r#"
            state CounterState {
                byte status;
            }

            actor Counter owns CounterState {
                entry inspect(byte increment) emits none {
                    byte next_status = status;
                    next_status = (signed(next_status) + signed(increment)) as byte;
                    require(signed(next_status) >= signed(status));
                }
            }

            app Test {
                actor Counter;
            }
        "#,
    );
    let sil = &actor_sil["Counter"];

    assert!(sil.contains("next_status = (signed(next_status) + signed(increment)) as byte;"), "{sil}");
}

#[test]
fn typed_state_constant_can_supply_a_constructed_successor_directly() {
    let (actors, _) = inline_actor_sil_and_artifact(
        "state-constant-successor",
        r#"
            state CounterState {
                int count;
            }

            const CounterState INITIAL = CounterState {
                count: 1,
            };

            actor Counter owns CounterState {
                entry reset() emits next: Counter {
                    byte[32] initial_digest = digest(INITIAL);
                    require(initial_digest == initial_digest);
                    unrestricted(next.value);
                    become next <- Counter(INITIAL);
                }
            }

            app Test { actor Counter; }
        "#,
    );

    assert!(actors["Counter"].contains("State constant INITIAL = State {"), "{}", actors["Counter"]);
    assert!(
        actors["Counter"].contains("byte[32] initial_digest = blake3(byte[](((INITIAL.count) as byte[8])));"),
        "{}",
        actors["Counter"]
    );
    assert!(!actors["Counter"].contains("function gen__digest_"), "{}", actors["Counter"]);
    assert!(actors["Counter"].contains("validateOutputState(gen__next_output_idx, INITIAL);"), "{}", actors["Counter"]);
}

#[test]
fn body_binding_shadows_typed_state_constant_provenance() {
    let err = emit_inline_error(
        r#"
            state CounterState { int count; }

            const CounterState INITIAL = CounterState { count: 1 };

            actor Counter owns CounterState {
                entry reset() emits next: Counter {
                    int INITIAL = 7;
                    unrestricted(next.value);
                    become next <- Counter(INITIAL);
                }
            }

            app Test { actor Counter; }
        "#,
    );

    assert!(err.to_string().contains("is not an authored `CounterState` value"), "unexpected error: {err}");
}

#[test]
fn digest_accepts_scalar_state_results_from_global_and_actor_functions_once() {
    let (actors, _) = inline_actor_sil_and_artifact(
        "state-function-result-digest",
        r#"
            state CounterState {
                int left;
                int right;
            }

            fn global_snapshot(int value) -> CounterState {
                return CounterState {
                    left: value,
                    right: value + 1,
                };
            }

            actor Counter owns CounterState {
                fn actor_snapshot() -> CounterState {
                    return CounterState {
                        left: left,
                        right: right,
                    };
                }

                entry inspect() emits none {
                    byte[32] global_digest = digest(global_snapshot(left));
                    byte[32] actor_digest = digest(actor_snapshot());
                    require(global_digest == global_digest);
                    require(actor_digest == actor_digest);
                }
            }

            app Test { actor Counter; }
        "#,
    );

    let sil = &actors["Counter"];
    assert_eq!(sil.matches("function gen__digest_CounterState(").count(), 1, "one typed helper is shared by both calls: {sil}");
    assert!(sil.contains("gen__digest_CounterState(global_snapshot(left))"), "{sil}");
    assert!(sil.contains("gen__digest_CounterState(actor_snapshot())"), "{sil}");
    assert_eq!(sil.matches("global_snapshot(").count(), 2, "global result must be evaluated once: {sil}");
    assert_eq!(sil.matches("actor_snapshot(").count(), 2, "actor result must be evaluated once: {sil}");
}

#[test]
fn observed_state_reference_can_supply_a_matching_route_state() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "observed-state-route-source",
        r#"
            state ForeignState {
                cov_id group_id;
                int amount;
            }

            state PeerState {
                int amount;
            }

            actor Foreign owns ForeignState {
                entry relay()
                observes asset by self.group_id {
                    inputs {
                        src: Foreign,
                    }
                    outputs {
                        dst: Foreign,
                    }
                }
                emits none {
                    require asset.outputs become {
                        dst <- Foreign(state(asset.inputs.src)),
                    };
                }

                entry forward() emits next: Peer {
                    unrestricted(next.value);
                    become next <- Peer(PeerState {
                        amount: amount,
                    });
                }
            }

            actor Peer owns PeerState {
                entry inspect() emits none {
                    require(amount >= 0);
                }
            }

            app Test {
                actor Foreign;
                actor Peer;
            }
        "#,
    );
    let sil = &actor_sil["Foreign"];
    let relay = sil
        .split_once("entry relay")
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.split_once("entry forward").map(|(body, _)| body))
        .expect("relay entry is delimited in the generated Sil");
    let authored = relay
        .split_once("ForeignState gen__source_dst_foreign_state = ForeignState {")
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.split_once("        };").map(|(body, _)| body))
        .expect("relay reconstructs one authored ForeignState");

    assert_eq!(relay.matches("State gen__asset_src_state = readInputStateWithTemplate(").count(), 1, "{relay}");
    assert!(authored.contains("group_id: gen__asset_src_state.group_id,"), "{authored}");
    assert!(authored.contains("amount: gen__asset_src_state.amount,"), "{authored}");
    assert!(!authored.contains("gen__foreign_template"), "{authored}");
    assert!(!authored.contains("gen__peer_template"), "{authored}");
    assert!(relay.contains("gen__foreign_template: gen__foreign_template,"), "{relay}");
    assert!(relay.contains("gen__peer_template: gen__peer_template,"), "{relay}");
    assert!(!relay.contains("gen__asset_src_state.gen__foreign_template"), "{relay}");
    assert!(!relay.contains("gen__asset_src_state.gen__peer_template"), "{relay}");
    assert!(relay.contains("validateOutputState(gen__asset_dst_output_idx, gen__state_dst_state);"), "{relay}");
}

#[test]
fn consumed_input_handles_reject_same_named_locals() {
    let path = PathBuf::from("consumed-reference-shadowing.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state LocalState {
                int count;
            }

            state PeerState {
                int amount;
            }

            actor Local owns LocalState {
                entry inspect() consumes { peer: Peer, } emits next: Local {
                    {
                        LocalState peer = LocalState {
                            count: count + 1,
                        };
                        LocalState copy = peer;
                        require(copy.count == peer.count);
                    }
                    require(peer.amount >= 0);
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            actor Peer owns PeerState {
                delegate accept() consumes { local: Local, } {}
            }

            app Test {
                actor Local;
                actor Peer;
            }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor("Local").expect("Local exists");
    let err = emit_actor(actor, &model).expect_err("entry locals must not shadow consumed input handles");
    assert!(err.to_string().contains("entry binding `peer` collides with consume handle of the same name"), "{err}");
}

#[test]
fn uniform_input_references_expose_operations_without_implicit_state_values() {
    let (actors, _) = inline_actor_sil_and_artifact(
        "uniform-input-references",
        r#"
            state LocalState {
                cov_id remote_id;
                int count;
            }

            state PeerState {
                int amount;
            }

            fn peer_amount(PeerState value) -> int {
                return value.amount;
            }

            actor Local owns LocalState {
                entry inspect()
                consumes { peer: Peer, }
                observes remote by self.remote_id {
                    inputs { src: Peer, }
                }
                emits next: Local {
                    LocalState current = state(self);
                    PeerState consumed = state(peer);
                    PeerState observed = state(remote.inputs.src);
                    byte[32] consumed_digest = digest(state(peer));

                    require(current.count == self.count);
                    require(consumed.amount == peer.amount);
                    require(observed.amount == remote.inputs.src.amount);
                    require(peer_amount(state(peer)) == peer.amount);
                    require(self.value + peer.value + remote.inputs.src.value >= 0);
                    require(self.cov_id == self.cov_id);
                    require(peer.cov_id == peer.cov_id);
                    require(remote.inputs.src.cov_id == remote.inputs.src.cov_id);
                    require(consumed_digest == consumed_digest);
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            actor Peer owns PeerState {
                delegate accept() consumes { local: Local, } {}
            }

            app Test { actor Local; actor Peer; }
        "#,
    );
    let sil = &actors["Local"];

    assert!(sil.contains("PeerState gen__peer_state = readInputStateWithTemplate("), "{sil}");
    assert!(sil.contains("PeerState gen__remote_src_state = readInputStateWithTemplate("), "{sil}");
    assert!(sil.contains("PeerState consumed = PeerState {"), "{sil}");
    assert!(sil.contains("amount: gen__peer_state.amount,"), "{sil}");
    assert!(sil.contains("PeerState observed = PeerState {"), "{sil}");
    assert!(sil.contains("amount: gen__remote_src_state.amount,"), "{sil}");
    assert!(sil.contains("peer_amount(PeerState {"), "{sil}");
    assert!(sil.contains("byte[32] consumed_digest = blake3(byte[](((gen__peer_state.amount) as byte[8])));"), "{sil}");
    assert!(sil.contains("tx.inputs[gen__peer_input_idx].value"), "{sil}");
    assert!(sil.contains("tx.inputs[gen__remote_src_input_idx].value"), "{sil}");
    assert!(sil.contains("OpInputCovenantId(gen__peer_input_idx)"), "{sil}");
    assert!(sil.contains("OpInputCovenantId(gen__remote_src_input_idx)"), "{sil}");
    assert_eq!(sil.matches("Gen__PeerState gen__peer_state = readInputStateWithTemplate(").count(), 1, "{sil}");
    assert_eq!(sil.matches("Gen__PeerState gen__remote_src_state = readInputStateWithTemplate(").count(), 1, "{sil}");
    assert!(!sil.contains("state(peer)"), "{sil}");
    assert!(!sil.contains("remote.inputs.src"), "{sil}");
}

#[test]
fn input_references_reject_implicit_and_legacy_whole_state_forms() {
    let bare = emit_inline_error(
        r#"
            state SharedState { int count; }
            fn read(SharedState value) -> int { return value.count; }
            actor Counter owns SharedState {
                entry inspect() consumes { peer: Counter, } emits none {
                    require(read(peer) >= 0);
                }
            }
            app Test { actor Counter; }
        "#,
    );
    assert!(bare.to_string().contains("use `state(peer)`"), "unexpected error: {bare}");

    for (legacy_expr, replacement) in
        [("self.state", "state(self)"), ("peer.state", "state(peer)"), ("remote.inputs.src.state", "state(remote.inputs.src)")]
    {
        let legacy = emit_inline_error(&format!(
            r#"
                state SharedState {{ cov_id group_id; int count; }}
                actor Counter owns SharedState {{
                    entry inspect()
                    consumes {{ peer: Counter, }}
                    observes remote by self.group_id {{ inputs {{ src: Counter, }} }}
                    emits none {{
                        SharedState value = {legacy_expr};
                        require(value.count >= 0);
                    }}
                }}
                app Test {{ actor Counter; }}
            "#
        ));
        assert!(legacy.to_string().contains("has no `.state` member"), "unexpected error for {legacy_expr}: {legacy}");
        assert!(legacy.to_string().contains(&format!("use `{replacement}`")), "unexpected error for {legacy_expr}: {legacy}");
    }

    for state in ["self.state", "state(self)"] {
        let successor = emit_inline_error(&format!(
            r#"
                state SharedState {{ int count; }}
                actor Counter owns SharedState {{
                    entry inspect() emits next: Counter {{
                        unrestricted(next.value);
                        become next <- Counter({state});
                    }}
                }}
                app Test {{ actor Counter; }}
            "#
        ));
        assert!(successor.to_string().contains("use `next <- self`"), "unexpected error for {state}: {successor}");
    }

    let nested = emit_inline_error(
        r#"
            state SharedState { int count; }
            actor Counter owns SharedState {
                entry inspect() consumes { peer: Counter, } emits none {
                    byte[32] value = digest(peer.state);
                    require(value.length == 32);
                }
            }
            app Test { actor Counter; }
        "#,
    );
    assert!(nested.to_string().contains("use `state(peer)`"), "unexpected error: {nested}");
}

#[test]
fn input_state_reconstruction_rejects_invalid_calls_and_function_contexts() {
    for (case, expression, expected) in [
        ("missing argument", "state()", "requires exactly one input reference"),
        ("extra argument", "state(self, peer)", "requires exactly one input reference"),
        ("ordinary value", "state(value)", "requires one visible entry input reference"),
        ("output handle", "state(next)", "requires one visible entry input reference"),
    ] {
        let source = format!(
            r#"
                state SharedState {{ int count; }}
                actor Counter owns SharedState {{
                    entry inspect(SharedState value)
                    consumes {{ peer: Counter, }}
                    emits next: Counter {{
                        SharedState reconstructed = {expression};
                        require(reconstructed.count >= 0);
                        unrestricted(next.value);
                        become next <- self;
                    }}
                }}
                app Test {{ actor Counter; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(err.to_string().contains(expected), "{case}: unexpected error: {err}");
    }

    for (context, declaration) in [
        ("global", "fn reconstruct(SharedState value) -> SharedState { return state(value); }"),
        (
            "actor",
            r#"
                actor Counter owns SharedState {
                    fn reconstruct(SharedState value) -> SharedState { return state(value); }
                    entry inspect() emits none { require(count >= 0); }
                }
            "#,
        ),
    ] {
        let actor = if context == "global" {
            "actor Counter owns SharedState { entry inspect() emits none { require(count >= 0); } }"
        } else {
            ""
        };
        let source = format!(
            r#"
                state SharedState {{ int count; }}
                {declaration}
                {actor}
                app Test {{ actor Counter; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(
            err.to_string().contains("input-state reconstruction is only available in entry bodies"),
            "{context}: unexpected error: {err}"
        );
    }
}

#[test]
fn empty_input_state_digest_uses_explicit_empty_bytes() {
    let (actors, _) = inline_actor_sil_and_artifact(
        "empty-input-state-digest",
        r#"
            state Empty {}
            actor EmptyActor owns Empty {
                entry verify(byte[32] expected) emits none {
                    require(digest(state(self)) == expected);
                }
            }
            app Test { actor EmptyActor; }
        "#,
    );
    let sil = &actors["EmptyActor"];

    assert!(sil.contains("require(blake3(byte[](0x)) == expected);"), "{sil}");
}

#[test]
fn expanded_input_and_named_state_digests_use_the_same_storage_payload() {
    let (actors, _) = inline_actor_sil_and_artifact(
        "expanded-input-named-state-digest",
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

            actor Vault owns Expanded {
                entry verify() emits none {
                    Expanded snapshot = state(self);
                    byte[32] direct = digest(state(self));
                    byte[32] local = digest(snapshot);
                    require(direct == local);
                }
            }

            app Test { actor Vault; }
        "#,
    );
    let sil = &actors["Vault"];
    let initializer = |binding: &str| {
        sil.lines()
            .find_map(|line| line.trim().strip_prefix(&format!("byte[32] {binding} = ")).and_then(|value| value.strip_suffix(';')))
            .unwrap_or_else(|| panic!("missing `{binding}` initializer in:\n{sil}"))
    };

    let direct = initializer("direct");
    let local = initializer("local");
    assert_ne!(direct, local, "{sil}");
    assert!(direct.contains("byte[](detail)"), "{sil}");
    assert!(!direct.contains("gen__detail_count"), "{sil}");
    assert!(local.contains("snapshot.nonce"), "{sil}");
    assert!(local.contains("snapshot.detail.count"), "{sil}");
    assert!(sil.contains("require(blake3(byte[](gen__detail_details_preimage)) == detail);"), "{sil}");
    assert!(sil.contains("int gen__detail_count = OpBin2Num(gen__detail_details_preimage.slice(0, 8));"), "{sil}");
}

#[test]
fn digest_call_uses_ast_spans_for_spacing_comments_and_arity() {
    for (case, expression) in [("spaced", "digest (state(self))"), ("commented", "digest /* authored state */ (state(self))")] {
        let source = format!(
            r#"
                state Empty {{}}
                actor EmptyActor owns Empty {{
                    entry verify(byte[32] expected) emits none {{
                        require({expression} == expected);
                    }}
                }}
                app Test {{ actor EmptyActor; }}
            "#
        );
        let (actors, _) = inline_actor_sil_and_artifact(case, &source);
        let sil = &actors["EmptyActor"];
        assert!(sil.contains("require(blake3(byte[](0x)) == expected);"), "{case}: {sil}");
    }

    for expression in ["digest()", "digest(state(self), state(self))"] {
        let source = format!(
            r#"
                state Empty {{}}
                actor EmptyActor owns Empty {{
                    entry verify() emits none {{
                        byte[32] invalid = {expression};
                        require(invalid == invalid);
                    }}
                }}
                app Test {{ actor EmptyActor; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(
            err.to_string().contains("`digest(...)` requires exactly one authored state value"),
            "{expression}: unexpected error: {err}"
        );
    }
}

#[test]
fn observe_roots_reject_same_named_locals() {
    let err = emit_inline_error(
        r#"
            state ForeignState {
                cov_id group_id;
                int amount;
            }

            actor Foreign owns ForeignState {
                entry relay()
                observes asset by self.group_id {
                    inputs {
                        src: Foreign,
                    }
                    outputs {
                        dst: Foreign,
                    }
                }
                emits none {
                    {
                        int asset = 0;
                        require asset.outputs become {
                            dst <- Foreign(state(asset.inputs.src)),
                        };
                    }
                }
            }

            app Test {
                actor Foreign;
            }
        "#,
    );

    assert!(err.to_string().contains("entry binding `asset` collides with observe root of the same name"), "unexpected error: {err}");
}

#[test]
fn observed_input_leaves_do_not_reserve_bare_body_names() {
    let path = PathBuf::from("observed-input-leaf-local.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state ForeignState {
                cov_id group_id;
                int amount;
            }

            actor Foreign owns ForeignState {
                entry inspect()
                observes asset by self.group_id {
                    inputs { src: Foreign, }
                }
                emits none {
                    int src = 1;
                    require(src == 1);
                }
            }

            app Test { actor Foreign; }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor("Foreign").expect("Foreign exists");
    let sil = emit_actor(actor, &model).expect("a local may share a qualified observed input leaf name");

    assert!(sil.contains("int src = 1;"), "{sil}");
    assert!(sil.contains("State gen__asset_src_state = readInputState("), "{sil}");
}

#[test]
fn observed_input_and_output_leaves_may_share_a_name() {
    let path = PathBuf::from("observed-input-output-leaf.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state ForeignState { int amount; }
            state LocalState { cov_id group_id; }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry relay()
                observes asset by self.group_id {
                    inputs { agent: Foreign, }
                    outputs { agent: Foreign, }
                }
                emits none {
                    require asset.outputs become {
                        agent <- Foreign(state(asset.inputs.agent)),
                    };
                }
            }

            app Test { actor Foreign; actor Local; }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("qualified input and output leaves may share a name");
    let actor_sil = actor_sil_for_model(&model);

    emit_artifact(&program, &model, &actor_sil).expect("same-named qualified input and output leaves compile");
}

#[test]
fn observed_output_labels_reject_same_named_body_bindings() {
    let err = emit_inline_error(
        r#"
            state ForeignState {
                cov_id group_id;
                int amount;
            }

            actor Foreign owns ForeignState {
                entry relay()
                observes asset by self.group_id {
                    inputs { src: Foreign, }
                    outputs { dst: Foreign, }
                }
                emits none {
                    ForeignState dst = state(asset.inputs.src);
                    require asset.outputs become {
                        dst <- Foreign(dst),
                    };
                }
            }

            app Test { actor Foreign; }
        "#,
    );

    assert!(
        err.to_string().contains("entry binding `dst` collides with observe `asset` output label of the same name"),
        "unexpected error: {err}"
    );
}

#[test]
fn spawned_output_labels_reject_same_named_body_bindings() {
    let err = emit_inline_error(
        r#"
            state LauncherState { int launches; }
            state ChildState { int amount; }

            actor Launcher owns LauncherState {
                entry launch()
                spawns children by child_id {
                    outputs { child: Child, }
                }
                emits none {
                    ChildState child = { amount: 1 };
                    require children.outputs become {
                        child <- Child(child),
                    };
                }
            }

            actor Child owns ChildState {}
            app Test { actor Launcher; actor Child; }
        "#,
    );

    assert!(
        err.to_string().contains("entry binding `child` collides with spawn `children` output label of the same name"),
        "unexpected error: {err}"
    );
}

#[test]
fn current_state_array_entry_param_uses_selected_state_type() {
    let (actor_sil, artifact) = inline_actor_sil_and_artifact(
        "current-state-array-entry-param",
        r#"
            state NoteState {
                int nonce;
            }

            actor Note owns NoteState {
                entry inspect(NoteState[2] notes) emits none {
                    require(notes[0].nonce >= 0);
                }
            }

            app Test {
                actor Note;
            }
            "#,
    );

    let sil = actor_sil.get("Note").expect("Note emits");
    assert!(!sil.contains("NoteState"), "{sil}");
    assert!(sil.contains("entry inspect(State[2] notes)"), "{sil}");

    let inspect = artifact.sil_abi.contract("Note").expect("Note Sil ABI exists").entry("inspect").expect("inspect entry exists");
    assert_eq!(
        inspect.params[0].ty,
        TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Struct { name: "State".to_string() }), len: 2 }
    );
}

#[test]
fn rejects_mismatched_authored_state_array_shapes_at_function_boundaries() {
    let path = PathBuf::from("state-array-shape-mismatch.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state NoteState {
                int nonce;
            }

            fn fixed(NoteState[2] values) -> NoteState[2] {
                return values;
            }

            actor Note owns NoteState {
                entry inspect(NoteState[] values) emits none {
                    NoteState[2] invalid = fixed(values);
                    require(invalid[0].nonce >= 0);
                }
            }

            app Test {
                actor Note;
            }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let err = emit_actor(model.actor("Note").expect("Note exists"), &model).expect_err("array shapes must agree at the call boundary");

    assert!(err.to_string().contains("authored state value has type `State[]`, not `State[2]`"), "unexpected error: {err}");
}

#[test]
fn constant_sized_state_array_local_remains_planned() {
    let sil = emit_unresolved_fixed_state_array_local("constant-state-array-local", "const int COUNT = 2;", "COUNT");

    assert!(sil.contains("int constant COUNT = 2;"), "{sil}");
    assert!(sil.contains("State[COUNT] values = State[COUNT]{"), "{sil}");
    assert!(sil.contains("State indexed = values[0];"), "{sil}");
    assert!(sil.contains("State[2] result = fixed(values);"), "{sil}");
}

#[test]
fn inferred_state_array_local_uses_initializer_shape() {
    let sil = emit_unresolved_fixed_state_array_local("inferred-state-array-local", "", "_");

    assert!(sil.contains("State[_] values = State[_]{"), "{sil}");
    assert!(sil.contains("State indexed = values[0];"), "{sil}");
    assert!(sil.contains("State[2] result = fixed(values);"), "{sil}");
}

fn emit_unresolved_fixed_state_array_local(case: &str, constant: &str, dimension: &str) -> String {
    let source = r#"
        __CONSTANT__

        state NoteState {
            int nonce;
        }

        fn fixed(NoteState[2] values) -> NoteState[2] {
            return values;
        }

        actor Note owns NoteState {
            entry inspect() emits none {
                NoteState[__DIMENSION__] values = NoteState[__DIMENSION__]{
                    NoteState { nonce: 1 },
                    NoteState { nonce: 2 },
                };
                NoteState indexed = values[0];
                NoteState[2] result = fixed(values);
                require(indexed.nonce + result[0].nonce >= 0);
            }
        }

        app Test {
            actor Note;
        }
    "#
    .replace("__CONSTANT__", constant)
    .replace("__DIMENSION__", dimension);
    let (actors, _) = inline_actor_sil_and_artifact(case, &source);
    actors.get("Note").expect("Note emits").clone()
}

#[test]
fn routed_current_state_array_entry_param_uses_source_state_type() {
    let (actor_sil, artifact) = inline_actor_sil_and_artifact(
        "current-state-array-entry-param",
        r#"
            state NoteState {
                int nonce;
            }

            state ArchiveState {
                int nonce;
            }

            actor Note owns NoteState {
                entry choose(NoteState[2] notes) emits next: Note {
                    unrestricted(next.value);
                    require(notes[0].nonce < notes[1].nonce);
                    become next <- Note(notes[1]);
                }

                entry archive() emits saved: Archive {
                    unrestricted(saved.value);
                    become saved <- Archive(ArchiveState { nonce: nonce });
                }
            }

            actor Archive owns ArchiveState {
                entry hold() emits none {
                    require(nonce >= 0);
                }
            }

            app Test {
                actor Note;
                actor Archive;
            }
            "#,
    );

    let sil = actor_sil.get("Note").expect("Note emits");
    assert!(sil.contains("struct NoteState"), "{sil}");
    assert!(sil.contains("entry choose(NoteState[2] notes)"), "{sil}");
    assert!(sil.contains("gen__archive_template: gen__archive_template"), "{sil}");
    assert!(sil.contains("NoteState gen__source_next_note_state = notes[1];"), "{sil}");
    assert!(sil.contains("nonce: gen__source_next_note_state.nonce"), "{sil}");

    let choose = artifact.sil_abi.contract("Note").expect("Note Sil ABI exists").entry("choose").expect("choose entry exists");
    assert_eq!(
        choose.params[0].ty,
        TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Struct { name: "NoteState".to_string() }), len: 2 }
    );
}

#[test]
fn expanded_entry_params_keep_the_authored_nested_layout() {
    let (actor_sil, artifact) = inline_actor_sil_and_artifact(
        "expanded-entry-param-layout",
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

            actor Vault owns Expanded {
                entry inspect(Expanded value, Expanded[] values, byte[32] expected_digest) emits none {
                    Expanded current = state(self);
                    Details copy = self.detail;
                    byte[32] whole = digest(state(self));
                    require(current.detail.count >= 0);
                    require(copy.count >= 0);
                    require(whole == expected_digest);
                    require(value.detail.count >= 0);
                    require(values.length >= 0);
                }
            }

            state ReaderState {
                int nonce;
            }

            actor Reader owns ReaderState {
                entry inspect() consumes {
                    vault: Vault,
                } emits next: Reader {
                    require(vault.nonce >= 0);

                    Expanded candidate = {
                        nonce: vault.nonce,
                        detail: Details { count: 0 },
                    };
                    require(candidate.detail.count == 0);

                    unrestricted(next.value);
                    become next <- self;
                }
            }

            app ExpandedArgs {
                actor Vault;
                actor Reader;
            }
            "#,
    );
    let sil = &actor_sil["Vault"];

    assert!(sil.contains("struct Expanded {"), "{sil}");
    assert!(sil.contains("Details detail;"), "{sil}");
    assert!(sil.contains("Expanded value,\n        Expanded[] values,\n        byte[32] expected_digest,"), "{sil}");
    assert!(sil.contains("Expanded current = Expanded {"), "{sil}");
    assert!(sil.contains("count: gen__detail_count,"), "{sil}");
    assert!(sil.contains("Details copy = Details {"), "{sil}");
    assert!(sil.contains("byte[32] whole = blake3(byte[](((nonce) as byte[8]) + byte[](detail)));"), "{sil}");
    assert!(sil.contains("int gen__detail_count = OpBin2Num(gen__detail_details_preimage.slice(0, 8));"), "{sil}");
    let inspect = artifact.sil_abi.contract("Vault").expect("Vault contract exists").entry("inspect").expect("inspect entry exists");
    assert_eq!(inspect.params[0].ty, TypeArtifact::Struct { name: "Expanded".to_string() });
    assert_eq!(
        inspect.params[1].ty,
        TypeArtifact::DynamicArray { item: Box::new(TypeArtifact::Struct { name: "Expanded".to_string() }) }
    );
    let expanded = artifact.sil_abi.structs.get("Expanded").expect("Expanded ABI state exists");
    assert_eq!(
        expanded.fields[1].ty,
        TypeArtifact::Struct { name: "Details".to_string() },
        "expanded entry arguments expose their authored nested field"
    );

    let reader_sil = &actor_sil["Reader"];
    assert!(reader_sil.contains("struct Gen__PhysicalExpanded {"), "{reader_sil}");
    assert!(reader_sil.contains("byte[32] detail;"), "{reader_sil}");
    assert!(reader_sil.contains("Gen__PhysicalExpanded gen__vault_state = readInputStateWithTemplate("), "{reader_sil}");
}

#[test]
fn active_expanded_field_projects_as_an_authored_value() {
    let (actors, artifact) = inline_actor_sil_and_artifact(
        "active-expanded-field-value",
        r#"
            state Capsule { virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                fn read_detail(Details value) -> int {
                    return value.count;
                }

                entry inspect() emits next: Archive {
                    Details copy = detail;
                    int opened_count = detail.count;
                    Details[1] copies = Details[1]{ detail };
                    require(copy.count == opened_count);
                    require(copies.length == 1);
                    require(read_detail(detail) == opened_count);

                    unrestricted(next.value);
                    become next <- Archive(detail);
                }
            }

            actor Archive owns Details {
                entry hold() emits none {
                    require(count >= 0);
                }
            }

            app Test { actor Vault; actor Archive; }
        "#,
    );

    let sil = &actors["Vault"];
    assert!(sil.contains("Details copy = Details {"), "{sil}");
    assert!(sil.contains("int opened_count = gen__detail_count;"), "{sil}");
    assert!(sil.contains("Details[1] copies = Details[1]{ Details {"), "{sil}");
    assert!(sil.contains("read_detail(Details {"), "{sil}");
    assert!(sil.contains("Details gen__source_next_details = Details {"), "{sil}");
    assert_eq!(sil.matches("count: gen__detail_count,").count(), 4, "{sil}");

    let expanded = artifact.sil_abi.structs.get("Expanded").expect("Expanded ABI struct exists");
    assert_eq!(expanded.fields[0].ty, TypeArtifact::Struct { name: "Details".to_string() });
    assert_eq!(artifact.sil_abi.structs["Details"].fields[0].ty, TypeArtifact::Int);
}

#[test]
fn aggregate_sil_abi_canonicalizes_contract_local_state_struct_references() {
    let (actors, artifact) = inline_actor_sil_and_artifact(
        "aggregate-abi-state-struct-reference",
        r#"
            state Capsule { virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Archive owns Details {
                entry inspect(Expanded value) emits none {
                    require(value.detail.count >= 0);
                }
            }

            app Test { actor Vault; actor Archive; }
        "#,
    );

    let archive_sil = &actors["Archive"];
    assert!(archive_sil.contains("struct Expanded {\n        // :: user declared fields\n        State detail;"), "{archive_sil}");

    let expanded = &artifact.sil_abi.structs["Expanded"];
    assert_eq!(expanded.fields[0].ty, TypeArtifact::Struct { name: "Details".to_string() });
    assert_eq!(artifact.sil_abi.structs["Details"].fields[0].ty, TypeArtifact::Int);

    let args = vec![SilExpr::int(0)];
    let compiled = compile_contract(archive_sil, &args, CompileOptions::default()).expect("Archive Sil compiles");
    let direct_abi = sil_abi_artifact_from_compiled(&compiled, &args).expect("direct Archive ABI builds");
    assert_eq!(
        direct_abi.structs["Expanded"].fields[0].ty,
        TypeArtifact::Struct { name: "State".to_string() },
        "the direct Sil ABI retains its contract-local State reference"
    );

    let value = crate::codec::ArtifactValue::Object(BTreeMap::from([(
        "detail".to_string(),
        crate::codec::ArtifactValue::Object(BTreeMap::from([("count".to_string(), crate::codec::ArtifactValue::Int(7))])),
    )]));
    let direct_sig = crate::codec::encode_contract_entry_sig_script(&direct_abi, "Archive", "inspect", std::slice::from_ref(&value))
        .expect("direct Sil ABI encodes the struct argument");
    let aggregate_sig = crate::codec::encode_contract_entry_sig_script(&artifact.sil_abi, "Archive", "inspect", &[value])
        .expect("aggregate Sil ABI encodes the canonical struct argument");
    assert_eq!(aggregate_sig, direct_sig);
}

#[test]
fn canonicalizes_state_references_inside_array_types() {
    let mut fixed = TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Struct { name: "State".to_string() }), len: 2 };
    let mut dynamic = TypeArtifact::DynamicArray { item: Box::new(TypeArtifact::Struct { name: "State".to_string() }) };

    assert!(type_references_state(&fixed));
    assert!(type_references_state(&dynamic));
    replace_state_type_ref(&mut fixed, "Details");
    replace_state_type_ref(&mut dynamic, "Details");

    assert!(!type_references_state(&fixed));
    assert!(!type_references_state(&dynamic));
    assert_eq!(fixed, TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Struct { name: "Details".to_string() }), len: 2 });
    assert_eq!(dynamic, TypeArtifact::DynamicArray { item: Box::new(TypeArtifact::Struct { name: "Details".to_string() }) });
}

#[test]
fn sil_abi_merge_rejects_conflicting_structs_and_duplicate_contracts() {
    let compile = |contract: &str, field_type: &str| {
        let source = format!(
            r#"pragma silverscript ^0.1.0;
contract {contract}() {{
    struct Shared {{
        {field_type} value;
    }}

    entry hold() {{
        require(true);
    }}
}}
"#
        );
        let compiled = compile_contract(&source, &[], CompileOptions::default()).expect("test Sil compiles");
        sil_abi_artifact_from_compiled(&compiled, &[]).expect("test Sil ABI builds")
    };

    let left = compile("Left", "int");
    let merged = merge_sil_abi_artifacts(left.clone(), compile("Right", "int")).expect("identical shared structs merge");
    assert_eq!(merged.contracts.len(), 2);
    assert_eq!(merged.structs.len(), 1);

    let right = compile("Right", "bool");
    let err = merge_sil_abi_artifacts(left.clone(), right).expect_err("different definitions of Shared must not merge");
    assert!(err.to_string().contains("conflicting Sil struct `Shared`"), "unexpected error: {err}");

    let err = merge_sil_abi_artifacts(left.clone(), left).expect_err("the same contract must not merge twice");
    assert!(err.to_string().contains("duplicate Sil contract `Left`"), "unexpected error: {err}");
}

#[test]
fn active_expanded_field_rejects_whole_value_destructuring() {
    let err = emit_inline_error(
        r#"
            state Capsule { virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                entry inspect() emits none {
                    Details { count: int opened_count } = detail;
                    require(opened_count >= 0);
                }
            }

            app Test { actor Vault; }
        "#,
    );

    assert!(
        err.to_string().contains(
            "active expanded state field `detail` cannot be destructured as a whole value; project its fields directly, for example `int opened_count = detail.count;`"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn expanded_input_fields_require_validated_preimages() {
    let path = PathBuf::from("expanded-input-projection.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state Capsule { int nonce; virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                entry hold() emits none { require(nonce >= 0); }
            }

            state ReaderState { int nonce; }
            actor Reader owns ReaderState {
                entry inspect() consumes { vault: Vault, } emits next: Reader {
                    require(vault.detail.count >= 0);
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            app Test { actor Vault; actor Reader; }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("expanded input plans");

    let err = emit_actor(model.actor("Reader").expect("Reader exists"), &model)
        .expect_err("a stored expansion digest cannot expose its authored payload");
    assert!(err.to_string().contains("expanded input field `detail`"), "unexpected error: {err}");
    assert!(err.to_string().contains("validated preimage"), "unexpected error: {err}");
}

#[test]
fn expanded_input_state_reconstruction_requires_validated_preimages() {
    let err = emit_inline_error(
        r#"
            state Capsule { int nonce; virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                entry hold() emits none { require(nonce >= 0); }
            }

            state ReaderState { int nonce; }
            actor Reader owns ReaderState {
                entry inspect() consumes { vault: Vault, } emits none {
                    Expanded copy = state(vault);
                    require(copy.nonce >= 0);
                }
            }

            app Test { actor Vault; actor Reader; }
        "#,
    );

    assert!(err.to_string().contains("cannot be materialized without a validated preimage"), "unexpected error: {err}");
    assert!(err.to_string().contains("field `detail`"), "unexpected error: {err}");
}

#[test]
fn expanded_actor_functions_require_explicit_authored_parameters() {
    let path = PathBuf::from("expanded-function-capture.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state Capsule { int nonce; virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                fn captured_count() -> int {
                    return detail.count;
                }

                entry hold() emits none {
                    require(nonce >= 0);
                }
            }

            app Test { actor Vault; }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("expanded actor plans");
    let err = emit_actor(model.actor("Vault").expect("Vault exists"), &model)
        .expect_err("actor functions cannot capture an entry-specific expansion preimage");
    assert!(err.to_string().contains("actor function `Vault::captured_count`"), "unexpected error: {err}");
    assert!(err.to_string().contains("cannot capture expanded field `detail`"), "unexpected error: {err}");
    assert!(err.location.is_some(), "expanded capture diagnostics retain the exact function-body location");

    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "expanded-function-parameter",
        r#"
            state Capsule { int nonce; virtual detail; }
            state Details { int count; }
            state Expanded expands Capsule { detail: Details; }

            actor Vault owns Expanded {
                fn explicit_count(Expanded value) -> int {
                    return value.detail.count;
                }

                fn make_details() -> Details {
                    return Details {
                        count: 1,
                    };
                }

                entry inspect(Expanded value) emits next: Vault {
                    Expanded current = Expanded {
                        nonce: nonce,
                        detail: Details {
                            count: detail.count,
                        },
                    };
                    Details next_detail = Details {
                        count: 2,
                    };
                    Expanded from_local = {
                        nonce: 1,
                        detail: next_detail,
                    };
                    Expanded from_call = {
                        nonce: 2,
                        detail: make_details(),
                    };
                    require(explicit_count(value) >= 0);
                    require(explicit_count(current) >= 0);
                    require(explicit_count(from_local) >= 0);
                    unrestricted(next.value);
                    become next <- Vault(from_call);
                }
            }

            app Test { actor Vault; }
        "#,
    );
    let sil = actor_sil.get("Vault").expect("Vault emits");
    assert!(sil.contains("function explicit_count(Expanded value) : int"), "{sil}");
    assert!(sil.contains("return value.detail.count;"), "{sil}");
    assert!(sil.contains("Expanded current = Expanded {"), "{sil}");
    assert!(sil.contains("detail: Details {"), "{sil}");
    assert!(sil.contains("count: gen__detail_count"), "{sil}");
    assert!(sil.contains("detail: next_detail"), "{sil}");
    assert!(sil.contains("detail: make_details()"), "{sil}");
    assert!(sil.contains("from_call.detail.count"), "{sil}");
}

#[test]
fn entry_state_params_use_selected_types_for_actor_function_calls() {
    let (actor_sil, artifact) = inline_actor_sil_and_artifact(
        "current-state-dynamic-array-entry-param",
        r#"
            state NoteState {
                int nonce;
            }

            actor Note owns NoteState {
                fn read_nonce(NoteState note) -> int {
                    return note.nonce;
                }

                entry inspect(NoteState note) emits none {
                    require(read_nonce(note) >= 0);
                }

                entry inspect_many(NoteState[] notes) emits none {
                    require(notes.length > 0);
                    require(notes[0].nonce >= 0);
                }
            }

            app Test {
                actor Note;
            }
            "#,
    );

    let sil = actor_sil.get("Note").expect("Note emits");
    assert!(!sil.contains("NoteState"), "{sil}");
    assert!(sil.contains("function read_nonce(State note) : int"), "{sil}");
    assert!(sil.contains("entry inspect(State note)"), "{sil}");
    assert!(sil.contains("entry inspect_many(State[] notes)"), "{sil}");

    let note = artifact.sil_abi.contract("Note").expect("Note Sil ABI exists");
    assert_eq!(note.entry("inspect").expect("inspect entry exists").params[0].ty, TypeArtifact::Struct { name: "State".to_string() });
    assert_eq!(
        note.entry("inspect_many").expect("inspect_many entry exists").params[0].ty,
        TypeArtifact::DynamicArray { item: Box::new(TypeArtifact::Struct { name: "State".to_string() }) }
    );
    assert_eq!(artifact.argent.actors.iter().find(|actor| actor.name == "Note").expect("Note actor exists").state, "NoteState");
    assert!(artifact.argent.states.iter().any(|state| state.name == "NoteState"));
}

#[test]
fn terminal_state_does_not_carry_its_own_template() {
    let path = PathBuf::from("terminal-route.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state SourceState {
                int count;
            }

            state TerminalState {
                int count;
            }

            actor Source owns SourceState {
                entry finish() emits next: Terminal {
                    unrestricted(next.value);
                    TerminalState next_state = {
                        count: count + 1,
                    };
                    become next <- Terminal(next_state);
                }
            }

            actor Terminal owns TerminalState {
                entry step() emits next: Terminal {
                    unrestricted(next.value);
                    TerminalState next_state = {
                        count: count + 1,
                    };
                    become next <- Terminal(next_state);
                }
            }

            app Test {
                actor Source;
                actor Terminal;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let terminal = model.actor("Terminal").expect("Terminal actor exists");
    let terminal_sil = emit_actor(terminal, &model).expect("Terminal emits");
    let artifact = emit_artifact(&program, &model, &actor_sil_for_model(&model)).expect("artifact emits");

    assert!(!terminal_sil.contains("byte[32] gen__init_terminal_template"), "{terminal_sil}");
    assert!(!terminal_sil.contains("byte[32] gen__terminal_template ="), "{terminal_sil}");
    assert!(!terminal_sil.contains("TerminalState"), "{terminal_sil}");
    assert!(terminal_sil.contains("State next_state = State {"), "{terminal_sil}");
    assert!(terminal_sil.contains("validateOutputState(gen__next_output_idx, next_state);"), "{terminal_sil}");
    assert!(runtime_state_plan(&artifact, "Terminal").is_none());
    assert_eq!(
        runtime_state_plan(&artifact, "Source")
            .expect("Source carries the target template")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![("gen__terminal_template", RuntimeFieldRoleArtifact::Template { contract: "Terminal".to_string() })]
    );
    let source_template =
        artifact.argent.template_plan.templates.iter().find(|template| template.actor == "Source").expect("Source template exists");
    let source_handle = &source_template.actor_type_handle;
    assert_eq!(source_handle.state, "SourceState");
    assert_eq!(source_handle.context_fields, ["gen__terminal_template"]);
    assert_ne!(source_handle.template.hash, source_template.sil_template_hash);
}

#[test]
fn emits_portable_artifact_schema() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state FooState {
                byte[32] owner;
                int count;
            }

            actor Foo owns FooState {
                entry step(int amount) emits next: Foo {
                    require(next.value == self.value);
                    become next <- self;
                }
            }

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor_sil = actor_sil_for_model(&model);

    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");
    artifact.check_schema_version().expect("schema version is current");
    let json = serde_json::to_string(&artifact).expect("artifact serializes");
    let artifact: crate::artifact::Artifact = serde_json::from_str(&json).expect("artifact deserializes");

    assert_eq!(artifact.schema_version, ARTIFACT_SCHEMA_VERSION);
    assert_eq!(artifact.generator.name, "argentc");
    assert_eq!(artifact.app, "Test");
    assert_eq!(artifact.root, "test.ag");
    assert_eq!(artifact.argent.templates[0].symbol, "gen__foo_template");
    assert_eq!(artifact.argent.templates[0].id, "template/foo");
    assert_eq!(artifact.argent.template_plan.templates[0].id, "template/foo");
    assert_eq!(
        artifact.argent.template_plan.templates[0].sil_template_hash,
        artifact.sil_abi.contract("Foo").unwrap().compiled.template_hash
    );
    let template = &artifact.argent.template_plan.templates[0];
    assert_eq!(template.actor_type_handle.state, "FooState");
    assert!(template.actor_type_handle.context_fields.is_empty());
    assert_eq!(
        template.actor_type_handle.template,
        extract_sil_template(&artifact.sil_abi.contract("Foo").unwrap().compiled).expect("Sil template extracts"),
        "a plain actor still exports its Sil template as its source-state handle"
    );
    artifact.check_template_plan_consistency().expect("template plan receipt verifies");
    assert!(artifact.sil_abi.structs.is_empty(), "the equivalent authored struct is absent from the exact Sil ABI");

    let state = artifact.argent.states.iter().find(|state| state.name == "FooState").expect("source state is present");
    assert_eq!(
        state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["owner", "count"],
        "source state field order must stay stable"
    );
    assert_eq!(state.fields[0].ty, TypeArtifact::FixedBytes { len: 32 });
    assert_eq!(state.fields[1].ty, TypeArtifact::Int);

    let actor = artifact.argent.actors.iter().find(|actor| actor.name == "Foo").expect("actor is present");
    assert_eq!(actor.abi.contract, "Foo");
    let sil_contract = artifact.sil_abi.contract(&actor.abi.contract).expect("outer actor should point at Sil ABI contract");
    assert_eq!(sil_contract.source_path, "sil/Foo.sil");
    assert_compiled_projection("Foo", &sil_contract.compiled);
    assert_eq!(
        sil_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["owner", "count"],
        "runtime state field order must match generated Silverscript state order"
    );
    assert!(runtime_state_plan(&artifact, "Foo").is_none(), "pure source runtime state should not need an Argent field-role overlay");

    let entry = actor.entries.iter().find(|entry| entry.name == "step").expect("entry is present");
    assert_eq!(entry.kind, EntryKindArtifact::Leader);
    assert_eq!(entry.abi.contract, "Foo");
    assert_eq!(entry.abi.entry, "step");
    assert!(entry.hidden_params.is_empty(), "exact same-state continuation should not expose template witnesses");
    assert!(entry.witnesses.is_empty(), "exact same-state continuation should not expose route witnesses");
    assert!(matches!(&entry.emits, EmitArtifact::Outputs { outputs } if outputs.len() == 1 && outputs[0].name == "next"));
    assert_eq!(entry.routes[0].output, "next");
    assert!(matches!(entry.routes[0].successor, RouteSuccessorArtifact::ExactSelf));
    assert_eq!(entry.route_plan.active_input.as_ref().map(|input| (input.actor.as_str(), input.cov_index)), Some(("Foo", Some(0))));
    assert_eq!(entry.route_plan.outputs[0].auth_index, Some(0));
    assert_eq!(entry.route_plan.outputs[0].name, "next");

    let sil_entry = sil_contract.entry(&entry.abi.entry).expect("outer entry should point at Sil ABI entry");
    assert_eq!(sil_entry.params.len(), 1);
    assert_eq!(sil_entry.params[0].name, "amount");
    assert_eq!(sil_entry.params[0].ty, TypeArtifact::Int);
    assert_eq!(
        entry
            .witnesses
            .iter()
            .map(|witness| (witness.param.clone(), subject_label(&witness.subject).to_string(), witness.purpose))
            .collect::<Vec<_>>(),
        entry
            .hidden_params
            .iter()
            .map(|param| (param.name.clone(), subject_label(&param.subject).to_string(), param.purpose))
            .collect::<Vec<_>>(),
        "outer witness recipes must correspond to outer hidden ABI params"
    );
}

#[test]
fn argent_states_preserve_lossy_source_types() {
    let artifact = inline_artifact(
        "source-state-types",
        r#"
            state PayloadState {
                int value;
            }

            state HolderState {
                cov_id controller;
                actor_type<PayloadState> payload_type;
                byte[32] raw;
            }

            actor Holder owns HolderState {
                entry hold() emits next: Holder {
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            app Test {
                actor Holder;
            }
            "#,
    );

    let state = artifact.argent.states.iter().find(|state| state.name == "HolderState").expect("HolderState exists");
    assert_eq!(state.fields[0].ty, TypeArtifact::FixedBytes { len: 32 });
    assert_eq!(
        state.fields[0].source_type,
        Some(SourceTypeArtifact { name: word::COVENANT_ID.to_string(), array: None, actor_state: None })
    );
    assert_eq!(state.fields[1].ty, TypeArtifact::FixedBytes { len: 32 });
    assert_eq!(
        state.fields[1].source_type,
        Some(SourceTypeArtifact { name: word::ACTOR_TYPE.to_string(), array: None, actor_state: Some("PayloadState".to_string()) })
    );
    assert_eq!(state.fields[2].ty, TypeArtifact::FixedBytes { len: 32 });
    assert_eq!(state.fields[2].source_type, None);
}

#[test]
fn state_expansion_uses_base_storage_layout() {
    let (sil, artifact) = emit_fixture("state_expansion", "Forager");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/state_expansion/Forager.sil"));
    assert!(sil.contains("ForagerStrategy strategy;"), "{sil}");
    assert!(sil.contains("byte[32] strategy;"), "{sil}");
    assert!(sil.contains("ForagerState next_state = ForagerState {"), "{sil}");
    assert!(sil.contains("validateOutputState(gen__next_output_idx, gen__state_next_state);"), "{sil}");
    assert!(!sil.contains("validateOutputStateWithTemplate"), "{sil}");

    let expansion = artifact.argent.state_expansions.first().expect("state expansion is recorded");
    assert_eq!(expansion.state, "ForagerState");
    assert_eq!(expansion.base, "AgentCapsule");
    assert_eq!(expansion.digests.len(), 1);
    assert_eq!(expansion.digests[0].field, "strategy");
    assert_eq!(expansion.digests[0].state, "ForagerStrategy");

    let forager_state = artifact.argent.states.iter().find(|state| state.name == "ForagerState").expect("ForagerState exists");
    assert_eq!(forager_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["strategy", "energy"]);
    assert!(forager_state.fields[0].virtual_slot);
    assert!(!forager_state.fields[1].virtual_slot);

    let contract = artifact.sil_abi.contract("Forager").expect("Forager Sil ABI exists");
    assert_eq!(contract.runtime_state.source, "State");
    assert_eq!(contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["strategy", "energy"]);
    assert_eq!(encode_hex(&contract.compiled.template_hash), "6fe9ea6382a598cf1c2c6df366fc8bc4c419ae259d56eee5a7c45d6eb680df02");
    assert!(runtime_state_plan(&artifact, "Forager").is_none());
    let template = artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|template| template.actor == "Forager")
        .expect("Forager template receipt exists");
    assert!(template.actor_type_handle.context_fields.is_empty());
    assert_eq!(template.sil_template_hash, contract.compiled.template_hash);
    let hold = contract.entry("hold").expect("hold ABI exists");
    assert_eq!(hold.params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(), ["gen__strategy_forager_strategy_preimage"]);
    assert_eq!(hold.params[0].ty, TypeArtifact::FixedBytes { len: 8 });

    let actor = artifact.argent.actors.iter().find(|actor| actor.name == "Forager").expect("Forager actor is present");
    let hold = actor.entries.iter().find(|entry| entry.name == "hold").expect("hold entry is present");
    assert_eq!(hold.hidden_params.len(), 1);
    assert_eq!(hold.hidden_params[0].name, "gen__strategy_forager_strategy_preimage");
    assert_eq!(hold.hidden_params[0].ty, TypeArtifact::FixedBytes { len: 8 });
    assert_eq!(hold.hidden_params[0].purpose, HiddenParamPurposeArtifact::StateExpansionPreimage);
}

#[test]
fn scalar_byte_expansion_fields_use_indexed_extraction() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "scalar-byte-state-expansion",
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
                entry inspect(byte expected_network) emits none {
                    require(policy.network == expected_network);
                }
            }

            app Test {
                actor Token;
            }
        "#,
    );
    let sil = &actor_sil["Token"];

    assert!(sil.contains("int gen__policy_version = OpBin2Num(gen__policy_policy_preimage.slice(0, 8));"), "{sil}");
    assert!(sil.contains("byte gen__policy_network = gen__policy_policy_preimage[8];"), "{sil}");
    assert!(sil.contains("int gen__policy_limit = OpBin2Num(gen__policy_policy_preimage.slice(9, 17));"), "{sil}");
    assert!(!sil.contains("byte(gen__policy_policy_preimage.slice"), "{sil}");
}

#[test]
fn static_output_to_a_foreign_expanded_state_declares_the_planned_physical_type() {
    let path = PathBuf::from("static-expanded-output.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state SourceState {
                int nonce;
            }

            state ExpandedStorage {
                int amount;
                virtual detail;
            }

            state Details {
                int count;
            }

            state ExpandedState expands ExpandedStorage {
                detail: Details;
            }

            actor Source owns SourceState {
                entry send() emits next: Target {
                    ExpandedState next_state = ExpandedState {
                        amount: nonce,
                        detail: Details { count: nonce },
                    };
                    unrestricted(next.value);
                    become next <- Target(next_state);
                }
            }

            actor Target owns ExpandedState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            app Test {
                actor Source;
                actor Target;
            }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("expanded target plans");
    let actor_sil = actor_sil_for_model(&model);
    let source_sil = &actor_sil["Source"];

    assert!(source_sil.contains("struct Gen__PhysicalExpandedState {"), "{source_sil}");
    assert!(!source_sil.contains("struct Gen__TargetState {"), "{source_sil}");
    assert!(source_sil.contains("Gen__PhysicalExpandedState gen__state_next_gen__physical_expanded_state"), "{source_sil}");
    emit_artifact(&program, &model, &actor_sil).expect("planned expanded output type compiles");
}

#[test]
fn expanded_output_payload_calls_are_evaluated_once_before_digest_lowering() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "expanded-output-single-evaluation",
        r#"
            state Capsule {
                int nonce;
                virtual detail;
            }

            state Details {
                int count;
                int limit;
            }

            state Expanded expands Capsule {
                detail: Details;
            }

            actor Vault owns Expanded {
                fn make_details() -> Details {
                    return Details {
                        count: 1,
                        limit: 2,
                    };
                }

                entry advance() emits next: Vault {
                    unrestricted(next.value);
                    become next <- Vault(Expanded {
                        nonce: nonce + 1,
                        detail: make_details(),
                    });
                }
            }

            app Test {
                actor Vault;
            }
        "#,
    );
    let sil = &actor_sil["Vault"];

    assert_eq!(sil.matches("detail: make_details(),").count(), 1, "{sil}");
    assert!(sil.contains("Expanded gen__source_next_expanded = Expanded {"), "{sil}");
    assert!(sil.contains("gen__source_next_expanded.detail.count"), "{sil}");
    assert!(sil.contains("gen__source_next_expanded.detail.limit"), "{sil}");
    assert!(!sil.contains("make_details().count"), "{sil}");
    assert!(!sil.contains("make_details().limit"), "{sil}");
}

#[test]
fn rejects_authored_physical_state_constructors() {
    for initializer in ["{ count: count + 1 }", "State { count: count + 1 }"] {
        let source = format!(
            r#"
                state SharedState {{ int count; }}

                actor Current owns SharedState {{
                    entry advance() emits next: Current {{
                        State next_state = {initializer};
                        unrestricted(next.value);
                        become next <- Current(next_state);
                    }}
                }}

                app Test {{ actor Current; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(
            err.to_string().contains("physical `State` is compiler-owned and cannot be constructed in Argent source"),
            "unexpected error for `{initializer}`: {err}"
        );
    }

    for (label, helper) in [
        (
            "global",
            r#"
                fn forge(int count) -> State {
                    return State { count: count + 1 };
                }
            "#,
        ),
        (
            "actor",
            r#"
                actor Current owns SharedState {
                    fn forge(int count) -> State {
                        return State { count: count + 1 };
                    }

                    entry hold() emits none {
                        require(count >= 0);
                    }
                }
            "#,
        ),
    ] {
        let actor = if label == "global" {
            r#"
                actor Current owns SharedState {
                    entry hold() emits none {
                        require(count >= 0);
                    }
                }
            "#
        } else {
            ""
        };
        let source = format!(
            r#"
                state SharedState {{ int count; }}
                {helper}
                {actor}
                app Test {{ actor Current; }}
            "#
        );
        let err = emit_inline_error(&source);
        assert!(
            err.to_string().contains("physical `State` is compiler-owned and cannot be constructed in Argent"),
            "unexpected {label} function error: {err}"
        );
    }
}

#[test]
fn rejects_unclassified_authored_state_constructor_components() {
    let err = emit_inline_error(
        r#"
            fn validation_call() -> int {
                return 1;
            }

            state CounterState { int count; }

            actor Counter owns CounterState {
                entry inspect() emits none {
                    CounterState snapshot = CounterState {
                        count: 1,
                        validation_call(),
                    };
                    require(snapshot.count == 1);
                }
            }

            app Test { actor Counter; }
        "#,
    );

    assert!(err.to_string().contains("state constructor component"), "unexpected error: {err}");
}

#[test]
fn preserves_trivia_between_authored_state_type_and_constructor() {
    let (actors, _) = inline_actor_sil_and_artifact(
        "authored-state-constructor-trivia",
        r#"
            state CounterState { int count; }

            actor Counter owns CounterState {
                entry inspect() emits none {
                    CounterState snapshot = CounterState /* authored */ {
                        count: 1,
                    };
                    CounterState trailing = CounterState {
                        count: 2,
                        /* trailing constructor trivia */
                    };
                    require(snapshot.count == 1 && trailing.count == 2);
                }
            }

            app Test { actor Counter; }
        "#,
    );

    assert!(actors["Counter"].contains("State /* authored */ {"), "{}", actors["Counter"]);
}

#[test]
fn authenticated_physical_state_values_can_be_bound_and_destructured() {
    inline_actor_sil_and_artifact(
        "physical-state-binding",
        r#"
            state CounterState { int count; }

            actor Counter owns CounterState {
                fn retain(State value) -> State {
                    return value;
                }

                entry inspect() emits none {
                    State physical = readInputState(this.activeInputIndex);
                    State rebound = retain(physical);
                    State { count: int current } = rebound;
                    require(rebound.count == current);
                }
            }

            app Test { actor Counter; }
        "#,
    );
}

#[test]
fn physical_state_values_cannot_supply_authored_successors() {
    let err = emit_inline_error(
        r#"
            state CounterState { int count; }

            actor Counter owns CounterState {
                entry advance() emits next: Counter {
                    State physical = readInputState(this.activeInputIndex);
                    unrestricted(next.value);
                    become next <- Counter(physical);
                }
            }

            app Test { actor Counter; }
        "#,
    );
    assert!(err.to_string().contains("is not an authored `CounterState` value"), "unexpected error: {err}");
}

#[test]
fn physical_state_function_results_cannot_supply_authored_successors() {
    let err = emit_inline_error(
        r#"
            state CounterState { int count; }

            actor Counter owns CounterState {
                fn retain(State value) -> State {
                    return value;
                }

                entry advance() emits next: Counter {
                    State physical = readInputState(this.activeInputIndex);
                    unrestricted(next.value);
                    become next <- Counter(retain(physical));
                }
            }

            app Test { actor Counter; }
        "#,
    );
    assert!(err.to_string().contains("is not a proven authored `CounterState` value"), "unexpected error: {err}");
}

#[test]
fn non_active_selector_declares_and_uses_its_canonical_named_type() {
    use crate::compiler::model::PhysicalTargetId;
    use crate::routing::{CommitmentForest, CommitmentPlan, Cut, FamilyPlan, NodePath, RoutePlan};

    let path = PathBuf::from("non-active-selector-output.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state BoardState { int ply; }

            actor enum MoveActor {
                Alpha;
                Beta;
            }

            actor Mux owns BoardState {
                entry choose(MoveActor target) emits next: MoveActor {
                    BoardState next_state = BoardState { ply: ply + 1 };
                    unrestricted(next.value);
                    become next <- target(next_state);
                }
            }

            actor Alpha owns BoardState {
                entry advance() emits next: Tail {
                    BoardState next_state = BoardState { ply: ply + 1 };
                    unrestricted(next.value);
                    become next <- Tail(next_state);
                }
            }

            actor Beta owns BoardState {
                entry advance() emits next: Tail {
                    BoardState next_state = BoardState { ply: ply + 2 };
                    unrestricted(next.value);
                    become next <- Tail(next_state);
                }
            }

            actor Tail owns BoardState {
                entry hold() emits none { require(ply >= 0); }
            }

            actor Extra owns BoardState {
                entry hold() emits none { require(ply >= 1); }
            }

            app Test {
                actor Mux;
                actor Alpha;
                actor Beta;
                actor Tail;
                actor Extra;
            }
        "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let leaf = |actor: &str| CommitmentNode::Leaf { actor: actor.to_string() };
    let cut = |paths: &[&[usize]]| paths.iter().map(|path| NodePath::new(path.to_vec())).collect::<Cut>();
    // Default selector cohorts align these cuts; inject a valid asymmetric
    // plan to exercise the canonical named-type fallback.
    let crafted_plan = RoutePlan {
        families: vec![FamilyPlan {
            domain: "BoardState".to_string(),
            rep: "Mux".to_string(),
            members: ["Mux", "Alpha", "Beta", "Tail"].into_iter().map(str::to_string).collect(),
            gates: vec!["Mux".to_string()],
            table: ["Alpha", "Beta"].into_iter().map(str::to_string).collect(),
        }],
        commitments: CommitmentPlan {
            forest: CommitmentForest {
                roots: vec![
                    leaf("Mux"),
                    CommitmentNode::Branch { children: vec![leaf("Alpha"), leaf("Beta")] },
                    leaf("Tail"),
                    leaf("Extra"),
                ],
            },
            cuts: BTreeMap::from([
                ("Mux".to_string(), cut(&[&[1, 0], &[1, 1], &[2], &[3]])),
                ("Alpha".to_string(), cut(&[&[1, 0], &[1, 1], &[2]])),
                ("Beta".to_string(), cut(&[&[1, 0], &[1, 1], &[2]])),
                ("Tail".to_string(), Cut::new()),
                ("Extra".to_string(), Cut::new()),
            ]),
        },
    };
    let injected_planner = move |_graph: &RouteGraph,
                                 _domains: &BTreeMap<String, Vec<String>>,
                                 selectors: &[SelectorRequirement]|
          -> crate::error::Result<RoutePlan> {
        assert_eq!(selectors.len(), 1);
        Ok(crafted_plan.clone())
    };
    let model = Model::from_program_with_route_planner(&program, &injected_planner).expect("non-active selector plans");
    let mux = model.actor("Mux").expect("Mux exists");
    let choose = mux.entries.iter().find(|entry| entry.name == "choose").expect("choose entry exists");
    let selector = model
        .entry_model(mux, choose)
        .expect("entry model exists")
        .template_selectors()
        .get("target")
        .expect("target selector exists");
    let output = plan_selector_output_state(mux, selector, &model).expect("selector output state plans");

    assert!(matches!(output.canonical_target(), PhysicalTargetId::Actor(actor) if actor.actor() == "Alpha"));
    assert_eq!(output.physical_type(), "Gen__AlphaState");
    let actor_sil = actor_sil_for_model(&model);
    let mux_sil = &actor_sil["Mux"];
    assert!(mux_sil.contains("struct Gen__AlphaState {"), "{mux_sil}");
    assert!(!mux_sil.contains("struct Gen__BetaState {"), "{mux_sil}");
    assert!(mux_sil.contains("Gen__AlphaState gen__state_next_gen__alpha_state"), "{mux_sil}");
    emit_artifact(&program, &model, &actor_sil).expect("canonical selector output type compiles");
}

#[test]
fn expanded_actor_records_sil_and_capsule_template_cuts() {
    let (sil, artifact) = emit_fixture("capsule_route_context", "ReserveAsset");
    let (wallet_sil, _) = emit_fixture("capsule_route_context", "WalletAsset");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/capsule_route_context/ReserveAsset.sil"));
    assert_eq!(wallet_sil, include_str!("../../../../tests/fixtures/emit/capsule_route_context/WalletAsset.sil"));
    assert!(sil.contains("byte[32] gen__wallet_asset_template"), "{sil}");
    assert!(sil.contains("ReserveAssetState next_asset = ReserveAssetState {"), "{sil}");
    assert!(sil.contains("validateOutputState(gen__next_output_idx, gen__state_next_state);"), "{sil}");
    assert!(sil.contains("validateOutputStateWithTemplate("), "{sil}");

    // Migration debt: exact continuation is still recognized from the
    // exact-successor route intent.
    assert!(wallet_sil.contains("tx.outputs[gen__next_output_idx].scriptPubKey"), "{wallet_sil}");
    assert!(wallet_sil.contains("== tx.inputs[this.activeInputIndex].scriptPubKey"), "{wallet_sil}");
    assert!(!wallet_sil.contains("validateOutputState"), "{wallet_sil}");

    let contract = artifact.sil_abi.contract("ReserveAsset").expect("ReserveAsset Sil ABI exists");
    assert_eq!(
        contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["gen__reserve_asset_template", "gen__wallet_asset_template", "owner_kind", "owner_id", "policy", "balance"]
    );
    assert_eq!(encode_hex(&contract.compiled.template_hash), "627db2b04fa0d951683831303996ca6cd1c4ababec8bdf59546a57afe3f02206");
    let wallet_contract = artifact.sil_abi.contract("WalletAsset").expect("WalletAsset Sil ABI exists");
    assert_eq!(
        wallet_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["gen__reserve_asset_template", "gen__wallet_asset_template", "owner_kind", "owner_id", "policy", "balance"]
    );
    assert_eq!(
        encode_hex(&wallet_contract.compiled.template_hash),
        "7fcc79baaa34f0dce572b2d915ddd4697b487baab7f53d1e930d6aac0d82fedc"
    );

    let source_state =
        artifact.argent.states.iter().find(|state| state.name == "ReserveAssetState").expect("ReserveAssetState exists");
    assert_eq!(
        source_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["owner_kind", "owner_id", "policy", "balance"]
    );
    assert!(source_state.fields[2].virtual_slot);

    let wallet_actor = artifact.argent.actors.iter().find(|actor| actor.name == "WalletAsset").expect("WalletAsset actor exists");
    let hold = wallet_actor.entries.iter().find(|entry| entry.name == "hold").expect("WalletAsset hold entry exists");
    assert!(matches!(hold.routes[0].successor, RouteSuccessorArtifact::ExactSelf));

    let runtime_plan = runtime_state_plan(&artifact, "ReserveAsset").expect("route context is recorded");
    assert_eq!(
        runtime_plan.field_roles.iter().map(|field| (field.name.as_str(), field.role.clone())).collect::<Vec<_>>(),
        [
            ("gen__reserve_asset_template", RuntimeFieldRoleArtifact::Template { contract: "ReserveAsset".to_string() },),
            ("gen__wallet_asset_template", RuntimeFieldRoleArtifact::Template { contract: "WalletAsset".to_string() },),
        ]
    );
    assert_eq!(
        runtime_state_plan(&artifact, "WalletAsset")
            .expect("WalletAsset route context is recorded")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        [
            ("gen__reserve_asset_template", RuntimeFieldRoleArtifact::Template { contract: "ReserveAsset".to_string() },),
            ("gen__wallet_asset_template", RuntimeFieldRoleArtifact::Template { contract: "WalletAsset".to_string() },),
        ]
    );
    let receipt = artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|template| template.actor == "ReserveAsset")
        .expect("ReserveAsset template receipt exists");
    assert_eq!(receipt.sil_template_hash, contract.compiled.template_hash);
    let handle = &receipt.actor_type_handle;
    assert_eq!(handle.state, "AssetCapsule");
    assert_eq!(handle.context_fields, runtime_plan.field_roles.iter().map(|field| field.name.clone()).collect::<Vec<_>>());
    assert_ne!(handle.template.hash, receipt.sil_template_hash);

    let sil_template = extract_sil_template(&contract.compiled).expect("Sil template extracts");
    let sil_prefix = &sil_template.prefix;
    let capsule_prefix = &handle.template.prefix;
    assert!(capsule_prefix.starts_with(sil_prefix));
    assert!(capsule_prefix.len() > sil_prefix.len());
    assert_eq!(handle.template.suffix, sil_template.suffix);
    artifact.check_template_plan_consistency().expect("capsule template receipt verifies");

    // A direct template role always stores one fixed-width template hash.
    let mut dynamic_template_field = artifact.clone();
    let contract = dynamic_template_field.sil_abi.contracts.get_mut("ReserveAsset").expect("ReserveAsset Sil ABI exists");
    contract
        .runtime_state
        .fields
        .iter_mut()
        .find(|field| field.name == "gen__reserve_asset_template")
        .expect("template context field exists")
        .ty = TypeArtifact::Bytes;
    let err = dynamic_template_field.check_template_plan_consistency().expect_err("dynamic template context is rejected");
    assert!(
        matches!(err, TemplatePlanError::RuntimeStatePlanMismatch { ref contract, .. } if contract == "ReserveAsset"),
        "unexpected error: {err}"
    );
    assert!(err.to_string().contains("must have type `byte[32]`"), "unexpected error: {err}");

    let mut corrupted = artifact.clone();
    let receipt = corrupted
        .argent
        .template_plan
        .templates
        .iter_mut()
        .find(|template| template.actor == "ReserveAsset")
        .expect("ReserveAsset template receipt exists");
    let handle = &mut receipt.actor_type_handle;
    let mut prefix = handle.template.prefix.clone();
    *prefix.last_mut().expect("capsule prefix contains context") ^= 1;
    handle.template.prefix = prefix.clone();
    let suffix = handle.template.suffix.clone();
    handle.template.hash = silverscript_lang::template::template_hash(&prefix, &suffix);
    let err = corrupted.check_template_plan_consistency().expect_err("corrupted capsule context is rejected");
    assert!(matches!(err, TemplatePlanError::ActorTypeHandleMismatch { .. }), "unexpected error: {err}");

    let mut corrupted = artifact.clone();
    let handle = corrupted
        .argent
        .template_plan
        .templates
        .iter_mut()
        .find(|template| template.actor == "ReserveAsset")
        .map(|template| &mut template.actor_type_handle)
        .expect("ReserveAsset capsule handle exists");
    let prefix = handle.template.prefix.clone();
    let context = &prefix[sil_prefix.len()..];
    let first_push_end = 1 + context[0] as usize;
    assert!(first_push_end <= context.len(), "test context starts with one direct data push");
    let mut noncanonical_prefix = prefix[..sil_prefix.len()].to_vec();
    noncanonical_prefix.extend_from_slice(&[OpPushData1, context[0]]);
    noncanonical_prefix.extend_from_slice(&context[1..first_push_end]);
    noncanonical_prefix.extend_from_slice(&context[first_push_end..]);
    let suffix = handle.template.suffix.clone();
    handle.template.prefix = noncanonical_prefix.clone();
    handle.template.hash = silverscript_lang::template::template_hash(&noncanonical_prefix, &suffix);
    let err = corrupted.check_template_plan_consistency().expect_err("non-canonical capsule context is rejected");
    assert!(matches!(err, TemplatePlanError::ActorTypeHandleMismatch { .. }), "unexpected error: {err}");

    let mut corrupted = artifact.clone();
    let capsule =
        corrupted.argent.states.iter_mut().find(|state| state.name == "AssetCapsule").expect("AssetCapsule Argent layout exists");
    capsule.fields.last_mut().expect("AssetCapsule has fields").ty = TypeArtifact::Bool;
    let err = corrupted.check_template_plan_consistency().expect_err("capsule state layout mismatch is rejected");
    assert!(matches!(err, TemplatePlanError::ActorTypeHandleMismatch { .. }), "unexpected error: {err}");

    let mut corrupted = artifact.clone();
    let handle = corrupted
        .argent
        .template_plan
        .templates
        .iter_mut()
        .find(|template| template.actor == "ReserveAsset")
        .map(|template| &mut template.actor_type_handle)
        .expect("ReserveAsset capsule handle exists");
    handle.template.hash = [0; 32];
    let err = corrupted.check_template_plan_consistency().expect_err("corrupted capsule hash is rejected");
    assert!(matches!(err, TemplatePlanError::ActorTypeHandleMismatch { .. }), "unexpected error: {err}");
}

#[test]
fn state_expansion_requires_virtual_byte32_backing_field() {
    let err = parse_and_validate(
        r#"
            state AgentCapsule {
                byte[32] strategy;
            }

            state ForagerStrategy {
                int hunger;
            }

            state ForagerState expands AgentCapsule {
                strategy: ForagerStrategy;
            }

            actor Forager owns ForagerState {}

            app Test {
                actor Forager;
            }
            "#,
    )
    .expect_err("non-digest backing field must be rejected");

    assert!(err.to_string().contains("expanded slots must be virtual"), "unexpected error: {err}");
}

#[test]
fn state_expansion_slots_require_typed_payload_constructors() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state AgentCapsule {
                virtual strategy;
            }

            state ForagerStrategy {
                int hunger;
            }

            state ForagerState expands AgentCapsule {
                strategy: ForagerStrategy;
            }

            actor Forager owns ForagerState {
                entry step() emits next: Forager {
                    unrestricted(next.value);
                    ForagerState next_state = {
                        strategy: {
                            hunger: strategy.hunger + 1,
                        },
                    };

                    become next <- Forager(next_state);
                }
            }

            app Test {
                actor Forager;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor("Forager").expect("Forager actor exists");
    let err = emit_actor(actor, &model).expect_err("anonymous virtual slot payload must be rejected");

    assert!(err.to_string().contains("must use `ForagerStrategy { ... }`"), "unexpected error: {err}");
}

#[test]
fn builds_examples_with_compiled_artifacts() {
    assert_example_build_artifact(
        "examples/tickets.ag",
        "tickets",
        &[
            ("Issuer", "a6af0ca5bff28389fd687b7ca8ac8cf0dd270276927037a9f212a3ea8ff27166"),
            ("Ticket", "0480dbcb791c1d53b7f4668bf684c14be77fd7cf4ee02e49c9f9f2528e2fbd3e"),
        ],
    );
    assert_example_build_artifact("examples/stones/app.ag", "stones", &[]);
    assert_example_build_artifact("examples/icc/kcc20_asset.ag", "icc-kcc20-asset", &[]);
    assert_example_build_artifact("examples/icc/minter.ag", "icc-minter", &[]);
}

#[test]
fn observes_blocks_are_recorded_in_artifact() {
    let artifact = inline_artifact(
        "icc-observes",
        r#"
            state KCC20State {
                int amount;
            }

            state MinterProxyState {
                byte[32] controller_id;
            }

            state MinterState {
                cov_id kcc20_covid;
                int amount;
            }

            actor KCC20 owns KCC20State {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor MinterProxy owns MinterProxyState {
                entry hold() emits none {
                    require(controller_id == controller_id);
                }
            }

            actor Minter owns MinterState {
                entry mint(int minted_amount)
                observes asset by self.kcc20_covid {
                    inputs {
                        proxy: MinterProxy,
                    }

                    outputs {
                        proxy: MinterProxy,
                        recipient: KCC20,
                    }
                }
                emits {
                    controller: Minter,
                } {
                    unrestricted(controller.value);
                    MinterState next_minter = {
                        kcc20_covid: kcc20_covid,
                        amount: amount - minted_amount,
                    };

                    become controller <- Minter(next_minter);
                }
            }

            app Test {
                actor KCC20;
                actor Minter;
                actor MinterProxy;
            }
            "#,
    );

    let minter = artifact.argent.actors.iter().find(|actor| actor.name == "Minter").expect("Minter actor exists");
    let mint = minter.entries.iter().find(|entry| entry.name == "mint").expect("mint entry exists");

    assert_eq!(mint.observes.len(), 1);
    let observe = &mint.observes[0];
    assert_eq!(observe.name, "asset");
    assert_eq!(observe.covenant_expr, "self.kcc20_covid");
    assert_eq!(observe.covenant_id_source, CovenantIdSourceArtifact::StateField { field: "kcc20_covid".to_string() });
    assert_eq!(observe.inputs[0].name, "proxy");
    assert!(matches!(
        &observe.inputs[0].target,
        ObservedTargetArtifact::StaticActor { app, actor } if app == "Test" && actor == "MinterProxy"
    ));
    assert_eq!(observe.outputs[0].name, "proxy");
    assert!(matches!(
        &observe.outputs[0].target,
        ObservedTargetArtifact::StaticActor { app, actor } if app == "Test" && actor == "MinterProxy"
    ));
    assert_eq!(observe.outputs[1].name, "recipient");
    assert!(matches!(
        &observe.outputs[1].target,
        ObservedTargetArtifact::StaticActor { app, actor } if app == "Test" && actor == "KCC20"
    ));
    assert_eq!(
        mint.hidden_params.iter().map(|param| (param.name.as_str(), &param.subject, param.purpose)).collect::<Vec<_>>(),
        vec![
            (
                "gen__kcc20_prefix",
                &HiddenParamSubjectArtifact::Actor { actor: "KCC20".to_string() },
                HiddenParamPurposeArtifact::TemplatePrefixBytes,
            ),
            (
                "gen__kcc20_suffix",
                &HiddenParamSubjectArtifact::Actor { actor: "KCC20".to_string() },
                HiddenParamPurposeArtifact::TemplateSuffixBytes,
            ),
            (
                "gen__minter_proxy_prefix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "MinterProxy".to_string() },
                HiddenParamPurposeArtifact::TemplatePrefixLen,
            ),
            (
                "gen__minter_proxy_suffix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "MinterProxy".to_string() },
                HiddenParamPurposeArtifact::TemplateSuffixLen,
            ),
        ]
    );
    assert_eq!(
        mint.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "witness/kcc20/template_prefix_bytes",
            "witness/kcc20/template_suffix_bytes",
            "witness/minter_proxy/template_prefix_len",
            "witness/minter_proxy/template_suffix_len",
        ]
    );
    assert_eq!(
        runtime_state_plan(&artifact, "Minter")
            .expect("Minter runtime role overlay exists")
            .field_roles
            .iter()
            .map(|role| (role.name.as_str(), role.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__kcc20_template", RuntimeFieldRoleArtifact::Template { contract: "KCC20".to_string() },),
            ("gen__minter_proxy_template", RuntimeFieldRoleArtifact::Template { contract: "MinterProxy".to_string() },),
        ]
    );
}

#[test]
fn observe_entry_argument_source_is_recorded_by_index() {
    let artifact = inline_artifact(
        "observe-entry-argument",
        r#"
            state ForeignState {
                int count;
            }
            state LocalState {
                int marker;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step(int unused, cov_id target_id)
                observes asset by target_id {
                    inputs {
                        foreign: Foreign,
                    }
                }
                emits none {
                    require(unused >= 0);
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    );

    let local = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local actor exists");
    let step = local.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
    assert_eq!(step.observes[0].covenant_id_source, CovenantIdSourceArtifact::EntryArgument { index: 1 });
}

#[test]
fn observe_covenant_id_source_rejects_computed_expressions() {
    let err = parse_and_validate(
        r#"
            state LocalState {}

            actor Local owns LocalState {
                entry step(cov_id first, cov_id second)
                observes asset by first + second {}
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Local;
            }
            "#,
    )
    .expect_err("computed observe covenant ids must be rejected");

    assert!(
        err.to_string().contains("covenant id source must be a `self.<field>` state field or entry argument of type `cov_id`"),
        "unexpected error: {err}"
    );
}

#[test]
fn observe_covenant_id_source_requires_cov_id_type() {
    let err = parse_and_validate(
        r#"
            state LocalState {
                byte[32] target_id;
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {}
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Local;
            }
            "#,
    )
    .expect_err("byte arrays must not stand in for covenant ids");

    assert!(err.to_string().contains("has type `byte[32]`; expected `cov_id`"), "unexpected error: {err}");
}

#[test]
fn observe_covenant_id_state_fields_require_self() {
    let err = parse_and_validate(
        r#"
            state LocalState {
                cov_id target_id;
            }

            actor Local owns LocalState {
                entry step()
                observes asset by target_id {}
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Local;
            }
            "#,
    )
    .expect_err("bare observe covenant state fields must be rejected");

    assert!(err.to_string().contains("state field `target_id` must be referenced as `self.target_id`"), "unexpected error: {err}");
}

#[test]
fn observed_actor_type_state_fields_require_self() {
    let err = parse_and_validate(
        r#"
            state ForeignState {}
            state LocalState {
                cov_id target_id;
                actor_type<ForeignState> foreign_type;
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    inputs {
                        foreign: foreign_type,
                    }
                }
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Local;
            }
            "#,
    )
    .expect_err("bare observed actor-type state fields must be rejected");

    assert!(
        err.to_string().contains("state field `foreign_type` must be referenced as `self.foreign_type`"),
        "unexpected error: {err}"
    );
}

#[test]
fn spawned_actor_type_state_fields_require_self() {
    let err = parse_and_validate(
        r#"
            state PairState {}
            state LauncherState {
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch()
                spawns pair by pair_id {
                    outputs {
                        next_pair: pair_type,
                    }
                }
                emits none {
                    unrestricted(pair.outputs.next_pair.value);
                    require(1 == 1);
                }
            }

            app Test {
                actor Launcher;
            }
            "#,
    )
    .expect_err("bare spawned actor-type state fields must be rejected");

    assert!(err.to_string().contains("state field `pair_type` must be referenced as `self.pair_type`"), "unexpected error: {err}");
}

#[test]
fn observed_actor_type_sources_have_distinct_witness_names() {
    let artifact = inline_artifact(
        "observed-actor-type-sources",
        r#"
            state RemoteState {
                int value;
            }
            state LocalState {
                cov_id remote_id;
                actor_type<RemoteState> target;
            }

            actor Local owns LocalState {
                entry inspect(actor_type<RemoteState> self_target)
                observes remote by self.remote_id {
                    inputs {
                        stored: self.target,
                        argument: self_target,
                    }
                }
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Local;
            }
            "#,
    );

    let inspect = artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "inspect").expect("inspect entry exists");
    assert_eq!(
        inspect.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec![
            "gen__actor_type_self_target_prefix_len",
            "gen__actor_type_self_target_suffix_len",
            "gen__actor_type_arg_self_target_prefix_len",
            "gen__actor_type_arg_self_target_suffix_len",
        ]
    );
}

#[test]
fn observed_slots_lower_to_foreign_state_checks() {
    let out_dir = std::env::temp_dir().join(format!("argent-icc-observed-input-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    crate::build_file("examples/icc/minter.ag", &out_dir).expect("ICC example builds");

    let minter_sil = fs::read_to_string(out_dir.join("sil/Minter.sil")).expect("Minter.sil exists");
    assert!(minter_sil.contains("byte[32] constant gen__kcc20_asset__kcc20_template_const = byte[32](0x"), "{minter_sil}");
    assert!(minter_sil.contains("entry mint(\n"), "{minter_sil}");
    assert!(minter_sil.contains("sig owner_sig,"), "{minter_sil}");
    assert!(minter_sil.contains("byte[32] recipient_owner,"), "{minter_sil}");
    assert!(minter_sil.contains("int gen__kcc20_asset__minter_proxy_prefix_len,"), "{minter_sil}");
    assert!(minter_sil.contains("byte[] gen__kcc20_asset__kcc20_suffix"), "{minter_sil}");
    assert!(
        minter_sil.contains("byte[32] gen__kcc20_asset__minter_proxy_template = gen__kcc20_asset__minter_proxy_template_const;"),
        "{minter_sil}"
    );
    assert!(!minter_sil.contains("gen__init_kcc20_asset__"), "{minter_sil}");
    assert!(minter_sil.contains("struct MinterProxyState"), "{minter_sil}");
    assert!(minter_sil.contains("struct KCC20State"), "{minter_sil}");
    assert!(minter_sil.contains("byte[32] gen__asset_cov_id = kcc20_covid; // observe asset"), "{minter_sil}");
    assert!(minter_sil.contains("require(OpCovInputCount(gen__asset_cov_id) == 1);"), "{minter_sil}");
    assert!(minter_sil.contains("require(OpCovOutputCount(gen__asset_cov_id) == 2);"), "{minter_sil}");
    assert!(!minter_sil.contains("gen__kcc20_asset__minter_proxy_prefix.length"), "{minter_sil}");
    assert!(!minter_sil.contains("gen__kcc20_asset__minter_proxy_suffix.length"), "{minter_sil}");
    assert!(minter_sil.contains("MinterProxyState gen__asset_proxy_state = readInputStateWithTemplate("), "{minter_sil}");
    assert!(minter_sil.contains("gen__asset_proxy_input_idx,"), "{minter_sil}");
    assert!(minter_sil.contains("gen__kcc20_asset__minter_proxy_template"), "{minter_sil}");
    assert!(minter_sil.contains("// :: observed output asset.proxy: KCC20Asset::MinterProxy"), "{minter_sil}");
    assert!(minter_sil.contains("int gen__asset_proxy_output_idx = OpCovOutputIdx(gen__asset_cov_id, 0);"), "{minter_sil}");
    assert!(minter_sil.contains("// :: observed output asset.recipient: KCC20Asset::KCC20"), "{minter_sil}");
    assert!(minter_sil.contains("int gen__asset_recipient_output_idx = OpCovOutputIdx(gen__asset_cov_id, 1);"), "{minter_sil}");
    assert!(minter_sil.contains("validateOutputStateWithInputTemplate(\n            gen__asset_proxy_output_idx,"), "{minter_sil}");
    assert!(minter_sil.contains("gen__asset_proxy_input_idx,"), "{minter_sil}");
    assert!(minter_sil.contains("validateOutputStateWithTemplate(\n            gen__asset_recipient_output_idx,"), "{minter_sil}");
    assert!(minter_sil.contains("gen__kcc20_asset__kcc20_template"), "{minter_sil}");
    assert!(minter_sil.contains("MinterProxyState prev_proxy = gen__asset_proxy_state;"), "{minter_sil}");

    let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
    let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");
    artifact.check_template_plan_consistency().expect("observed witness receipts verify");

    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn icc_asset_lowers_cov_id_co_spend_and_else_if() {
    let out_dir = std::env::temp_dir().join(format!("argent-icc-asset-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    let program = crate::compiler::loader::load_program(Path::new("examples/icc/kcc20_asset.ag")).expect("ICC asset app loads");
    emit_build(&program, &out_dir).expect("ICC asset app builds");

    let kcc20_sil = fs::read_to_string(out_dir.join("sil/KCC20.sil")).expect("KCC20.sil exists");
    assert!(kcc20_sil.contains("} else if (identifier_type == IDENTIFIER_COVENANT_ID) {"), "{kcc20_sil}");
    assert!(kcc20_sil.contains("require(checkSig(owner_sig, pubkey(owner_identifier)));"), "{kcc20_sil}");
    assert!(kcc20_sil.contains("// :: co-spent with owner_identifier"), "{kcc20_sil}");
    assert!(kcc20_sil.contains("require(OpCovInputCount(owner_identifier) > 0);"), "{kcc20_sil}");
    assert!(!kcc20_sil.contains("KCC20State"), "{kcc20_sil}");
    assert!(kcc20_sil.contains("State next_state = State {"), "{kcc20_sil}");
    assert!(kcc20_sil.contains("validateOutputState(gen__next_output_idx, next_state);"), "{kcc20_sil}");

    let proxy_sil = fs::read_to_string(out_dir.join("sil/MinterProxy.sil")).expect("MinterProxy.sil exists");
    assert!(proxy_sil.contains("byte[32] controller_id = init_controller_id;"), "{proxy_sil}");
    assert!(proxy_sil.contains("entry mint(\n        MinterProxyState next_proxy,"), "{proxy_sil}");
    assert!(proxy_sil.contains("gen__kcc20_template: gen__kcc20_template"), "{proxy_sil}");
    assert!(proxy_sil.contains("controller_id: next_proxy.controller_id"), "{proxy_sil}");
    assert!(proxy_sil.contains("// :: co-spent with controller_id"), "{proxy_sil}");
    assert!(proxy_sil.contains("require(OpCovInputCount(controller_id) > 0);"), "{proxy_sil}");

    let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
    let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");
    let proxy_entry =
        artifact.sil_abi.contract("MinterProxy").expect("MinterProxy ABI exists").entry("mint").expect("mint ABI exists");
    assert_eq!(proxy_entry.params[0].name, "next_proxy");
    assert_eq!(proxy_entry.params[0].ty, TypeArtifact::Struct { name: "MinterProxyState".to_string() });

    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn lowers_co_spend_and_output_value_in_the_same_expression() {
    let source = r#"
            state CounterState {
                cov_id guard;
            }

            actor Counter owns CounterState {
                entry bump() emits next: Counter {
                    require(guard.co_spent() && next.value >= 0);
                    become next <- self;
                }
            }

            app Test {
                actor Counter;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Counter").expect("actor exists"), &model).expect("actor emits");

    assert!(sil.contains("require(OpCovInputCount(guard) > 0 && tx.outputs[gen__next_output_idx].value >= 0);"), "{sil}");
}

#[test]
fn rejects_co_spent_on_non_cov_id_value() {
    let out_dir = std::env::temp_dir().join(format!("argent-co-spent-type-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state FooState {
                byte[32] id;
            }

            actor Foo owns FooState {
                entry hold() emits none {
                    require(id.co_spent());
                }
            }

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };

    let err = emit_build(&program, &out_dir).expect_err("non-covenant-id co-spend must be rejected");
    assert!(err.to_string().contains(&format!("only available on `{}` values", word::COVENANT_ID)), "unexpected error: {err}");

    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn rejects_duplicate_observe_names() {
    let err = parse_and_validate(
        r#"
            state ForeignState {}
            state LocalState {
                cov_id target_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    inputs {
                        foreign: Foreign,
                    }
                }
                observes asset by self.target_id {
                    outputs {
                        foreign: Foreign,
                    }
                }
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    )
    .expect_err("duplicate observe names must be rejected");

    assert!(err.to_string().contains("declares observe `asset` more than once"), "unexpected error: {err}");
}

#[test]
fn rejects_duplicate_observed_handles() {
    let err = parse_and_validate(
        r#"
            state ForeignState {}
            state LocalState {
                cov_id target_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    inputs {
                        foreign: Foreign,
                        foreign: Foreign,
                    }
                }
                emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    )
    .expect_err("duplicate observed handles must be rejected");

    assert!(err.to_string().contains("observe `asset` declares input `foreign` more than once"), "unexpected error: {err}");
}

#[test]
fn in_app_observed_templates_use_shared_actor_witnesses() {
    let (sil, artifact) = emit_fixture("observed_template_witnesses", "Local");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/observed_template_witnesses/Local.sil"));
    assert!(sil.contains("ForeignState gen__asset_src_state = readInputStateWithTemplate("), "{sil}");
    assert!(sil.contains("validateOutputStateWithInputTemplate("), "{sil}");

    let foreign_state = artifact.argent.states.iter().find(|state| state.name == "ForeignState").expect("ForeignState exists");
    assert_eq!(foreign_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["count"]);
    let local_state = artifact.argent.states.iter().find(|state| state.name == "LocalState").expect("LocalState exists");
    assert_eq!(local_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["target_id"]);

    let foreign_contract = artifact.sil_abi.contract("Foreign").expect("Foreign contract exists");
    assert_eq!(foreign_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["count"]);
    assert_eq!(
        encode_hex(&foreign_contract.compiled.template_hash),
        "464dd0aa5c6a60a35f5a1f3e54be4822991b4578cfe58e5a266cb8650e524c94"
    );
    let local_contract = artifact.sil_abi.contract("Local").expect("Local contract exists");
    assert_eq!(
        local_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["gen__foreign_template", "target_id"]
    );
    assert_eq!(encode_hex(&local_contract.compiled.template_hash), "ed3b4d44f4911b5dc91a4ad26acb9bb1d61526f3082e976b1de506969dccf81d");

    assert_eq!(
        runtime_state_plan(&artifact, "Local")
            .expect("Local runtime state role overlay exists")
            .field_roles
            .iter()
            .map(|role| (role.name.as_str(), role.role.clone()))
            .collect::<Vec<_>>(),
        vec![("gen__foreign_template", RuntimeFieldRoleArtifact::Template { contract: "Foreign".to_string() },)]
    );

    let local_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local artifact actor exists");
    let step = local_actor.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
    assert_eq!(step.observes[0].covenant_id_source, CovenantIdSourceArtifact::StateField { field: "target_id".to_string() });
    assert_eq!(
        step.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec!["gen__foreign_prefix_len", "gen__foreign_suffix_len"]
    );
    assert_eq!(
        step.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["witness/foreign/template_prefix_len", "witness/foreign/template_suffix_len",]
    );
}

#[test]
fn in_app_observe_preserves_observed_route_context() {
    let (local_sil, artifact) = emit_fixture("in_app_observe_routes", "Local");
    let (foreign_sil, _) = emit_fixture("in_app_observe_routes", "Foreign");
    let (target_sil, _) = emit_fixture("in_app_observe_routes", "Target");

    assert_eq!(local_sil, include_str!("../../../../tests/fixtures/emit/in_app_observe_routes/Local.sil"));
    assert_eq!(foreign_sil, include_str!("../../../../tests/fixtures/emit/in_app_observe_routes/Foreign.sil"));
    assert_eq!(target_sil, include_str!("../../../../tests/fixtures/emit/in_app_observe_routes/Target.sil"));
    assert!(local_sil.contains("function foreign_identity(ForeignState value) : ForeignState"), "{local_sil}");
    assert!(local_sil.contains("ForeignState next_foreign = foreign_identity(ForeignState {"), "{local_sil}");

    assert_eq!(
        runtime_state_plan(&artifact, "Foreign")
            .expect("Foreign runtime state role overlay exists")
            .field_roles
            .iter()
            .map(|role| (role.name.as_str(), role.role.clone()))
            .collect::<Vec<_>>(),
        vec![("gen__target_template", RuntimeFieldRoleArtifact::Template { contract: "Target".to_string() },)]
    );
    assert_eq!(
        runtime_state_plan(&artifact, "Local")
            .expect("Local runtime state role overlay exists")
            .field_roles
            .iter()
            .map(|role| (role.name.as_str(), role.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__foreign_template", RuntimeFieldRoleArtifact::Template { contract: "Foreign".to_string() },),
            ("gen__target_template", RuntimeFieldRoleArtifact::Template { contract: "Target".to_string() },),
        ]
    );

    let foreign_template =
        artifact.argent.template_plan.templates.iter().find(|template| template.actor == "Foreign").expect("Foreign template exists");
    assert_eq!(foreign_template.actor_type_handle.context_fields, vec!["gen__target_template"]);

    let local_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local actor exists");
    let step = local_actor.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
    assert_eq!(
        step.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec!["gen__foreign_prefix_len", "gen__foreign_suffix_len"]
    );
}

#[test]
fn consumed_route_reuses_input_template() {
    let (sil, artifact) = emit_fixture("input_template_route_reuse", "Controller");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/input_template_route_reuse/Controller.sil"));
    assert!(sil.contains("PeerState gen__peer_state = readInputStateWithTemplate("), "{sil}");
    assert!(sil.contains("validateOutputStateWithInputTemplate("), "{sil}");

    let controller_state =
        artifact.argent.states.iter().find(|state| state.name == "ControllerState").expect("ControllerState exists");
    assert_eq!(controller_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["tick"]);
    let peer_state = artifact.argent.states.iter().find(|state| state.name == "PeerState").expect("PeerState exists");
    assert_eq!(peer_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["count"]);

    let controller_contract = artifact.sil_abi.contract("Controller").expect("Controller contract exists");
    assert_eq!(
        controller_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
        ["gen__peer_template", "tick"]
    );
    assert_eq!(
        encode_hex(&controller_contract.compiled.template_hash),
        "3091c3cb1b9eac52e3f7be3661e80720b5d2be1c0b9569e76f440a493ce53413"
    );
    let peer_contract = artifact.sil_abi.contract("Peer").expect("Peer contract exists");
    assert_eq!(peer_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["count"]);
    assert_eq!(encode_hex(&peer_contract.compiled.template_hash), "7cbdc27a4fffbaad655bcd7565a7d85682469203db07d26b953f665640f4271f");

    assert_eq!(
        runtime_state_plan(&artifact, "Controller")
            .expect("Controller runtime state role overlay exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        [("gen__peer_template", RuntimeFieldRoleArtifact::Template { contract: "Peer".to_string() })]
    );

    let controller = artifact.argent.actors.iter().find(|actor| actor.name == "Controller").expect("Controller actor exists");
    let step = controller.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
    assert_eq!(
        step.hidden_params.iter().map(|param| (param.name.as_str(), param.purpose)).collect::<Vec<_>>(),
        vec![
            ("gen__peer_prefix_len", HiddenParamPurposeArtifact::TemplatePrefixLen),
            ("gen__peer_suffix_len", HiddenParamPurposeArtifact::TemplateSuffixLen),
        ]
    );
    assert_eq!(
        step.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["witness/peer/template_prefix_len", "witness/peer/template_suffix_len"]
    );
}

#[test]
fn single_actor_self_consume_is_pinned() {
    let (sil, artifact) = emit_fixture("single_actor_self_consume", "Counter");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/single_actor_self_consume/Counter.sil"));
    assert!(sil.contains("State gen__other_state = readInputState(gen__other_input_idx);"), "{sil}");
    assert!(!sil.contains("readInputStateWithTemplate"), "{sil}");
    assert!(!sil.contains("CounterState"), "{sil}");
    assert!(sil.contains("State copied = actor_identity(global_identity(gen__other_state));"), "{sil}");
    assert_eq!(sil.matches("actor_identity(global_identity(").count(), 1, "{sil}");
    assert!(sil.contains("copied = global_identity(gen__other_state);"), "{sil}");
    assert!(sil.contains("validateOutputState(gen__next_output_idx, next_state);"), "{sil}");

    let source_state = artifact.argent.states.iter().find(|state| state.name == "CounterState").expect("CounterState exists");
    assert_eq!(source_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["count"]);
    let contract = artifact.sil_abi.contract("Counter").expect("Counter contract exists");
    assert_eq!(contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["count"]);
    assert_eq!(encode_hex(&contract.compiled.template_hash), "7e3775a25b2ed4594671eb43b72ca5389252ec0a11f3f0b8b255f91d7851e44a");
    let template = artifact
        .argent
        .template_plan
        .templates
        .iter()
        .find(|template| template.actor == "Counter")
        .expect("Counter template receipt exists");
    assert!(template.actor_type_handle.context_fields.is_empty());
    assert_eq!(template.sil_template_hash, contract.compiled.template_hash);

    let counter = artifact.argent.actors.iter().find(|actor| actor.name == "Counter").expect("Counter actor exists");
    let merge = counter.entries.iter().find(|entry| entry.name == "merge").expect("merge entry exists");
    assert!(merge.hidden_params.is_empty());
    assert!(merge.route_plan.witness_recipe_ids.is_empty());
    assert!(runtime_state_plan(&artifact, "Counter").is_none());
}

#[test]
fn ranged_current_inputs_lower_to_a_pinned_input_reference_cache() {
    let (sil, artifact) = emit_fixture("entry_range_inputs", "Batch");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/entry_range_inputs/Batch.sil"));
    assert_fixture_artifact("entry_range_inputs", &artifact);
    let batch = artifact.argent.actors.iter().find(|actor| actor.name == "Batch").expect("Batch actor exists");
    assert_eq!(batch.entries[0].consumes[1].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 3 });
    assert_eq!(batch.entries[0].route_plan.consumes.iter().map(|input| input.cov_index).collect::<Vec<_>>(), [Some(1), None, None]);
}

#[test]
fn ranged_output_uses_planned_context_instead_of_same_actor_input_fields() {
    let sil = emit_inline_actor(
        r#"
            state BatchState {}
            state AccountState { int balance; }

            actor enum AccountRoute {
                Account;
                Frozen;
            }

            actor Batch owns BatchState {
                entry rebalance()
                consumes { accounts: Account[1..=2], }
                emits { next: Account[1..=2], } {
                    AccountState[] next_states;
                    AccountState next_state = { balance: accounts[0].balance + accounts.length, };
                    next_states = next_states.append(next_state);
                    unrestricted(next[0].value);
                    become next <- Account[](next_states);
                }
            }

            actor Account owns AccountState {
                entry reroute(AccountRoute target) emits next: AccountRoute {
                    AccountState next_state = { balance: balance, };
                    unrestricted(next.value);
                    become next <- target(next_state);
                }
            }

            actor Frozen owns AccountState {
                entry hold() emits none { require(balance >= 0); }
            }

            app Test { actor Batch; actor Account; actor Frozen; }
        "#,
        "Batch",
    );

    assert!(sil.contains("Gen__AccountState gen__accounts_state = readInputStateWithTemplate("), "{sil}");
    assert!(sil.contains("AccountState[] gen__accounts_authored_states;"), "{sil}");
    assert!(!sil.contains("gen__accounts_count == gen__next_output_count"), "independent ranges must not be equated:\n{sil}");
    assert!(!sil.contains("_physical_values"), "ranged outputs must not inherit same-actor input context:\n{sil}");
    assert!(
        sil.contains("gen__account_routes: byte[64](gen__account_template + gen__frozen_template),"),
        "ranged outputs must materialize the compiler-planned target context:\n{sil}"
    );
}

#[test]
fn ranged_current_outputs_lower_to_a_pinned_validation_loop() {
    let (sil, artifact) = emit_fixture("entry_range_outputs", "Batch");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/entry_range_outputs/Batch.sil"));
    assert_fixture_artifact("entry_range_outputs", &artifact);
    let batch = artifact.argent.actors.iter().find(|actor| actor.name == "Batch").expect("Batch actor exists");
    let EmitArtifact::Outputs { outputs } = &batch.entries[0].emits else {
        panic!("Batch::distribute emits outputs");
    };
    assert_eq!(outputs[1].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 3 });
    assert_eq!(outputs.iter().map(|output| output.auth_index).collect::<Vec<_>>(), [Some(0), None, None]);
    assert_eq!(batch.entries[0].route_plan.outputs.iter().map(|output| output.auth_index).collect::<Vec<_>>(), [Some(0), None, None]);

    let manifest = emit_fixture_manifest("entry_range_outputs");
    let manifest_batch = manifest["actors"]
        .as_array()
        .expect("manifest actors are an array")
        .iter()
        .find(|actor| actor["name"] == "Batch")
        .expect("Batch manifest actor exists");
    let entry = &manifest_batch["entries"][0];
    let manifest_outputs = entry["emits"]["outputs"].as_array().expect("manifest outputs are an array");
    assert_eq!(manifest_outputs[0]["auth_index"], serde_json::json!(0));
    assert!(manifest_outputs[1]["auth_index"].is_null());
    assert!(manifest_outputs[2]["auth_index"].is_null());
    assert_eq!(manifest_outputs[1]["cardinality"], serde_json::json!({ "kind": "range", "minimum": 1, "maximum": 3 }));
    let range_route = entry["routes"]
        .as_array()
        .expect("manifest routes are an array")
        .iter()
        .find(|route| route["output"] == "next")
        .expect("range output route exists");
    assert_eq!(range_route["successor"]["arity"], "many");
}

#[test]
fn ranged_inputs_and_outputs_lower_to_pinned_optional_template_paths() {
    let (sil, artifact) = emit_fixture("entry_range_inputs_outputs", "Batch");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/entry_range_inputs_outputs/Batch.sil"));
    assert_fixture_artifact("entry_range_inputs_outputs", &artifact);
    let batch = artifact.argent.actors.iter().find(|actor| actor.name == "Batch").expect("Batch actor exists");
    let entry = &batch.entries[0];
    assert_eq!(entry.consumes[0].cardinality, CardinalityArtifact::Range { minimum: 0, maximum: 2 });
    let EmitArtifact::Outputs { outputs } = &entry.emits else {
        panic!("Batch::rebalance emits outputs");
    };
    assert_eq!(outputs[0].cardinality, CardinalityArtifact::Range { minimum: 1, maximum: 3 });
}

#[test]
fn nonempty_input_range_can_authenticate_an_output_template() {
    let sil = emit_inline_actor(
        r#"
            const int MAX_ACCOUNTS = 2;
            state BatchState {}
            state AccountState {}

            actor Batch owns BatchState {
                entry rebalance()
                consumes {
                    accounts: Account[1..=MAX_ACCOUNTS],
                }
                emits {
                    next: Account[1..=MAX_ACCOUNTS],
                } {
                    AccountState[] next_states;
                    for (i, 0, accounts.length, MAX_ACCOUNTS) {
                        next_states = next_states.append(AccountState {});
                    }
                    unrestricted(next[0].value);
                    become next <- Account[](next_states);
                }
            }

            actor Account owns AccountState {}
            app Test { actor Batch; actor Account; }
        "#,
        "Batch",
    );

    assert!(
        sil.contains("OpCovInputIdx(gen__cov_id, 1),\n                gen__account_prefix_len"),
        "the guaranteed first range input was not reused:\n{sil}"
    );
}

#[test]
fn singleton_input_can_authenticate_a_template_also_used_by_an_optional_range() {
    let sil = emit_inline_actor(
        r#"
            const int MAX_ACCOUNTS = 2;
            state BatchState {}
            state AccountState {}

            actor Batch owns BatchState {
                entry rebalance()
                consumes {
                    accounts: Account[0..=MAX_ACCOUNTS],
                    anchor: Account,
                }
                emits {
                    next: Account[1..=MAX_ACCOUNTS],
                } {
                    AccountState[] next_states;
                    next_states = next_states.append(state(anchor));
                    unrestricted(next[0].value);
                    become next <- Account[](next_states);
                }
            }

            actor Account owns AccountState {}
            app Test { actor Batch; actor Account; }
        "#,
        "Batch",
    );

    assert!(sil.contains("int gen__account_prefix_len"), "full template bytes were requested unnecessarily:\n{sil}");
    assert!(
        sil.contains("gen__anchor_input_idx,\n                gen__account_prefix_len"),
        "the guaranteed singleton input was not reused:\n{sil}"
    );
}

#[test]
fn selected_app_actor_count_controls_self_consume_template_authentication() {
    let path = PathBuf::from("multi_actor_self_consume.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state CounterState {
                int count;
            }

            state GuardState {
                int marker;
            }

            actor Counter owns CounterState {
                entry merge()
                consumes {
                    other: Counter,
                }
                emits next: Counter {
                    unrestricted(next.value);
                    CounterState next_state = {
                        count: count + other.count,
                    };

                    become next <- Counter(next_state);
                }
            }

            actor Guard owns GuardState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            app Single {
                actor Counter;
            }

            app Multi {
                actor Counter;
                actor Guard;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let multi_model = Model::from_program_app(&program, "Multi").expect("multi-actor model validates");
    let counter = multi_model.actor("Counter").expect("Counter actor exists");
    let sil = emit_actor(counter, &multi_model).expect("Counter emits for the multi-actor app");
    let actor_sil = actor_sil_for_model(&multi_model);
    let artifact = emit_artifact(&program, &multi_model, &actor_sil).expect("multi-actor artifact emits");

    assert!(sil.contains("State gen__other_state = readInputStateWithTemplate("), "{sil}");
    assert!(!sil.contains("// :: direct input state"), "{sil}");
    let counter = artifact.argent.actors.iter().find(|actor| actor.name == "Counter").expect("Counter actor exists");
    let merge = counter.entries.iter().find(|entry| entry.name == "merge").expect("merge entry exists");
    assert_eq!(
        merge.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec!["gen__counter_prefix_len", "gen__counter_suffix_len"]
    );
    assert_eq!(
        merge.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["witness/counter/template_prefix_len", "witness/counter/template_suffix_len"]
    );
    assert!(runtime_state_plan(&artifact, "Counter").is_some());

    let single_model = Model::from_program_app(&program, "Single").expect("single-actor model validates");
    let counter = single_model.actor("Counter").expect("Counter actor exists");
    let sil = emit_actor(counter, &single_model).expect("Counter emits for the single-actor app");
    let actor_sil = actor_sil_for_model(&single_model);
    let artifact = emit_artifact(&program, &single_model, &actor_sil).expect("single-actor artifact emits");

    assert!(sil.contains("State gen__other_state = readInputState(gen__other_input_idx);"), "{sil}");
    assert!(!sil.contains("readInputStateWithTemplate"), "{sil}");
    assert!(runtime_state_plan(&artifact, "Counter").is_none());
}

#[test]
fn unselected_actors_do_not_shape_selected_app_state() {
    let path = PathBuf::from("app_state_isolation.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state SharedState {
                int count;
            }

            state TargetState {
                int marker;
            }

            actor Current owns SharedState {
                entry step() emits next: Current {
                    unrestricted(next.value);
                    become next <- self;
                }
            }

            actor Outside owns SharedState {
                entry step() emits next: Target {
                    unrestricted(next.value);
                    TargetState next_state = {
                        marker: 0,
                    };
                    become next <- Target(next_state);
                }
            }

            actor Target owns TargetState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            app CurrentApp {
                actor Current;
            }

            app OtherApp {
                actor Outside;
                actor Target;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program_app(&program, "CurrentApp").expect("selected app model validates");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("selected app artifact emits");
    let template =
        artifact.argent.template_plan.templates.iter().find(|template| template.actor == "Current").expect("Current template exists");

    assert!(runtime_state_plan(&artifact, "Current").is_none());
    assert!(template.actor_type_handle.context_fields.is_empty());
    assert_eq!(template.actor_type_handle.template.hash, template.sil_template_hash);
}

#[test]
fn open_observed_actor_binding_lowers_to_runtime_template_handle() {
    let (sil, artifact) = emit_fixture("open_observed_actor_binding", "Cell");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/open_observed_actor_binding/Cell.sil"));

    assert!(runtime_state_plan(&artifact, "Cell").is_none(), "{:#?}", artifact.argent.template_plan.runtime_states);

    let cell_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Cell").expect("Cell artifact actor exists");
    let advance = cell_actor.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
    let observe = advance.observes.first().expect("advance observes remote");
    assert_eq!(observe.inputs[0].target, ObservedTargetArtifact::DynamicActor { state: "AgentCapsule".to_string() });
    assert_eq!(observe.outputs[0].target, ObservedTargetArtifact::DynamicActor { state: "AgentCapsule".to_string() });
    assert_eq!(
        advance.hidden_params.iter().map(|param| (param.name.as_str(), param.purpose)).collect::<Vec<_>>(),
        vec![
            ("gen__remote_observed_agent_prefix_len", HiddenParamPurposeArtifact::TemplatePrefixLen),
            ("gen__remote_observed_agent_suffix_len", HiddenParamPurposeArtifact::TemplateSuffixLen),
            ("gen__remote_observed_agent_template", HiddenParamPurposeArtifact::TemplateHash),
        ]
    );
}

#[test]
fn open_observed_state_handle_lowers_to_source_actor_type() {
    let (sil, artifact) = emit_fixture("open_observed_state_handle", "Cell");

    assert_eq!(sil, include_str!("../../../../tests/fixtures/emit/open_observed_state_handle/Cell.sil"));

    assert!(runtime_state_plan(&artifact, "Cell").is_none(), "{:#?}", artifact.argent.template_plan.runtime_states);

    let cell_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Cell").expect("Cell artifact actor exists");
    let advance = cell_actor.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
    let observe = advance.observes.first().expect("advance observes remote");
    assert_eq!(observe.inputs[0].target, ObservedTargetArtifact::DynamicActor { state: "AgentCapsule".to_string() });
    assert_eq!(observe.outputs[0].target, ObservedTargetArtifact::DynamicActor { state: "AgentCapsule".to_string() });
    assert_eq!(
        advance.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec!["gen__actor_type_self_agent_type_prefix_len", "gen__actor_type_self_agent_type_suffix_len"]
    );
}

#[test]
fn rejects_input_only_open_observed_actor_binding() {
    let err = parse_and_validate(
        r#"
            state AgentCapsule {
                int energy;
            }

            state CellState {
                cov_id agent_covid;
            }

            actor Cell owns CellState {
                entry inspect()
                observes remote by self.agent_covid {
                    inputs {
                        agent: actor_type<AgentCapsule> as observed_agent,
                    }
                }
                emits none {
                    AgentCapsule prev_state = state(remote.inputs.agent);
                    require(prev_state.energy >= 0);
                }
            }

            app Test {
                actor Cell;
            }
            "#,
    )
    .expect_err("input-only open observed binding must be rejected");

    assert!(
        err.to_string().contains("open observed actor binding `observed_agent` must be used by an output"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_missing_observed_output_become_coverage() {
    let err = emit_inline_error(
        r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                cov_id target_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    outputs {
                        a: Foreign,
                        b: Foreign,
                    }
                }
                emits none {
                    ForeignState next = {
                        amount: 1,
                    };

                    require asset.outputs become {
                        a <- Foreign(next),
                    };
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    );

    assert!(err.to_string().contains("observe `asset` does not validate output `b`"), "unexpected error: {err}");
}

#[test]
fn rejects_semicolons_in_observed_become_route_lists() {
    let err = parse_and_validate(
        r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                cov_id target_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    outputs {
                        a: Foreign,
                        b: Foreign,
                    }
                }
                emits none {
                    ForeignState next = {
                        amount: 1,
                    };

                    require asset.outputs become {
                        a <- Foreign(next);
                        b <- Foreign(next);
                    };
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    )
    .expect_err("semicolon-separated output routes must not parse");

    assert!(err.to_string().contains("expected `,` or `}`"), "unexpected error: {err}");
}

#[test]
fn rejects_observed_output_become_actor_mismatch() {
    let err = emit_inline_error(
        r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                cov_id target_id;
            }

            actor ForeignA owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor ForeignB owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    outputs {
                        next: ForeignA,
                    }
                }
                emits none {
                    ForeignState next_state = {
                        amount: 1,
                    };

                    require asset.outputs become {
                        next <- ForeignB(next_state),
                    };
                }
            }

            app Test {
                actor ForeignA;
                actor ForeignB;
                actor Local;
            }
            "#,
    );

    assert!(
        err.to_string().contains("observe `asset` output `next` expects `ForeignA`, but route uses `ForeignB`"),
        "unexpected error: {err}"
    );
}

#[test]
fn stones_delegate_reads_use_length_only_template_witnesses() {
    let out_dir = std::env::temp_dir().join(format!("argent-stones-length-witness-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    let program = crate::compiler::loader::load_program(Path::new("examples/stones/app.ag")).expect("stones example loads");
    emit_build(&program, &out_dir).expect("stones example builds");
    let player_sil = fs::read_to_string(out_dir.join("sil/Player.sil")).expect("Player.sil exists");
    let league_sil = fs::read_to_string(out_dir.join("sil/League.sil")).expect("League.sil exists");
    let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
    let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");

    assert!(player_sil.contains("entry accept_start(\n"), "{player_sil}");
    assert!(player_sil.contains("sig owner_sig,"), "{player_sil}");
    assert!(player_sil.contains("pubkey owner_pk,"), "{player_sil}");
    assert!(player_sil.contains("int gen__player_prefix_len,"), "{player_sil}");
    assert!(player_sil.contains("int gen__player_suffix_len"), "{player_sil}");
    assert!(!player_sil.contains("entry accept_start(sig owner_sig, pubkey owner_pk, byte[]"), "{player_sil}");
    assert!(player_sil.contains("entry start_game(\n"), "{player_sil}");
    assert!(player_sil.contains("int gen__player_prefix_len,"), "{player_sil}");
    assert!(player_sil.contains("byte[] gen__stones_game_prefix,"), "{player_sil}");
    assert!(player_sil.contains("byte[] gen__stones_game_suffix"), "{player_sil}");
    assert!(!player_sil.contains("byte[] gen__player_prefix"), "{player_sil}");
    assert!(player_sil.contains("byte[32] gen__init_player_template"), "{player_sil}");
    assert!(player_sil.contains("byte[32] gen__init_stones_game_template"), "{player_sil}");
    assert!(player_sil.contains("byte[32] gen__init_stones_settle_template"), "{player_sil}");
    assert!(player_sil.contains("byte[32] gen__player_template = gen__init_player_template;"), "{player_sil}");
    assert!(player_sil.contains("byte[32] gen__stones_game_template = gen__init_stones_game_template;"), "{player_sil}");
    assert!(!player_sil.contains("gen__template_root"), "{player_sil}");
    assert!(!player_sil.contains("gen__player_template_proof"), "{player_sil}");
    assert!(
        !player_sil.contains("gen__template_table") && !player_sil.contains("gen__init_template_table"),
        "ordinary direct-template state should not store a packed table: {player_sil}"
    );
    assert!(
        !player_sil.contains("byte[32][]") && !player_sil.contains("byte[][]"),
        "template roots/proofs should use fixed bytes, not nested arrays: {player_sil}"
    );
    assert!(
        !player_sil.contains("gen__league_template"),
        "Player route-family template root should not carry unrelated League template: {player_sil}"
    );
    assert!(player_sil.contains("PlayerState next_self = PlayerState {"), "{player_sil}");
    assert!(player_sil.contains("PlayerState next_opponent = PlayerState {"), "{player_sil}");
    assert!(player_sil.contains("validateOutputState(gen__self_out_output_idx, gen__state_self_out_state);"), "{player_sil}");
    assert!(player_sil.contains("validateOutputState(gen__opponent_out_output_idx, gen__state_opponent_out_state);"), "{player_sil}");
    assert!(player_sil.contains("validateOutputStateWithTemplate(\n            gen__game_output_idx,"), "{player_sil}");
    assert!(league_sil.contains("entry register_player(\n"), "{league_sil}");
    assert!(league_sil.contains("byte[] gen__player_prefix,"), "{league_sil}");
    assert!(league_sil.contains("byte[] gen__player_suffix"), "{league_sil}");
    assert!(!league_sil.contains("gen__league_prefix"), "{league_sil}");
    assert!(league_sil.contains("tx.outputs[gen__league_output_idx].scriptPubKey"), "{league_sil}");
    assert!(league_sil.contains("== tx.inputs[this.activeInputIndex].scriptPubKey"), "{league_sil}");
    assert!(league_sil.contains("validateOutputStateWithTemplate(\n            gen__player_output_idx,"), "{league_sil}");

    let player_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Player").expect("Player actor exists");
    let accept_start = player_actor.entries.iter().find(|entry| entry.name == "accept_start").expect("accept_start ABI exists");
    assert_eq!(accept_start.hidden_params.len(), 2);
    assert_eq!(accept_start.hidden_params[0].name, "gen__player_prefix_len");
    assert_eq!(accept_start.hidden_params[0].ty, TypeArtifact::Int);
    assert_eq!(subject_label(&accept_start.hidden_params[0].subject), "Player");
    assert_eq!(accept_start.hidden_params[0].purpose, HiddenParamPurposeArtifact::TemplatePrefixLen);
    assert_eq!(accept_start.hidden_params[1].name, "gen__player_suffix_len");
    assert_eq!(accept_start.hidden_params[1].ty, TypeArtifact::Int);
    assert_eq!(subject_label(&accept_start.hidden_params[1].subject), "Player");
    assert_eq!(accept_start.hidden_params[1].purpose, HiddenParamPurposeArtifact::TemplateSuffixLen);

    let start_game = player_actor.entries.iter().find(|entry| entry.name == "start_game").expect("start_game ABI exists");
    assert_eq!(
        start_game
            .hidden_params
            .iter()
            .map(|param| (param.name.as_str(), param.ty.clone(), subject_label(&param.subject), param.purpose))
            .collect::<Vec<_>>(),
        vec![
            ("gen__player_prefix_len", TypeArtifact::Int, "Player", HiddenParamPurposeArtifact::TemplatePrefixLen),
            ("gen__player_suffix_len", TypeArtifact::Int, "Player", HiddenParamPurposeArtifact::TemplateSuffixLen),
            ("gen__stones_game_prefix", TypeArtifact::Bytes, "StonesGame", HiddenParamPurposeArtifact::TemplatePrefixBytes),
            ("gen__stones_game_suffix", TypeArtifact::Bytes, "StonesGame", HiddenParamPurposeArtifact::TemplateSuffixBytes),
        ]
    );

    let player_contract = artifact.sil_abi.contract("Player").expect("Player Sil ABI contract exists");
    let player_runtime_plan = runtime_state_plan(&artifact, "Player").expect("Player runtime role overlay exists");
    assert_eq!(player_contract.runtime_state.fields[0].name, "gen__player_template");
    assert_eq!(player_contract.runtime_state.fields[0].ty, TypeArtifact::FixedBytes { len: 32 });
    assert_eq!(player_runtime_plan.field_roles[0].role, RuntimeFieldRoleArtifact::Template { contract: "Player".to_string() });
    assert_eq!(player_contract.runtime_state.fields[1].name, "gen__stones_game_template");
    assert_eq!(player_runtime_plan.field_roles[1].role, RuntimeFieldRoleArtifact::Template { contract: "StonesGame".to_string() });
    assert_eq!(player_contract.runtime_state.fields[2].name, "gen__stones_settle_template");
    assert_eq!(player_runtime_plan.field_roles[2].role, RuntimeFieldRoleArtifact::Template { contract: "StonesSettle".to_string() });
    assert!(artifact.argent.template_plan.route_tables.is_empty());
    assert!(artifact.argent.template_plan.route_proofs.is_empty());
    let sil_accept_start = player_contract.entry("accept_start").expect("accept_start Sil ABI entry exists");
    assert_eq!(
        sil_accept_start.params.iter().map(|param| (param.name.as_str(), param.ty.clone())).collect::<Vec<_>>(),
        vec![
            ("owner_sig", TypeArtifact::Sig),
            ("owner_pk", TypeArtifact::Pubkey),
            ("gen__player_prefix_len", TypeArtifact::Int),
            ("gen__player_suffix_len", TypeArtifact::Int),
        ]
    );

    let league_actor = artifact.argent.actors.iter().find(|actor| actor.name == "League").expect("League actor exists");
    let register_player = league_actor.entries.iter().find(|entry| entry.name == "register_player").expect("register_player exists");
    assert_eq!(
        register_player
            .hidden_params
            .iter()
            .map(|param| (param.name.as_str(), param.ty.clone(), subject_label(&param.subject), param.purpose))
            .collect::<Vec<_>>(),
        vec![
            ("gen__player_prefix", TypeArtifact::Bytes, "Player", HiddenParamPurposeArtifact::TemplatePrefixBytes),
            ("gen__player_suffix", TypeArtifact::Bytes, "Player", HiddenParamPurposeArtifact::TemplateSuffixBytes),
        ]
    );
    let _ = fs::remove_dir_all(out_dir);
}

#[test]
fn compiler_lowers_injected_deep_forest_cuts() {
    use crate::routing::{CommitmentForest, CommitmentPlan, Cut, FamilyPlan, NodePath, RoutePlan};

    fn leaf(actor: &str) -> CommitmentNode {
        CommitmentNode::Leaf { actor: actor.to_string() }
    }

    fn cut(paths: &[&[usize]]) -> Cut {
        paths.iter().map(|path| NodePath::new(path.to_vec())).collect()
    }

    let source = r#"
            state SourceState {
                int amount;
            }

            state SharedState {
                int amount;
            }

            state TailState {
                int amount;
            }

            actor Source owns SourceState {
                entry start() emits next: HubA {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 1 };
                    become next <- HubA(next_state);
                }
            }

            actor HubA owns SharedState {
                entry advance() emits next: A1 {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 1 };
                    become next <- A1(next_state);
                }
            }

            actor A1 owns SharedState {
                entry advance() emits next: A2 {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 1 };
                    become next <- A2(next_state);
                }
            }

            actor A2 owns SharedState {
                entry cross() emits next: HubB {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 1 };
                    become next <- HubB(next_state);
                }
            }

            actor HubB owns SharedState {
                entry advance() emits next: B1 {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 1 };
                    become next <- B1(next_state);
                }

                entry rewind() emits next: A1 {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 1 };
                    become next <- A1(next_state);
                }
            }

            actor B1 owns SharedState {
                entry advance() emits next: B2 {
                    unrestricted(next.value);
                    SharedState next_state = { amount: amount + 2 };
                    become next <- B2(next_state);
                }
            }

            actor B2 owns SharedState {
                entry finish() emits next: Tail {
                    unrestricted(next.value);
                    TailState next_state = { amount: amount + 1 };
                    become next <- Tail(next_state);
                }
            }

            actor Tail owns TailState {
                entry finish() emits none {
                    require(amount >= 0);
                }
            }

            app DeepForest {
                actor Source;
                actor HubA;
                actor A1;
                actor A2;
                actor HubB;
                actor B1;
                actor B2;
                actor Tail;
            }
        "#;
    let path = PathBuf::from("deep-forest.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("deep-forest app parses");
    let program = Program { root: path, modules: vec![module] };

    // The useful family branches live four levels below the forest root.
    // Wrapper branches are deliberately absent from every partial cut;
    // cuts mix packed families, opened family leaves, and a retained leaf.
    let forest = CommitmentForest {
        roots: vec![CommitmentNode::Branch {
            children: vec![
                leaf("Source"),
                CommitmentNode::Branch {
                    children: vec![CommitmentNode::Branch {
                        children: vec![
                            CommitmentNode::Branch { children: vec![leaf("HubA"), leaf("A1"), leaf("A2")] },
                            leaf("Tail"),
                            CommitmentNode::Branch { children: vec![leaf("HubB"), leaf("B1"), leaf("B2")] },
                        ],
                    }],
                },
            ],
        }],
    };
    let packed = cut(&[&[0, 1, 0, 0], &[0, 1, 0, 1], &[0, 1, 0, 2]]);
    let family_a_open = cut(&[&[0, 1, 0, 0, 0], &[0, 1, 0, 0, 1], &[0, 1, 0, 0, 2], &[0, 1, 0, 1], &[0, 1, 0, 2]]);
    let family_b_open = cut(&[&[0, 1, 0, 0], &[0, 1, 0, 1], &[0, 1, 0, 2, 0], &[0, 1, 0, 2, 1], &[0, 1, 0, 2, 2]]);
    let commitments = CommitmentPlan {
        forest,
        cuts: BTreeMap::from([
            ("Source".to_string(), packed),
            ("HubA".to_string(), family_a_open.clone()),
            ("A1".to_string(), family_a_open.clone()),
            ("A2".to_string(), family_a_open),
            ("HubB".to_string(), family_b_open.clone()),
            ("B1".to_string(), family_b_open.clone()),
            ("B2".to_string(), family_b_open),
            ("Tail".to_string(), Cut::new()),
        ]),
    };
    let crafted_plan = RoutePlan {
        families: vec![
            FamilyPlan {
                domain: "SharedState".to_string(),
                rep: "HubA".to_string(),
                members: ["HubA", "A1", "A2"].into_iter().map(str::to_string).collect(),
                gates: vec!["HubA".to_string()],
                table: ["HubA", "A1", "A2"].into_iter().map(str::to_string).collect(),
            },
            FamilyPlan {
                domain: "SharedState".to_string(),
                rep: "HubB".to_string(),
                members: ["HubB", "B1", "B2"].into_iter().map(str::to_string).collect(),
                gates: vec!["HubB".to_string()],
                table: ["HubB", "B1", "B2"].into_iter().map(str::to_string).collect(),
            },
        ],
        commitments,
    };
    assert!(crafted_plan.commitments.cuts.values().all(|cut| crafted_plan.commitments.forest.is_valid_cut(cut)));
    let cross = crafted_plan.commitments.cut_transition("A2", "HubB").expect("cross-family cut is derivable");
    assert_eq!(cross.branches_to_open.len(), 1);
    assert_eq!(cross.branches_to_pack.len(), 1);

    let injected_planner = move |_graph: &RouteGraph, domains: &BTreeMap<String, Vec<String>>, selectors: &[SelectorRequirement]| {
        assert_eq!(domains["SharedState"], ["HubA", "A1", "A2", "HubB", "B1", "B2"]);
        assert!(selectors.is_empty());
        Ok(crafted_plan.clone())
    };
    let model = Model::from_program_with_route_planner(&program, &injected_planner).expect("injected route plan validates");

    let family_a_id = "route_family/SharedState/hub_a".to_string();
    let family_b_id = "route_family/SharedState/hub_b".to_string();
    assert_eq!(
        model.route_transitions[&("A2".to_string(), "HubB".to_string())],
        CompilerRouteTransition { families_to_open: vec![family_b_id], families_to_pack: vec![family_a_id] }
    );

    let actor_sil = actor_sil_for_model(&model);
    let a2_sil = &actor_sil["A2"];
    assert!(a2_sil.contains("byte[96] gen__hub_b_routes"), "{a2_sil}");
    assert!(a2_sil.contains("gen__hub_a_routes_digest: blake3(byte[](gen__hub_a_routes)),"), "{a2_sil}");
    let hub_b_sil = &actor_sil["HubB"];
    assert!(hub_b_sil.contains("byte[96] gen__hub_a_routes"), "{hub_b_sil}");
    assert!(hub_b_sil.contains("gen__hub_b_routes_digest: blake3(byte[](gen__hub_b_routes)),"), "{hub_b_sil}");

    let artifact = emit_artifact(&program, &model, &actor_sil).expect("deep-forest artifact emits");
    artifact.check_template_plan_consistency().expect("deep-forest template plan verifies");
    assert_eq!(artifact.argent.template_plan.route_families.len(), 2);
}

#[test]
fn shared_state_actors_retain_distinct_transitive_cuts() {
    let path = PathBuf::from("actor-route-cuts.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state SharedState {
                int amount;
            }

            state MiddleState {
                int amount;
            }

            state TailState {
                int amount;
            }

            actor A owns SharedState {
                entry leave() emits next: Middle {
                    unrestricted(next.value);
                    MiddleState next_middle = {
                        amount: amount,
                    };
                    become next <- Middle(next_middle);
                }
            }

            actor B owns SharedState {}

            actor Middle owns MiddleState {
                entry leave() emits next: Tail {
                    unrestricted(next.value);
                    TailState next_tail = {
                        amount: amount,
                    };
                    become next <- Tail(next_tail);
                }
            }

            actor Tail owns TailState {}

            app ActorRouteCuts {
                actor A;
                actor B;
                actor Middle;
                actor Tail;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };

    let model = Model::from_program(&program).expect("model retains the planned actor cuts");

    assert_eq!(
        model.route_leaves_by_actor["A"],
        [RouteRootLeaf::Actor("Middle".to_string()), RouteRootLeaf::Actor("Tail".to_string())]
    );
    assert!(model.route_leaves_by_actor["B"].is_empty());

    let a_generated = model
        .state_lowering("A")
        .expect("A has a state lowering")
        .active()
        .physical()
        .fields()
        .iter()
        .filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_)))
        .map(|field| field.sil_name())
        .collect::<Vec<_>>();
    assert_eq!(a_generated, ["gen__middle_template", "gen__tail_template"]);
    assert!(
        model
            .state_lowering("B")
            .expect("B has a state lowering")
            .active()
            .physical()
            .fields()
            .iter()
            .all(|field| matches!(field.id(), PhysicalFieldId::Storage(_)))
    );

    let actor_a = model.actor("A").expect("A exists");
    let actor_b = model.actor("B").expect("B exists");
    let a_sil = emit_actor(actor_a, &model).expect("A Sil emits");
    let b_sil = emit_actor(actor_b, &model).expect("B Sil emits");
    let middle_sil = emit_actor(model.actor("Middle").expect("Middle exists"), &model).expect("Middle Sil emits");
    let shared_layout = middle_sil
        .split("struct SharedState {")
        .nth(1)
        .and_then(|rest| rest.split("    }").next())
        .expect("plain SharedState layout exists");
    assert!(!shared_layout.contains("gen__"), "{middle_sil}");
    assert!(a_sil.contains("byte[32] gen__init_middle_template"), "{a_sil}");
    assert!(a_sil.contains("byte[32] gen__middle_template = gen__init_middle_template;"), "{a_sil}");
    assert!(a_sil.contains("byte[32] gen__tail_template = gen__init_tail_template;"), "{a_sil}");
    assert!(!b_sil.contains("gen__middle_template"), "{b_sil}");
    assert!(!b_sil.contains("gen__tail_template"), "{b_sil}");
    assert_eq!(
        runtime_state_fields_for_actor(actor_a, &model)
            .expect("A runtime fields lower")
            .into_iter()
            .map(|field| field.name)
            .collect::<Vec<_>>(),
        ["gen__middle_template", "gen__tail_template", "amount"]
    );
    assert_eq!(
        runtime_state_fields_for_actor(actor_b, &model)
            .expect("B runtime fields lower")
            .into_iter()
            .map(|field| field.name)
            .collect::<Vec<_>>(),
        ["amount"]
    );
}

#[test]
fn foreign_routes_materialize_the_target_actors_cut() {
    let source = r#"
            state SourceState {
                int amount;
            }

            state SharedState {
                int amount;
            }

            state TailAState {
                int amount;
            }

            state TailBState {
                int amount;
            }

            actor Source owns SourceState {
                entry send() emits next: A {
                    unrestricted(next.value);
                    SharedState next_state = {
                        amount: amount,
                    };
                    become next <- A(next_state);
                }
            }

            actor A owns SharedState {
                entry leave() emits next: TailA {
                    unrestricted(next.value);
                    TailAState next_state = {
                        amount: amount,
                    };
                    become next <- TailA(next_state);
                }
            }

            actor B owns SharedState {
                entry leave() emits next: TailB {
                    unrestricted(next.value);
                    TailBState next_state = {
                        amount: amount + 1,
                    };
                    become next <- TailB(next_state);
                }
            }

            actor TailA owns TailAState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor TailB owns TailBState {
                entry hold() emits none {
                    require(amount >= 1);
                }
            }

            app ForeignActorCuts {
                actor Source;
                actor A;
                actor B;
                actor TailA;
                actor TailB;
            }
        "#;

    let path = PathBuf::from("foreign-actor-cuts.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let source_sil = emit_actor(model.actor("Source").expect("Source exists"), &model).expect("Source Sil emits");

    let actor_layout = source_sil
        .split("struct Gen__AState {")
        .nth(1)
        .and_then(|rest| rest.split("    }").next())
        .expect("A receives an actor-qualified foreign state layout");
    assert!(actor_layout.contains("byte[32] gen__tail_a_template;"), "{source_sil}");
    assert!(!actor_layout.contains("gen__tail_b_template"), "{source_sil}");
    assert!(source_sil.contains("SharedState next_state = SharedState {"), "{source_sil}");
    assert!(source_sil.contains("Gen__AState gen__state_next_gen__a_state = Gen__AState {"), "{source_sil}");
    assert!(source_sil.contains("amount: next_state.amount,"), "{source_sil}");
    assert!(source_sil.contains("gen__tail_a_template: gen__tail_a_template,"), "{source_sil}");
    assert!(!source_sil.contains("gen__tail_b_template:"), "{source_sil}");

    inline_artifact("foreign-actor-cuts", source);
}

#[test]
fn typed_actor_layouts_distinguish_local_tables_from_foreign_commitments() {
    let path = PathBuf::from("actor-route-field-kinds.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), toy_chess_source()).expect("toy chess source parses");
    let program = Program { root: path, modules: vec![module] };

    let model = Model::from_program(&program).expect("toy chess model validates");

    let mux_fields = model
        .state_lowering("Mux")
        .expect("Mux has a state lowering")
        .active()
        .physical()
        .fields()
        .iter()
        .filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_)))
        .collect::<Vec<_>>();
    assert_eq!(mux_fields.iter().map(|field| field.sil_name()).collect::<Vec<_>>(), ["gen__mux_template", "gen__mux_routes"]);
    assert!(matches!(
        mux_fields.as_slice(),
        [template, table]
            if matches!(template.id(), PhysicalFieldId::Generated(GeneratedFieldId::Template(actor)) if actor.actor() == "Mux")
                && matches!(table.id(), PhysicalFieldId::Generated(GeneratedFieldId::RouteFamilyTable { family, .. }) if family == "route_family/BoardState/mux")
    ));

    let player_fields = model
        .state_lowering("Player")
        .expect("Player has a state lowering")
        .active()
        .physical()
        .fields()
        .iter()
        .filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_)))
        .collect::<Vec<_>>();
    assert_eq!(
        player_fields.iter().map(|field| field.sil_name()).collect::<Vec<_>>(),
        ["gen__mux_template", "gen__mux_routes_digest"]
    );
    assert!(matches!(
        player_fields.as_slice(),
        [
            template,
            digest,
        ] if matches!(template.id(), PhysicalFieldId::Generated(GeneratedFieldId::Template(actor)) if actor.actor() == "Mux")
            && matches!(digest.id(), PhysicalFieldId::Generated(GeneratedFieldId::RouteFamilyDigest { family, .. }) if family == "route_family/BoardState/mux")
    ));

    assert_eq!(
        model.route_transitions[&("Player".to_string(), "Mux".to_string())],
        CompilerRouteTransition { families_to_open: vec!["route_family/BoardState/mux".to_string()], families_to_pack: Vec::new() }
    );
}

#[test]
fn family_table_witnesses_follow_cut_transitions() {
    let path = PathBuf::from("transition-family-witnesses.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), toy_chess_source()).expect("toy chess source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("toy chess model validates");

    let player = model.actor("Player").expect("Player exists");
    let enter_mux = player.entries.iter().find(|entry| entry.name == "enter_mux").expect("enter_mux exists");
    assert_eq!(
        entry_witness_specs(player, enter_mux, &model).expect("enter_mux witnesses lower").families,
        [RouteFamilyWitnessSpec { family_id: "route_family/BoardState/mux".to_string(), byte_len: 64 }]
    );

    let mux = model.actor("Mux").expect("Mux exists");
    let choose_pawn = mux.entries.iter().find(|entry| entry.name == "choose_pawn").expect("choose_pawn exists");
    assert!(entry_witness_specs(mux, choose_pawn, &model).expect("choose_pawn witnesses lower").families.is_empty());

    let read_only_mux = template_witness_specs_for_actor(player, &model, BTreeSet::from(["Mux".to_string()]), BTreeSet::new());
    assert!(read_only_mux.families.is_empty());
}

#[test]
fn in_app_observed_output_opens_the_target_family_cut() {
    let artifact = inline_artifact(
        "in-app-observed-family",
        r#"
            state ObserverState {
                cov_id game_id;
                int steps;
            }

            state BoardState {
                int turn;
            }

            actor Observer owns ObserverState {
                entry advance()
                observes game by self.game_id {
                    outputs {
                        mux: Mux,
                    }
                }
                emits next: Observer {
                    unrestricted(next.value);
                    BoardState board = { turn: 0 };
                    require game.outputs become {
                        mux <- Mux(board),
                    };
                    ObserverState next_state = {
                        game_id: game_id,
                        steps: steps + 1,
                    };
                    become next <- Observer(next_state);
                }
            }

            actor Mux owns BoardState {
                entry move() emits next: Pawn {
                    unrestricted(next.value);
                    BoardState next_state = { turn: turn + 1 };
                    become next <- Pawn(next_state);
                }
            }

            actor Pawn owns BoardState {
                entry finish() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_state = { turn: turn + 1 };
                    become next <- Mux(next_state);
                }
            }

            actor Knight owns BoardState {
                entry finish() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_state = { turn: turn + 2 };
                    become next <- Mux(next_state);
                }
            }

            app Test {
                actor Observer;
                actor Mux;
                actor Pawn;
                actor Knight;
            }
            "#,
    );

    let observer = artifact.argent.actors.iter().find(|actor| actor.name == "Observer").expect("Observer artifact exists");
    let advance = observer.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
    assert!(advance.hidden_params.iter().any(|param| param.purpose == HiddenParamPurposeArtifact::RouteFamilyTable));
    assert!(advance.hidden_params.iter().any(|param| {
        param.name == "gen__mux_prefix" && param.subject == HiddenParamSubjectArtifact::Actor { actor: "Mux".to_string() }
    }));
    assert!(advance.hidden_params.iter().any(|param| {
        param.name == "gen__mux_suffix" && param.subject == HiddenParamSubjectArtifact::Actor { actor: "Mux".to_string() }
    }));
    assert!(!advance.hidden_params.iter().any(|param| matches!(param.subject, HiddenParamSubjectArtifact::ObservedActor { .. })));
    artifact.check_template_plan_consistency().expect("in-app observed output uses the planned target cut");
}

#[test]
fn in_app_observed_input_uses_a_direct_template_dependency() {
    let artifact = inline_artifact(
        "in-app-observed-input",
        r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                cov_id foreign_id;
            }

            state TargetState {
                int amount;
            }

            actor Foreign owns ForeignState {
                entry route() emits next: Target {
                    unrestricted(next.value);
                    TargetState next_state = { amount: amount };
                    become next <- Target(next_state);
                }
            }

            actor Local owns LocalState {
                entry inspect()
                observes remote by self.foreign_id {
                    inputs {
                        src: Foreign,
                    }
                }
                emits none {
                    require(remote.inputs.src.amount >= 0);
                }
            }

            actor Target owns TargetState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            app Test {
                actor Foreign;
                actor Local;
                actor Target;
            }
            "#,
    );

    assert_eq!(
        runtime_state_plan(&artifact, "Local")
            .expect("Local directly carries the observed input template")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![("gen__foreign_template", RuntimeFieldRoleArtifact::Template { contract: "Foreign".to_string() })]
    );
    let local = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local artifact exists");
    let inspect = local.entries.iter().find(|entry| entry.name == "inspect").expect("inspect entry exists");
    assert_eq!(
        inspect.hidden_params.iter().map(|param| (param.name.as_str(), &param.subject, param.purpose)).collect::<Vec<_>>(),
        vec![
            (
                "gen__foreign_prefix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Foreign".to_string() },
                HiddenParamPurposeArtifact::TemplatePrefixLen,
            ),
            (
                "gen__foreign_suffix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Foreign".to_string() },
                HiddenParamPurposeArtifact::TemplateSuffixLen,
            ),
        ]
    );
}

#[test]
fn in_app_observed_output_reuses_a_current_input_template() {
    let artifact = inline_artifact(
        "in-app-observed-output-reuse",
        r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                cov_id remote_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry step()
                consumes {
                    source: Foreign,
                }
                observes remote by self.remote_id {
                    outputs {
                        next: Foreign,
                    }
                }
                emits none {
                    ForeignState next_state = state(source);
                    require remote.outputs become {
                        next <- Foreign(next_state),
                    };
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    );

    let local = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local artifact exists");
    let step = local.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
    assert_eq!(
        step.hidden_params.iter().map(|param| (param.name.as_str(), &param.subject, param.purpose)).collect::<Vec<_>>(),
        vec![
            (
                "gen__foreign_prefix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Foreign".to_string() },
                HiddenParamPurposeArtifact::TemplatePrefixLen,
            ),
            (
                "gen__foreign_suffix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Foreign".to_string() },
                HiddenParamPurposeArtifact::TemplateSuffixLen,
            ),
        ]
    );
}

#[test]
fn in_app_current_output_reuses_an_observed_input_template() {
    let artifact = inline_artifact(
        "in-app-current-output-reuse",
        r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                cov_id remote_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes remote by self.remote_id {
                    inputs {
                        source: Foreign,
                    }
                }
                emits next: Foreign {
                    unrestricted(next.value);
                    ForeignState next_state = state(remote.inputs.source);
                    become next <- Foreign(next_state);
                }
            }

            app Test {
                actor Foreign;
                actor Local;
            }
            "#,
    );

    let local = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local artifact exists");
    let step = local.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
    assert_eq!(
        step.hidden_params.iter().map(|param| (param.name.as_str(), &param.subject, param.purpose)).collect::<Vec<_>>(),
        vec![
            (
                "gen__foreign_prefix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Foreign".to_string() },
                HiddenParamPurposeArtifact::TemplatePrefixLen,
            ),
            (
                "gen__foreign_suffix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Foreign".to_string() },
                HiddenParamPurposeArtifact::TemplateSuffixLen,
            ),
        ]
    );
}

#[test]
fn selected_gates_open_from_the_family_table_and_direct_consumes_stay_concrete() {
    let source = r#"
            state SourceState {
                int nonce;
            }

            state BoardState {
                int ply;
            }

            state ConsumerState {
                int nonce;
            }

            state ArchiveState {
                int nonce;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Source owns SourceState {
                entry enter_pawn() emits next: Pawn {
                    unrestricted(next.value);
                    BoardState next_state = {
                        ply: nonce,
                    };
                    become next <- Pawn(next_state);
                }
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
                entry inspect() emits none {
                    require(ply >= 0);
                }
            }

            actor Knight owns BoardState {
                entry inspect() emits none {
                    require(ply >= 1);
                }
            }

            actor Consumer owns ConsumerState {
                entry verify() consumes {
                    pawn: Pawn,
                } emits next: Archive {
                    unrestricted(next.value);
                    require(pawn.ply >= 0);

                    ArchiveState next_state = {
                        nonce: nonce + 1,
                    };
                    become next <- Archive(next_state);
                }
            }

            actor Archive owns ArchiveState {
                entry reopen() emits next: Pawn {
                    unrestricted(next.value);
                    BoardState next_state = {
                        ply: nonce,
                    };
                    become next <- Pawn(next_state);
                }
            }

            app SelectedGate {
                actor Source;
                actor Mux;
                actor Pawn;
                actor Knight;
                actor Consumer;
                actor Archive;
            }
        "#;
    let path = PathBuf::from("selected-family-gate.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");

    let family = model.route_family_for_actor("Pawn").expect("Pawn belongs to the selected family");
    assert!(family.direct_template_actors().is_empty());
    assert_eq!(family.table_actors(), ["Pawn", "Knight", "Mux"]);
    assert_eq!(family.rep(), "Pawn");

    let source_actor = model.actor("Source").expect("Source exists");
    let enter_pawn = source_actor.entries.first().expect("enter_pawn exists");
    let specs = entry_witness_specs(source_actor, enter_pawn, &model).expect("entry witnesses lower");
    let pawn = specs.templates.iter().find(|spec| spec.actor == "Pawn").expect("Pawn template witness exists");
    assert_eq!(pawn.source, TemplateWitnessSource::FamilyTable { family_id: family.id.clone(), offset: 0 });

    let actor_sil = actor_sil_for_model(&model);
    let source_sil = &actor_sil["Source"];
    assert!(source_sil.contains("byte[32] gen__pawn_template = byte[32](gen__pawn_routes.slice(0, 32));"), "{source_sil}");
    let consumer_sil = &actor_sil["Consumer"];
    assert!(consumer_sil.contains("byte[32] gen__pawn_template = gen__init_pawn_template;"), "{consumer_sil}");
    assert!(consumer_sil.contains("byte[32] gen__knight_template = gen__init_knight_template;"), "{consumer_sil}");
    assert!(consumer_sil.contains("byte[32] gen__mux_template = gen__init_mux_template;"), "{consumer_sil}");
    assert!(
        consumer_sil
            .contains("gen__pawn_routes_digest: blake3(byte[](gen__pawn_template + gen__knight_template + gen__mux_template)),"),
        "{consumer_sil}"
    );

    let artifact = emit_artifact(&program, &model, &actor_sil).expect("generated Sil compiles");
    artifact.check_template_plan_consistency().expect("representative actors may be stored inside their family table");
}

#[test]
fn family_commitments_pack_on_planned_cut_transitions() {
    let source = toy_chess_source().replace(
        "            actor Mux owns BoardState {\n",
        r#"            actor Mux owns BoardState {
                entry return_to_player() emits next: Player {
                    unrestricted(next.value);
                    PlayerState next_player = {
                        nonce: ply,
                    };
                    become next <- Player(next_player);
                }

"#,
    );
    let path = PathBuf::from("family-pack-transition.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.clone()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");

    let family_id = "route_family/BoardState/mux".to_string();
    assert_eq!(
        model.route_transition("Mux", "Player"),
        Some(&CompilerRouteTransition { families_to_open: Vec::new(), families_to_pack: vec![family_id] })
    );

    let mux_sil = emit_actor(model.actor("Mux").expect("Mux exists"), &model).expect("Mux Sil emits");
    assert!(mux_sil.contains("PlayerState next_player = PlayerState {"), "{mux_sil}");
    assert!(mux_sil.contains("gen__mux_routes_digest: blake3(byte[](gen__mux_routes)),"), "{mux_sil}");
    assert!(!mux_sil.contains("gen__mux_routes_digest: gen__mux_routes_digest,"), "{mux_sil}");

    inline_artifact("family-pack-transition", &source);
}

#[test]
fn route_neutral_state_locals_convert_at_actor_routes() {
    let straight_path = PathBuf::from("examples/route_state_bodies.ag");
    let straight_source = fs::read_to_string(&straight_path).expect("route state body example exists");
    let straight_module =
        crate::compiler::syntax::parser::parse_module(straight_path.clone(), straight_source.clone()).expect("example parses");
    let straight_program = Program { root: straight_path, modules: vec![straight_module] };
    let straight_model = Model::from_program(&straight_program).expect("example model validates");
    let straight_sil = actor_sil_for_model(&straight_model);

    assert!(straight_sil["Lobby"].contains("struct BoardState {"), "{}", straight_sil["Lobby"]);
    assert!(straight_sil["Lobby"].contains("BoardState next_board = BoardState {"), "{}", straight_sil["Lobby"]);
    assert!(
        straight_sil["Lobby"].contains("Gen__MuxState gen__state_next_gen__mux_state = Gen__MuxState {"),
        "{}",
        straight_sil["Lobby"]
    );
    assert!(
        straight_sil["Lobby"].contains(
            "validateOutputStateWithTemplate(\n            gen__next_output_idx,\n            gen__state_next_gen__mux_state,"
        ),
        "{}",
        straight_sil["Lobby"]
    );
    assert!(straight_sil["Mux"].contains("struct ArchiveState {"), "{}", straight_sil["Mux"]);
    assert!(straight_sil["Mux"].contains("ArchiveState next_archive = ArchiveState {"), "{}", straight_sil["Mux"]);
    assert!(
        straight_sil["Mux"].contains("Gen__ArchiveState gen__state_next_gen__archive_state = Gen__ArchiveState {"),
        "{}",
        straight_sil["Mux"]
    );
    assert!(straight_sil["Archive"].contains("BoardState next_board = BoardState {"), "{}", straight_sil["Archive"]);
    assert!(
        straight_sil["Archive"].contains("Gen__PawnState gen__state_next_gen__pawn_state = Gen__PawnState {"),
        "{}",
        straight_sil["Archive"]
    );

    let choice_path = PathBuf::from("examples/route_state_body_choice.ag");
    let choice_source = fs::read_to_string(&choice_path).expect("route state body choice example exists");
    let choice_module = crate::compiler::syntax::parser::parse_module(choice_path.clone(), choice_source).expect("example parses");
    let choice_program = Program { root: choice_path, modules: vec![choice_module] };
    let choice_model = Model::from_program(&choice_program).expect("example model validates");
    let choice_sil = emit_actor(choice_model.actor("Lobby").expect("Lobby exists"), &choice_model).expect("Lobby Sil emits");

    assert!(choice_sil.contains("struct BoardState {"), "{choice_sil}");
    assert!(choice_sil.contains("BoardState next_board = BoardState {"), "{choice_sil}");
    assert!(choice_sil.contains("Gen__MuxState gen__state_next_gen__mux_state = Gen__MuxState {"), "{choice_sil}");
    assert!(
        choice_sil.contains("validateOutputStateWithTemplate(\n                gen__next_output_idx,\n                next_board,"),
        "{choice_sil}"
    );
    assert!(choice_sil.contains("ply: next_board.ply,"), "{choice_sil}");
}

#[test]
fn direct_route_families_are_inferred_without_hints() {
    let artifact = inline_artifact("toy-chess-family", &toy_chess_source());
    let families = artifact.argent.template_plan.route_families.iter().map(|family| {
        (
            family.id.as_str(),
            family.state.as_str(),
            family.representative_actor.as_str(),
            family.entry_actors.iter().map(String::as_str).collect::<Vec<_>>(),
            family.table_id.as_str(),
            family.actors.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    });

    assert_eq!(
        families.collect::<Vec<_>>(),
        vec![(
            "route_family/BoardState/mux",
            "BoardState",
            "Mux",
            vec!["Mux"],
            "route_table/BoardState/gen__mux_routes",
            vec!["Mux", "Pawn", "Knight"]
        )]
    );

    let board_table = artifact
        .argent
        .template_plan
        .route_tables
        .iter()
        .find(|table| table.id == route_template_table_receipt_id("BoardState", "gen__mux_routes"))
        .expect("BoardState route table exists");
    assert_eq!(board_table.byte_len, 64);
    assert_eq!(
        board_table.entries.iter().map(|entry| entry.leaf.clone()).collect::<Vec<_>>(),
        vec![
            RouteTemplateLeafArtifact::Template { actor: "Pawn".to_string(), template_id: "template/pawn".to_string() },
            RouteTemplateLeafArtifact::Template { actor: "Knight".to_string(), template_id: "template/knight".to_string() },
        ]
    );

    assert_eq!(
        artifact
            .argent
            .actor_enums
            .iter()
            .map(|actor_enum| {
                (
                    actor_enum.name.as_str(),
                    actor_enum.state.as_str(),
                    actor_enum.variants.iter().map(String::as_str).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>(),
        vec![("MoveActor", "BoardState", vec!["Pawn", "Knight"])]
    );

    assert_eq!(
        runtime_state_plan(&artifact, "Player")
            .expect("Player runtime role overlay exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__mux_template", RuntimeFieldRoleArtifact::Template { contract: "Mux".to_string() }),
            ("gen__mux_routes_digest", RuntimeFieldRoleArtifact::TemplateDigest { id: "route_family/BoardState/mux".to_string() }),
        ]
    );

    assert_eq!(
        runtime_state_plan(&artifact, "Mux").expect("Mux runtime role overlay exists").field_roles[..2]
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__mux_template", RuntimeFieldRoleArtifact::Template { contract: "Mux".to_string() }),
            ("gen__mux_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["Pawn".to_string(), "Knight".to_string()] }),
        ]
    );

    let player_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Player").expect("Player actor exists");
    let enter_mux = player_actor.entries.iter().find(|entry| entry.name == "enter_mux").expect("enter_mux entry exists");
    assert_eq!(
        enter_mux
            .hidden_params
            .iter()
            .map(|param| (param.name.as_str(), subject_label(&param.subject), param.purpose, param.route_proof_id.as_deref()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__mux_prefix", "Mux", HiddenParamPurposeArtifact::TemplatePrefixBytes, None),
            ("gen__mux_suffix", "Mux", HiddenParamPurposeArtifact::TemplateSuffixBytes, None),
            ("gen__mux_routes", "route_family/BoardState/mux", HiddenParamPurposeArtifact::RouteFamilyTable, None),
        ]
    );

    let mux_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Mux").expect("Mux actor exists");
    let choose = mux_actor.entries.iter().find(|entry| entry.name == "choose").expect("choose entry exists");
    assert_eq!(
        choose
            .template_selectors
            .iter()
            .map(|selector| {
                (
                    selector.name.as_str(),
                    selector.actor_enum.as_str(),
                    selector.state.as_str(),
                    selector.variants.iter().map(String::as_str).collect::<Vec<_>>(),
                    selector.fixed_actor.as_deref(),
                )
            })
            .collect::<Vec<_>>(),
        vec![("target", "MoveActor", "BoardState", vec!["Pawn", "Knight"], None)]
    );
    assert_eq!(
        choose
            .hidden_params
            .iter()
            .map(|param| (param.name.as_str(), subject_label(&param.subject), param.purpose))
            .collect::<Vec<_>>(),
        vec![
            ("gen__target_prefix", "target", HiddenParamPurposeArtifact::TemplatePrefixBytes),
            ("gen__target_suffix", "target", HiddenParamPurposeArtifact::TemplateSuffixBytes),
        ]
    );
    let choose_knight_const =
        mux_actor.entries.iter().find(|entry| entry.name == "choose_knight_const").expect("choose_knight_const entry exists");
    assert_eq!(
        choose_knight_const
            .template_selectors
            .iter()
            .map(|selector| {
                (
                    selector.name.as_str(),
                    selector.actor_enum.as_str(),
                    selector.state.as_str(),
                    selector.variants.iter().map(String::as_str).collect::<Vec<_>>(),
                    selector.fixed_actor.as_deref(),
                )
            })
            .collect::<Vec<_>>(),
        vec![("target", "MoveActor", "BoardState", vec!["Pawn", "Knight"], Some("Knight"))]
    );
    assert_eq!(choose_knight_const.routes.iter().map(artifact_constructed_actor).collect::<Vec<_>>(), vec!["Knight"]);
    artifact.check_template_plan_consistency().expect("template plan receipt verifies inferred route family");
}

#[test]
fn toy_chess_sil_uses_one_level_route_family_shape() {
    let path = PathBuf::from("toy-chess-shape.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), toy_chess_source()).expect("toy chess source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("toy chess model validates");
    let actor_sil = actor_sil_for_model(&model);

    let league_sil = actor_sil.get("League").expect("League Sil is emitted");
    assert!(league_sil.contains("byte[32] gen__init_mux_template"), "{league_sil}");
    assert!(league_sil.contains("byte[32] gen__init_mux_routes_digest"), "{league_sil}");
    assert!(league_sil.contains("byte[32] gen__mux_routes_digest = gen__init_mux_routes_digest;"), "{league_sil}");
    assert!(!league_sil.contains("gen__pawn_template"), "{league_sil}");
    assert!(!league_sil.contains("gen__knight_template"), "{league_sil}");
    assert!(!league_sil.contains("byte[64] gen__init_mux_routes"), "{league_sil}");
    assert!(!league_sil.contains("byte[64] gen__mux_routes = gen__init_mux_routes;"), "{league_sil}");

    let player_sil = actor_sil.get("Player").expect("Player Sil is emitted");
    assert!(player_sil.contains("byte[32] gen__init_mux_template"), "{player_sil}");
    assert!(player_sil.contains("byte[32] gen__init_mux_routes_digest"), "{player_sil}");
    assert!(player_sil.contains("entry enter_mux("), "{player_sil}");
    assert!(player_sil.contains("byte[] gen__mux_prefix,"), "{player_sil}");
    assert!(player_sil.contains("byte[] gen__mux_suffix,"), "{player_sil}");
    assert!(player_sil.contains("byte[64] gen__mux_routes"), "{player_sil}");
    assert!(player_sil.contains("require(blake3(byte[](gen__mux_routes)) == gen__mux_routes_digest);"), "{player_sil}");
    assert!(player_sil.contains("BoardState next_board = BoardState {"), "{player_sil}");
    assert!(player_sil.contains("Gen__MuxState gen__state_next_gen__mux_state = Gen__MuxState {"), "{player_sil}");
    assert!(!player_sil.contains("gen__pawn_template"), "{player_sil}");
    assert!(!player_sil.contains("gen__knight_template"), "{player_sil}");

    let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
    assert!(mux_sil.contains("byte[64] gen__init_mux_routes"), "{mux_sil}");
    assert!(mux_sil.contains("byte[64] gen__mux_routes = gen__init_mux_routes;"), "{mux_sil}");
    assert!(mux_sil.contains("entry choose(int target, byte[] gen__target_prefix, byte[] gen__target_suffix)"), "{mux_sil}");
    assert!(mux_sil.contains("if (target == 1 /*KNIGHT*/)"), "{mux_sil}");
    assert!(mux_sil.contains("int gen__target_selector = target;"), "{mux_sil}");
    assert!(mux_sil.contains("require(gen__target_selector >= 0);"), "{mux_sil}");
    assert!(mux_sil.contains("require(gen__target_selector < 2);"), "{mux_sil}");
    assert!(mux_sil.contains("byte[32] gen__target_template = byte[32]("), "{mux_sil}");
    assert!(mux_sil.contains("gen__mux_routes.slice(gen__target_selector * 32, gen__target_selector * 32 + 32)"), "{mux_sil}");
    assert!(mux_sil.contains("validateOutputStateWithTemplate(\n            gen__next_output_idx,"), "{mux_sil}");
    assert!(mux_sil.contains("gen__target_prefix,"), "{mux_sil}");
    assert!(mux_sil.contains("gen__target_template"), "{mux_sil}");
    assert!(mux_sil.contains("entry choose_knight_const(byte[] gen__target_prefix, byte[] gen__target_suffix)"), "{mux_sil}");
    assert!(mux_sil.contains("int gen__target_selector = 1 /*KNIGHT*/;"), "{mux_sil}");
    assert!(mux_sil.contains("byte[32] gen__pawn_template = byte[32](gen__mux_routes.slice(0, 32));"), "{mux_sil}");
    assert!(mux_sil.contains("byte[32] gen__knight_template = byte[32](gen__mux_routes.slice(32, 64));"), "{mux_sil}");
    assert!(mux_sil.contains("gen__pawn_prefix,"), "{mux_sil}");
    assert!(mux_sil.contains("gen__pawn_template"), "{mux_sil}");
    assert!(mux_sil.contains("gen__knight_prefix,"), "{mux_sil}");
    assert!(mux_sil.contains("gen__knight_template"), "{mux_sil}");

    let pawn_sil = actor_sil.get("Pawn").expect("Pawn Sil is emitted");
    assert!(pawn_sil.contains("byte[64] gen__init_mux_routes"), "{pawn_sil}");
    assert!(pawn_sil.contains("byte[64] gen__mux_routes = gen__init_mux_routes;"), "{pawn_sil}");
    assert!(!pawn_sil.contains("gen__pawn_template"), "{pawn_sil}");
    assert!(!pawn_sil.contains("gen__knight_template"), "{pawn_sil}");
}

#[test]
fn route_family_state_keeps_downstream_templates() {
    let path = PathBuf::from("route-family-with-downstream-actor.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state BoardState {
                int ply;
            }

            state ReceiptState {
                int final_ply;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Mux owns BoardState {
                entry choose(MoveActor target) emits next: MoveActor {
                    unrestricted(next.value);
                    BoardState next_board = {
                        ply: ply + 1,
                    };
                    become next <- target(next_board);
                }

                entry finish() emits next: Receipt {
                    unrestricted(next.value);
                    ReceiptState receipt = {
                        final_ply: ply,
                    };
                    become next <- Receipt(receipt);
                }
            }

            actor Pawn owns BoardState {
                entry back_to_mux() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_board = {
                        ply: ply + 1,
                    };
                    become next <- Mux(next_board);
                }
            }

            actor Knight owns BoardState {
                entry back_to_mux() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_board = {
                        ply: ply + 2,
                    };
                    become next <- Mux(next_board);
                }
            }

            actor Receipt owns ReceiptState {
                entry resume() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_board = {
                        ply: final_ply + 1,
                    };
                    become next <- Mux(next_board);
                }
            }

            app RoutedLifecycle {
                actor Mux;
                actor Pawn;
                actor Knight;
                actor Receipt;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor_sil = actor_sil_for_model(&model);

    let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
    assert!(mux_sil.contains("byte[32] gen__receipt_template = gen__init_receipt_template;"), "{mux_sil}");
    assert!(mux_sil.contains("byte[64] gen__mux_routes = gen__init_mux_routes;"), "{mux_sil}");
    assert!(mux_sil.contains("gen__mux_routes_digest: blake3(byte[](gen__mux_routes)),"), "{mux_sil}");

    emit_artifact(&program, &model, &actor_sil).expect("generated Sil compiles");
}

#[test]
fn actor_enum_order_drives_route_table_order() {
    let source = toy_chess_source().replace(
        "actor enum MoveActor {\n                Pawn;\n                Knight;\n            }",
        "actor enum MoveActor {\n                Knight;\n                Pawn;\n            }",
    );
    let path = PathBuf::from("toy-chess-selector-order.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source).expect("toy chess source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("reordered selector enum defines route table order");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");

    let board_table = artifact
        .argent
        .template_plan
        .route_tables
        .iter()
        .find(|table| table.id == route_template_table_receipt_id("BoardState", "gen__mux_routes"))
        .expect("BoardState route table exists");
    assert_eq!(
        board_table.entries.iter().map(|entry| entry.leaf.clone()).collect::<Vec<_>>(),
        vec![
            RouteTemplateLeafArtifact::Template { actor: "Knight".to_string(), template_id: "template/knight".to_string() },
            RouteTemplateLeafArtifact::Template { actor: "Pawn".to_string(), template_id: "template/pawn".to_string() },
        ]
    );
    assert_eq!(
        runtime_state_plan(&artifact, "Mux").expect("Mux runtime role overlay exists").field_roles[1].role,
        RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["Knight".to_string(), "Pawn".to_string()] }
    );

    let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
    assert!(mux_sil.contains("if (target == 0 /*KNIGHT*/)"), "{mux_sil}");
    assert!(mux_sil.contains("int gen__target_selector = 0 /*KNIGHT*/;"), "{mux_sil}");
    assert!(mux_sil.contains("byte[32] gen__knight_template = byte[32](gen__mux_routes.slice(0, 32));"), "{mux_sil}");
    assert!(mux_sil.contains("byte[32] gen__pawn_template = byte[32](gen__mux_routes.slice(32, 64));"), "{mux_sil}");
}

#[test]
fn gate_less_family_appends_rep_after_selector_variants() {
    let path = PathBuf::from("fixed-selector-table.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state BoardState {
                int ply;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Mux owns BoardState {
                entry choose_knight_const() emits next: MoveActor {
                    unrestricted(next.value);
                    BoardState next_board = {
                        ply: ply + 1,
                    };

                    actor_type<BoardState> target = MoveActor::Knight;
                    become next <- target(next_board);
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

            app FixedSelectorTable {
                actor Mux;
                actor Pawn;
                actor Knight;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("fixed selector still infers the full enum table");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");

    let family = artifact.argent.template_plan.route_families.first().expect("route family is inferred");
    assert!(family.entry_actors.is_empty());
    assert_eq!(family.representative_actor, "Mux");

    let board_table = artifact
        .argent
        .template_plan
        .route_tables
        .iter()
        .find(|table| table.id == route_template_table_receipt_id("BoardState", "gen__mux_routes"))
        .expect("BoardState route table exists");
    assert_eq!(
        board_table.entries.iter().map(|entry| entry.leaf.clone()).collect::<Vec<_>>(),
        vec![
            RouteTemplateLeafArtifact::Template { actor: "Pawn".to_string(), template_id: "template/pawn".to_string() },
            RouteTemplateLeafArtifact::Template { actor: "Knight".to_string(), template_id: "template/knight".to_string() },
            RouteTemplateLeafArtifact::Template { actor: "Mux".to_string(), template_id: "template/mux".to_string() },
        ]
    );

    let mux_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Mux").expect("Mux actor exists");
    let choose_knight_const = mux_actor.entries.iter().find(|entry| entry.name == "choose_knight_const").expect("entry exists");
    assert_eq!(
        choose_knight_const
            .template_selectors
            .iter()
            .map(|selector| (selector.name.as_str(), selector.fixed_actor.as_deref()))
            .collect::<Vec<_>>(),
        vec![("target", Some("Knight"))]
    );
    assert_eq!(choose_knight_const.routes.iter().map(artifact_constructed_actor).collect::<Vec<_>>(), vec!["Knight"]);

    let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
    assert!(mux_sil.contains("int gen__target_selector = 1 /*KNIGHT*/;"), "{mux_sil}");
    assert!(mux_sil.contains("require(gen__target_selector < 2);"), "{mux_sil}");
    assert!(mux_sil.contains("byte[32] gen__target_template = byte[32]("), "{mux_sil}");
    assert!(mux_sil.contains("gen__mux_routes.slice(gen__target_selector * 32, gen__target_selector * 32 + 32)"), "{mux_sil}");
    artifact.check_template_plan_consistency().expect("template plan receipt verifies");
}

#[test]
fn actor_enum_local_drives_selector_domain_and_route_expansion() {
    let path = PathBuf::from("local-actor-enum-selector.ag");
    let module = crate::compiler::syntax::parser::parse_module(
        path.clone(),
        r#"
            state BoardState {
                int ply;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Mux owns BoardState {
                entry choose(int index) emits next: MoveActor {
                    unrestricted(next.value);
                    MoveActor target = MoveActor[index];
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

            app LocalSelector {
                actor Mux;
                actor Pawn;
                actor Knight;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("local actor enum defines a selector domain");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("generated Sil compiles");

    let mux = artifact.argent.actors.iter().find(|actor| actor.name == "Mux").expect("Mux actor exists");
    let choose = mux.entries.iter().find(|entry| entry.name == "choose").expect("choose entry exists");
    assert_eq!(choose.template_selectors.iter().map(|selector| selector.name.as_str()).collect::<Vec<_>>(), vec!["target"]);
    assert_eq!(choose.routes.iter().map(artifact_constructed_actor).collect::<Vec<_>>(), vec!["Pawn", "Knight"]);

    let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
    assert!(mux_sil.contains("int target = index;"), "{mux_sil}");
    assert!(mux_sil.contains("int gen__target_selector = target;"), "{mux_sil}");
    artifact.check_template_plan_consistency().expect("local selector route plan verifies");
}

#[test]
fn actor_enums_over_same_route_table_must_use_one_order() {
    let source = r#"
            state BoardState {
                int selector;
                int ply;
            }

            actor enum FirstMove {
                Pawn;
                Knight;
            }

            actor enum SecondMove {
                Knight;
                Pawn;
            }

            actor Mux owns BoardState {
                entry choose_first(FirstMove target) emits next: FirstMove {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- target(next_board);
                }

                entry choose_second(SecondMove target) emits next: SecondMove {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- target(next_board);
                }
            }

            actor Pawn owns BoardState {}
            actor Knight owns BoardState {}

            app ConflictingSelectorOrder {
                actor Mux;
                actor Pawn;
                actor Knight;
            }
        "#;
    let path = PathBuf::from("conflicting-selector-order.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };

    let err = Model::from_program(&program).expect_err("conflicting actor enum orders must be rejected");
    assert!(err.to_string().contains("conflicts with requirement"), "unexpected error: {err}");
}

#[test]
fn actor_enum_variants_form_a_prefix_of_the_inferred_route_family() {
    let source = r#"
            state BoardState {
                int selector;
                int ply;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Mux owns BoardState {
                entry choose(MoveActor target) emits next: MoveActor {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- target(next_board);
                }

                entry visit_bishop() emits next: Bishop {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- Bishop(next_board);
                }
            }

            actor Pawn owns BoardState {}
            actor Knight owns BoardState {}
            actor Bishop owns BoardState {}

            app SelectorPrefix {
                actor Mux;
                actor Pawn;
                actor Knight;
                actor Bishop;
            }
        "#;
    let path = PathBuf::from("selector-prefix.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };

    let model = Model::from_program(&program).expect("selector variants may prefix other family actors");

    assert_eq!(model.route_families.len(), 1);
    assert_eq!(model.route_families[0].table_actors, ["Pawn", "Knight", "Mux", "Bishop"]);
}

#[test]
fn selector_can_include_its_source_actor() {
    let artifact = inline_artifact(
        "self-selector-variant",
        r#"
            state SharedState {
                int amount;
            }

            actor enum NextActor {
                Worker;
                Challenge;
            }

            actor Worker owns SharedState {
                entry inspect() emits none {
                    require(amount >= 0);
                }
            }

            actor Challenge owns SharedState {
                entry choose(NextActor target) emits next: NextActor {
                    unrestricted(next.value);
                    SharedState next_state = {
                        amount: amount + 1,
                    };
                    become next <- target(next_state);
                }
            }

            app SelfSelectorVariant {
                actor Worker;
                actor Challenge;
            }
            "#,
    );

    artifact.check_template_plan_consistency().expect("self selector variant has a valid identity cut transition");
}

#[test]
fn rejects_actor_enum_variants_with_different_owned_states() {
    let artifact_source = r#"
            state AState {
                int n;
            }

            state BState {
                int n;
            }

            actor A owns AState {}
            actor B owns BState {}

            actor enum MixedActor {
                A;
                B;
            }

            app BadEnum {
                actor A;
                actor B;
            }
            "#;
    let path = PathBuf::from("bad-actor-enum.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), artifact_source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };

    let err = Model::from_program(&program).expect_err("mixed actor enum state must be rejected");
    assert!(err.to_string().contains("variant `B` owns state `BState`, expected `AState`"), "unexpected error: {err}");
}

#[test]
fn two_actor_routes_use_direct_template_fields() {
    let artifact = inline_artifact(
        "genesis-route-family",
        r#"
            state BoardState {
                int n;
            }

            actor A owns BoardState {
                entry to_b() emits next: B {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- B(next_state);
                }
            }

            actor B owns BoardState {
                entry to_a() emits next: A {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- A(next_state);
                }
            }

            app GenesisFamily {
                actor A;
                actor B;
            }
            "#,
    );

    assert!(artifact.argent.template_plan.route_families.is_empty());
    assert!(artifact.argent.template_plan.route_tables.is_empty());

    assert_eq!(
        runtime_state_plan(&artifact, "A")
            .expect("A runtime role overlay exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__a_template", RuntimeFieldRoleArtifact::Template { contract: "A".to_string() }),
            ("gen__b_template", RuntimeFieldRoleArtifact::Template { contract: "B".to_string() }),
        ]
    );
    artifact.check_template_plan_consistency().expect("direct two-actor route plan verifies");
}

#[test]
fn route_family_state_can_have_multiple_disconnected_families() {
    let artifact = inline_artifact(
        "multi-family-route-state",
        r#"
            state BoardState {
                int n;
            }

            actor A owns BoardState {
                entry to_b() emits next: B {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- B(next_state);
                }
            }

            actor B owns BoardState {
                entry to_c() emits next: C {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- C(next_state);
                }
            }

            actor C owns BoardState {
                entry to_a() emits next: A {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- A(next_state);
                }
            }

            actor D owns BoardState {
                entry to_e() emits next: E {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- E(next_state);
                }
            }

            actor E owns BoardState {
                entry to_f() emits next: F {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- F(next_state);
                }
            }

            actor F owns BoardState {
                entry to_d() emits next: D {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- D(next_state);
                }
            }

            app MultiFamilyState {
                actor A;
                actor B;
                actor C;
                actor D;
                actor E;
                actor F;
            }
            "#,
    );

    let families = artifact
        .argent
        .template_plan
        .route_families
        .iter()
        .map(|family| {
            (
                family.id.as_str(),
                family.representative_actor.as_str(),
                family.actors.iter().map(String::as_str).collect::<Vec<_>>(),
                family.table_id.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        families,
        vec![
            ("route_family/BoardState/a", "A", vec!["A", "B", "C"], "route_table/BoardState/gen__a_routes"),
            ("route_family/BoardState/d", "D", vec!["D", "E", "F"], "route_table/BoardState/gen__d_routes"),
        ]
    );

    assert_eq!(
        artifact
            .argent
            .template_plan
            .route_tables
            .iter()
            .map(|table| { (table.id.as_str(), table.entries.iter().map(|entry| entry.leaf.clone()).collect::<Vec<_>>(),) })
            .collect::<Vec<_>>(),
        vec![
            (
                "route_table/BoardState/gen__a_routes",
                vec![
                    RouteTemplateLeafArtifact::Template { actor: "A".to_string(), template_id: "template/a".to_string() },
                    RouteTemplateLeafArtifact::Template { actor: "B".to_string(), template_id: "template/b".to_string() },
                    RouteTemplateLeafArtifact::Template { actor: "C".to_string(), template_id: "template/c".to_string() },
                ],
            ),
            (
                "route_table/BoardState/gen__d_routes",
                vec![
                    RouteTemplateLeafArtifact::Template { actor: "D".to_string(), template_id: "template/d".to_string() },
                    RouteTemplateLeafArtifact::Template { actor: "E".to_string(), template_id: "template/e".to_string() },
                    RouteTemplateLeafArtifact::Template { actor: "F".to_string(), template_id: "template/f".to_string() },
                ],
            ),
        ]
    );

    assert_eq!(
        runtime_state_plan(&artifact, "A")
            .expect("A runtime role overlay exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![(
            "gen__a_routes",
            RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["A".to_string(), "B".to_string(), "C".to_string()] }
        ),]
    );
    assert_eq!(
        runtime_state_plan(&artifact, "D")
            .expect("D runtime role overlay exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![(
            "gen__d_routes",
            RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["D".to_string(), "E".to_string(), "F".to_string()] }
        ),]
    );
    artifact.check_template_plan_consistency().expect("multi-family route state receipt verifies");
}

#[test]
fn route_family_with_one_table_actor_uses_direct_template_fields() {
    let artifact = inline_artifact(
        "single-entry-route-table",
        r#"
            state PlayerState {
                int n;
            }

            state BoardState {
                int n;
            }

            actor PlayerA owns PlayerState {
                entry enter_a() emits next: HubA {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n,
                    };

                    become next <- HubA(next_state);
                }
            }

            actor PlayerB owns PlayerState {
                entry enter_b() emits next: HubB {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n,
                    };

                    become next <- HubB(next_state);
                }
            }

            actor HubB owns BoardState {
                entry to_leaf() emits next: Leaf {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 2,
                    };

                    become next <- Leaf(next_state);
                }
            }

            actor HubA owns BoardState {
                entry to_leaf() emits next: Leaf {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- Leaf(next_state);
                }
            }

            actor Leaf owns BoardState {
                entry idle() emits none {
                    require(n >= 0);
                }
            }

            app SingleEntryRouteTable {
                actor PlayerA;
                actor PlayerB;
                actor HubB;
                actor HubA;
                actor Leaf;
            }
            "#,
    );

    assert!(artifact.argent.template_plan.route_families.is_empty());
    assert!(artifact.argent.template_plan.route_tables.is_empty());
    assert_eq!(
        runtime_state_plan(&artifact, "HubB")
            .expect("HubB runtime role overlay exists")
            .field_roles
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__hub_a_template", RuntimeFieldRoleArtifact::Template { contract: "HubA".to_string() }),
            ("gen__hub_b_template", RuntimeFieldRoleArtifact::Template { contract: "HubB".to_string() }),
            ("gen__leaf_template", RuntimeFieldRoleArtifact::Template { contract: "Leaf".to_string() }),
        ]
    );
    artifact.check_template_plan_consistency().expect("direct route plan verifies");
}

#[test]
fn route_family_with_multiple_external_entries_uses_first_entry_as_representative() {
    let artifact = inline_artifact(
        "multi-entry-route-family",
        r#"
            state PlayerState {
                int n;
            }

            state BoardState {
                int n;
            }

            actor PlayerA owns PlayerState {
                entry enter_a() emits next: HubA {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n,
                    };

                    become next <- HubA(next_state);
                }
            }

            actor PlayerB owns PlayerState {
                entry enter_b() emits next: HubB {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n,
                    };

                    become next <- HubB(next_state);
                }
            }

            actor HubB owns BoardState {
                entry to_leaf_a() emits next: LeafA {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- LeafA(next_state);
                }
            }

            actor HubA owns BoardState {
                entry to_leaf_b() emits next: LeafB {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- LeafB(next_state);
                }
            }

            actor LeafA owns BoardState {
                entry to_a() emits next: HubA {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- HubA(next_state);
                }
            }

            actor LeafB owns BoardState {
                entry to_b() emits next: HubB {
                    unrestricted(next.value);
                    BoardState next_state = {
                        n: n + 1,
                    };

                    become next <- HubB(next_state);
                }
            }

            app MultiEntryFamily {
                actor PlayerA;
                actor PlayerB;
                actor HubB;
                actor HubA;
                actor LeafA;
                actor LeafB;
            }
            "#,
    );

    let family = artifact.argent.template_plan.route_families.first().expect("route family is inferred");
    assert_eq!(family.id, "route_family/BoardState/hub_b");
    assert_eq!(family.representative_actor, "HubB");
    assert_eq!(family.entry_actors, vec!["HubB", "HubA"]);
    assert_eq!(family.actors, vec!["HubB", "HubA", "LeafA", "LeafB"]);
    assert_eq!(family.table_id, "route_table/BoardState/gen__hub_b_routes");

    assert_eq!(
        runtime_state_plan(&artifact, "HubB").expect("HubB runtime role overlay exists").field_roles[..3]
            .iter()
            .map(|field| (field.name.as_str(), field.role.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("gen__hub_b_template", RuntimeFieldRoleArtifact::Template { contract: "HubB".to_string() }),
            ("gen__hub_a_template", RuntimeFieldRoleArtifact::Template { contract: "HubA".to_string() }),
            (
                "gen__hub_b_routes",
                RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["LeafA".to_string(), "LeafB".to_string()] },
            ),
        ]
    );
    artifact.check_template_plan_consistency().expect("multi-entry route family receipt verifies");
}

fn inline_artifact(name: &str, source: &str) -> Artifact {
    inline_actor_sil_and_artifact(name, source).1
}

fn inline_actor_sil_and_artifact(name: &str, source: &str) -> (BTreeMap<String, String>, Artifact) {
    let path = PathBuf::from(format!("{name}.ag"));
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");
    (actor_sil, artifact)
}

#[test]
fn standalone_entry_body_block_lowers_and_compiles() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "standalone-entry-body-block",
        r#"
            state CounterState {
                int count;
            }

            actor Counter owns CounterState {
                entry inspect(int delta) emits none {
                    {
                        int candidate = count + delta;
                        require((candidate >= count) || (delta < 0));
                    }
                    require(count >= 0);
                }
            }

            app StandaloneEntryBodyBlock {
                actor Counter;
            }
            "#,
    );

    let sil = actor_sil.get("Counter").expect("Counter emits");
    assert!(
        sil.contains(
            r#"        {
            int candidate = count + delta;
            require((candidate >= count) || (delta < 0));
        }
        require(count >= 0);"#
        ),
        "standalone block must remain a nested Sil block:\n{sil}"
    );
}

#[test]
fn complex_nested_entry_body_lowers_and_compiles() {
    inline_artifact(
        "complex-nested-entry-body",
        r#"
            state CounterState {
                int count;
                int limit;
            }

            actor Counter owns CounterState {
                entry advance(int delta, int scale, bool prefer_limit) emits next: Counter {
                    int base = count + ((delta * scale) + (limit - count));
                    {
                        int bounded = base + ((limit - base) * scale);
                        require((bounded >= count) || ((delta < 0) && !prefer_limit));
                        {
                            int mixed = (bounded + (delta * (scale + 1))) % (limit + 1);
                            require(((mixed >= 0) && (bounded <= limit)) || prefer_limit);
                        }
                    }

                    if ((delta > 0) && ((base < limit) || prefer_limit)) {
                        CounterState next_state = {
                            count: base + (scale * 2),
                            limit: limit,
                        };
                        require(
                            (next.value >= self.value)
                                && ((next_state.count > count) || (delta > scale))
                        );
                        become next <- Counter(next_state);
                    } else if ((delta == 0) || ((scale > limit) && !prefer_limit)) {
                        CounterState next_state = {
                            count: count,
                            limit: limit + (scale - delta),
                        };
                        require(
                            (next.value == self.value)
                                || ((next.value > self.value) && (next_state.limit >= limit))
                        );
                        become next <- Counter(next_state);
                    } else {
                        CounterState next_state = {
                            count: count + ((limit - scale) * (delta + 1)),
                            limit: limit,
                        };
                        require(
                            ((next.value >= 0) && (self.value >= 0))
                                || ((next_state.count <= limit) && !prefer_limit)
                        );
                        become next <- Counter(next_state);
                    }
                }
            }

            app ComplexNestedEntryBody {
                actor Counter;
            }
            "#,
    );
}

#[test]
fn for_loop_entry_body_lowers_and_compiles() {
    inline_artifact(
        "for-loop-entry-body",
        r#"
            state CounterState {
                int count;
            }

            actor Counter owns CounterState {
                entry inspect(int iterations) emits none {
                    for (i, 0, iterations, 16) {
                        require((i >= 0) && (i < iterations));
                    }
                }
            }

            app ForLoopEntryBody {
                actor Counter;
            }
            "#,
    );
}

#[test]
fn scalar_state_arguments_lower_inside_for_headers() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "state-argument-for-header",
        r#"
            state CounterState {
                int count;
            }

            fn read_count(CounterState value) -> int {
                return value.count;
            }

            actor Counter owns CounterState {
                entry inspect()
                consumes {
                    other: Counter,
                }
                emits none {
                    for (i, 0, read_count(state(other)), 8) {
                        require(i >= 0);
                    }
                }
            }

            app StateArgumentForHeader {
                actor Counter;
            }
        "#,
    );
    let sil = actor_sil.get("Counter").expect("Counter emits");
    assert!(!sil.contains("CounterState"), "{sil}");
    assert!(sil.contains("function read_count(State gen__glob_value) : int"), "{sil}");
    assert!(sil.contains("for (i, 0, read_count(gen__other_state), 8)"), "{sil}");
}

#[test]
fn scalar_state_arguments_lower_after_actor_enum_literals() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "state-argument-actor-enum",
        r#"
            state CounterState {
                int count;
            }

            fn read_count(CounterState value) -> int {
                return value.count;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor Pawn owns CounterState {
                entry hold() emits none {
                    require(count >= 0);
                }
            }

            actor Knight owns CounterState {
                entry hold() emits none {
                    require(count >= 1);
                }
            }

            actor Counter owns CounterState {
                entry inspect()
                consumes {
                    other: Counter,
                }
                emits none {
                    require(read_count(state(other)) + MoveActor::Knight >= 0);
                }
            }

            app StateArgumentActorEnum {
                actor Counter;
                actor Pawn;
                actor Knight;
            }
        "#,
    );
    let sil = actor_sil.get("Counter").expect("Counter emits");
    assert!(sil.contains("read_count(CounterState {"), "{sil}");
    assert!(sil.contains("count: gen__other_state.count"), "{sil}");
    assert!(sil.contains("+ 1 /*KNIGHT*/ >= 0"), "{sil}");
    assert!(!sil.contains("read_count(state(other))"), "{sil}");
}

#[test]
fn brace_leading_assignments_lower_and_compile_as_sil_statements() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "brace-leading-assignments",
        r#"
            state CounterState {
                int count;
            }

            fn identity(int value) -> int {
                return value;
            }

            actor Counter owns CounterState {
                entry inspect(byte[4] packed) emits none {
                    CounterState snapshot = {
                        count: count,
                    };
                    CounterState {count: int copied} = snapshot;
                    State {count: int current} = readInputState(this.activeInputIndex);
                    (byte[] left, byte[] right) = packed.split(2);
                    byte[] first, byte[] second = packed.split(2);
                    (int returned) = identity(count);
                    require(
                        (copied == count)
                            && (current == count)
                            && (left == first)
                            && (right == second)
                            && (returned == count)
                    );
                }
            }

            app BraceLeadingAssignments {
                actor Counter;
            }
            "#,
    );

    let sil = actor_sil.get("Counter").expect("Counter emits");
    assert!(sil.contains("State {count: int copied} = snapshot;"), "{sil}");
    assert!(sil.contains("State {count: int current} = readInputState(this.activeInputIndex);"), "{sil}");
    assert!(sil.contains("(byte[] left, byte[] right) = packed.split(2);"), "{sil}");
    assert!(sil.contains("byte[] first, byte[] second = packed.split(2);"), "{sil}");
    assert!(sil.contains("(int returned) = identity(count);"), "{sil}");
}

#[test]
fn typed_destructuring_keeps_an_expanded_entry_parameter_authored() {
    let (actor_sil, _) = inline_actor_sil_and_artifact(
        "expanded-parameter-destructuring",
        r#"
            state Detail {
                int count;
            }

            state Capsule {
                int amount;
                virtual detail;
            }

            state Expanded expands Capsule {
                detail: Detail;
            }

            actor Vault owns Expanded {
                entry inspect(Expanded value) emits none {
                    Expanded {
                        amount: int amount_value,
                        detail: Detail detail_value,
                    } = value;
                    require(amount_value >= 0);
                    require(detail_value.count >= 0);
                }
            }

            app ExpandedDestructuring {
                actor Vault;
            }
            "#,
    );

    let sil = actor_sil.get("Vault").expect("Vault emits");
    assert!(sil.contains("        Expanded {\n"), "{sil}");
    assert!(!sil.contains("        State {\n"), "{sil}");
}

#[test]
fn genesis_spawn_lowers_to_pinned_sil_and_artifact_metadata() {
    let (controller_sil, controller_artifact) =
        emit_selected_fixture("tests/fixtures/runtime/context_genesis_spawn/app.ag", "ControllerApp", "Controller");
    assert_eq!(controller_sil, include_str!("../../../../tests/fixtures/runtime/context_genesis_spawn/Controller.sil"));
    let launch =
        controller_artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "launch").expect("launch entry exists");
    assert_eq!(launch.spawns.len(), 1);
    assert_eq!(launch.spawns[0].name, "new_pair");
    assert_eq!(launch.spawns[0].covenant, "pair_id");
    assert_eq!(
        launch.spawns[0].outputs.iter().map(|output| (output.name.as_str(), output.group_index)).collect::<Vec<_>>(),
        vec![("left", 0), ("right", 1)]
    );
    assert_eq!(
        launch.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec![
            "gen__new_pair_left_output_idx",
            "gen__new_pair_right_output_idx",
            "gen__actor_type_self_pair_type_prefix",
            "gen__actor_type_self_pair_type_suffix",
        ]
    );
    controller_artifact.check_template_plan_consistency().expect("spawn metadata verifies");
    let mut malformed = controller_artifact.clone();
    malformed.argent.actors[0].entries[0].spawns[0].outputs[1].group_index = 2;
    assert!(
        matches!(malformed.check_template_plan_consistency(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
        "malformed spawn output order must be rejected"
    );
    let mut noncanonical_template_subject = controller_artifact.clone();
    let prefix = noncanonical_template_subject.argent.actors[0].entries[0]
        .hidden_params
        .iter_mut()
        .find(|param| param.purpose == HiddenParamPurposeArtifact::TemplatePrefixBytes)
        .expect("spawn prefix witness exists");
    let HiddenParamSubjectArtifact::SpawnActor { handle, .. } = &mut prefix.subject else {
        panic!("spawn prefix has a spawn actor subject");
    };
    *handle = "right".to_string();
    assert!(
        matches!(noncanonical_template_subject.check_template_plan_consistency(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
        "shared spawn template witnesses must use their first output as subject"
    );

    let (pair_sil, _) = emit_selected_fixture("tests/fixtures/runtime/context_genesis_spawn/app.ag", "PairApp", "Pair");
    assert_eq!(pair_sil, include_str!("../../../../tests/fixtures/runtime/context_genesis_spawn/Pair.sil"));
}

#[test]
fn multiple_genesis_spawns_lower_to_pinned_sil_and_artifact_metadata() {
    let source = "tests/fixtures/runtime/context_multiple_genesis_spawns/app.ag";
    let (controller_sil, controller_artifact) = emit_selected_fixture(source, "ControllerApp", "Controller");
    assert_eq!(controller_sil, include_str!("../../../../tests/fixtures/runtime/context_multiple_genesis_spawns/Controller.sil"));
    let launch =
        controller_artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "launch").expect("launch entry exists");
    assert_eq!(
        launch
            .spawns
            .iter()
            .map(|spawn| {
                (
                    spawn.name.as_str(),
                    spawn.outputs.iter().map(|output| (output.name.as_str(), output.group_index)).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("first_pair", vec![("left", 0), ("right", 1)]),
            ("second_pair", vec![("pair", 0)]),
            ("third_pair", vec![("left", 0), ("right", 1)]),
        ]
    );
    assert_eq!(
        launch.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec![
            "gen__first_pair_left_output_idx",
            "gen__first_pair_right_output_idx",
            "gen__second_pair_pair_output_idx",
            "gen__third_pair_left_output_idx",
            "gen__third_pair_right_output_idx",
            "gen__actor_type_self_pair_type_prefix",
            "gen__actor_type_self_pair_type_suffix",
        ]
    );
    controller_artifact.check_template_plan_consistency().expect("multiple-spawn metadata verifies");

    let (pair_sil, _) = emit_selected_fixture(source, "PairApp", "Pair");
    assert_eq!(pair_sil, include_str!("../../../../tests/fixtures/runtime/context_multiple_genesis_spawns/Pair.sil"));
}

#[test]
fn observed_and_spawned_source_actor_share_pinned_witnesses() {
    let source = "tests/fixtures/runtime/context_shared_actor_witness/app.ag";
    let (controller_sil, controller_artifact) = emit_selected_fixture(source, "SharedActorWitness", "Controller");
    assert_eq!(controller_sil, include_str!("../../../../tests/fixtures/runtime/context_shared_actor_witness/Controller.sil"));

    let advance =
        controller_artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
    assert_eq!(
        advance.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec![
            "gen__anchor_prefix_len",
            "gen__anchor_suffix_len",
            "gen__newborn_pair_output_idx",
            "gen__actor_type_self_pair_type_prefix",
            "gen__actor_type_self_pair_type_suffix",
        ]
    );
    let source_witnesses =
        advance.hidden_params.iter().filter(|param| param.name.starts_with("gen__actor_type_self_pair_type_")).collect::<Vec<_>>();
    assert_eq!(source_witnesses.len(), 2);
    assert!(source_witnesses.iter().all(|param| {
        matches!(
            &param.subject,
            HiddenParamSubjectArtifact::ObservedActor {
                observe,
                side: ObservedActorSideArtifact::Output,
                handle,
                actor,
            } if observe == "existing" && handle == "pair" && actor == "self.pair_type"
        )
    }));
    assert_eq!(
        source_witnesses.iter().map(|param| param.recipe_id.as_str()).collect::<Vec<_>>(),
        vec![
            "witness/Controller/advance/actor_type/self_pair_type/template_prefix_bytes",
            "witness/Controller/advance/actor_type/self_pair_type/template_suffix_bytes",
        ]
    );
    controller_artifact.check_template_plan_consistency().expect("shared observe/spawn witness metadata verifies");

    let mut malformed = controller_artifact.clone();
    let prefix = malformed.argent.actors[0].entries[0]
        .hidden_params
        .iter_mut()
        .find(|param| param.name == "gen__actor_type_self_pair_type_prefix")
        .expect("shared prefix witness exists");
    let HiddenParamSubjectArtifact::ObservedActor { handle, .. } = &mut prefix.subject else {
        panic!("shared prefix uses its first observed output");
    };
    *handle = "missing".to_string();
    assert!(
        matches!(malformed.check_template_plan_consistency(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
        "spawn metadata rejects an invalid observed witness provider"
    );

    let (anchor_sil, _) = emit_selected_fixture(source, "SharedActorWitness", "Anchor");
    assert_eq!(anchor_sil, include_str!("../../../../tests/fixtures/runtime/context_shared_actor_witness/Anchor.sil"));
    let (pair_sil, _) = emit_selected_fixture(source, "SharedActorWitness", "Pair");
    assert_eq!(pair_sil, include_str!("../../../../tests/fixtures/runtime/context_shared_actor_witness/Pair.sil"));
}

#[test]
fn spawn_actor_type_sources_have_distinct_witness_names() {
    let artifact = inline_artifact(
        "spawn-actor-type-sources",
        r#"
            state PairState {
                int value;
            }
            state LauncherState {
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch(actor_type<PairState> self_pair_type)
                spawns stored by stored_id {
                    outputs {
                        pair: self.pair_type,
                    }
                }
                spawns argument by argument_id {
                    outputs {
                        pair: self_pair_type,
                    }
                }
                emits next: Launcher {
                    unrestricted(stored.outputs.pair.value);
                    unrestricted(argument.outputs.pair.value);
                    unrestricted(next.value);
                    PairState stored_pair = { value: 1 };
                    PairState argument_pair = { value: 2 };
                    require stored.outputs become {
                        pair <- self.pair_type(stored_pair),
                    };
                    require argument.outputs become {
                        pair <- self_pair_type(argument_pair),
                    };
                    become next <- self;
                }
            }

            app Test {
                actor Launcher;
            }
            "#,
    );

    let launch = artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "launch").expect("launch entry exists");
    assert_eq!(
        launch.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
        vec![
            "gen__stored_pair_output_idx",
            "gen__argument_pair_output_idx",
            "gen__actor_type_self_pair_type_prefix",
            "gen__actor_type_self_pair_type_suffix",
            "gen__actor_type_arg_self_pair_type_prefix",
            "gen__actor_type_arg_self_pair_type_suffix",
        ]
    );
}

#[test]
fn spawn_witness_recipe_ids_are_scoped_to_the_entry() {
    let artifact = inline_artifact(
        "entry-scoped-spawn-recipes",
        r#"
            state PairState {
                int value;
            }
            state LauncherState {
                actor_type<PairState> first_type;
                actor_type<PairState> second_type;
            }

            actor Launcher owns LauncherState {
                entry launch_first()
                spawns child by child_id {
                    outputs {
                        pair: self.first_type,
                    }
                }
                emits next: Launcher {
                    unrestricted(child.outputs.pair.value);
                    unrestricted(next.value);
                    PairState pair_state = { value: 1 };
                    require child.outputs become {
                        pair <- self.first_type(pair_state),
                    };
                    become next <- self;
                }

                entry launch_second()
                spawns child by child_id {
                    outputs {
                        pair: self.second_type,
                    }
                }
                emits next: Launcher {
                    unrestricted(child.outputs.pair.value);
                    unrestricted(next.value);
                    PairState pair_state = { value: 2 };
                    require child.outputs become {
                        pair <- self.second_type(pair_state),
                    };
                    become next <- self;
                }
            }

            app Test {
                actor Launcher;
            }
            "#,
    );

    let launcher = &artifact.argent.actors[0];
    let first = launcher.entries.iter().find(|entry| entry.name == "launch_first").expect("first entry exists");
    let second = launcher.entries.iter().find(|entry| entry.name == "launch_second").expect("second entry exists");
    let first_recipe = first
        .hidden_params
        .iter()
        .find(|param| param.purpose == HiddenParamPurposeArtifact::TemplatePrefixBytes)
        .expect("first spawn prefix exists");
    let second_recipe = second
        .hidden_params
        .iter()
        .find(|param| param.purpose == HiddenParamPurposeArtifact::TemplatePrefixBytes)
        .expect("second spawn prefix exists");
    assert_eq!(first_recipe.recipe_id, "witness/Launcher/launch_first/actor_type/self_first_type/template_prefix_bytes");
    assert_eq!(second_recipe.recipe_id, "witness/Launcher/launch_second/actor_type/self_second_type/template_prefix_bytes");
    assert_ne!(first_recipe.recipe_id, second_recipe.recipe_id);
}

#[test]
fn genesis_spawn_groups_must_follow_first_output_order() {
    let source = r#"
            state PairState {
                int value;
            }

            state LauncherState {
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch()
                spawns first by first_id {
                    outputs {
                        pair: self.pair_type,
                    }
                }
                spawns second by second_id {
                    outputs {
                        pair: self.pair_type,
                    }
                }
                emits next: Launcher {
                    unrestricted(first.outputs.pair.value);
                    unrestricted(second.outputs.pair.value);
                    unrestricted(next.value);
                    PairState pair_state = { value: 1 };
                    require first.outputs become {
                        pair <- self.pair_type(pair_state),
                    };
                    require second.outputs become {
                        pair <- self.pair_type(pair_state),
                    };
                    become next <- self;
                }
            }

            app Test {
                actor Launcher;
            }
        "#;
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let sil = emit_actor(model.actor("Launcher").expect("launcher exists"), &model).expect("Launcher emits");
    assert!(sil.contains("require(gen__first_pair_output_idx < gen__second_pair_output_idx);"), "{sil}");
    let actor_sil = actor_sil_for_model(&model);
    emit_artifact(&program, &model, &actor_sil).expect("generated Sil compiles");
}

#[test]
fn rejects_actor_type_parameter_shadowing_same_named_app_actor() {
    let err = parse_and_validate(
        r#"
            state LauncherState {
                int launches;
            }

            state ChildState {
                int amount;
            }

            actor Launcher owns LauncherState {
                entry launch(actor_type<ChildState> Child)
                spawns child_group by child_id {
                    outputs {
                        child: Child,
                    }
                }
                emits next: Launcher {
                    unrestricted(child_group.outputs.child.value);
                    unrestricted(next.value);
                    ChildState child_state = { amount: 1 };
                    LauncherState next_state = { launches: launches + 1 };
                    require child_group.outputs become {
                        child <- Child(child_state),
                    };
                    become next <- Launcher(next_state);
                }
            }

            actor Child owns ChildState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            app Test {
                actor Launcher;
                actor Child;
            }
            "#,
    )
    .expect_err("actor_type parameters must not shadow actor references");

    assert_eq!(
        err.message,
        "entry `Launcher::launch` actor_type parameter `Child` shadows an actor reference with the same name; rename the parameter"
    );
}

#[test]
fn fixed_actor_spawn_uses_compiler_owned_template_and_keeps_its_closure() {
    let source = r#"
            state LauncherState {
                int launches;
            }

            state ChildState {
                int amount;
            }

            actor Launcher owns LauncherState {
                entry launch(int amount)
                spawns child_group by child_id {
                    outputs {
                        child: Child,
                        sibling: Child,
                    }
                }
                emits next: Launcher {
                    unrestricted(child_group.outputs.child.value);
                    unrestricted(child_group.outputs.sibling.value);
                    unrestricted(next.value);
                    ChildState child_state = { amount: amount };
                    ChildState sibling_state = { amount: amount + 1 };
                    LauncherState next_state = { launches: launches + 1 };
                    require child_group.outputs become {
                        child <- Child(child_state),
                        sibling <- Child(sibling_state),
                    };
                    become next <- Launcher(next_state);
                }
            }

            // The spawned actor itself needs Launcher's template for its
            // normal successor, exercising the spawned template closure.
            actor Child owns ChildState {
                entry return_to_launcher() emits next: Launcher {
                    unrestricted(next.value);
                    LauncherState next_state = { launches: 0 };
                    become next <- Launcher(next_state);
                }
            }

            app Test {
                actor Launcher;
                actor Child;
            }
        "#;
    let artifact = inline_artifact("fixed_actor_spawn", source);
    let launcher = artifact.argent.actors.iter().find(|actor| actor.name == "Launcher").expect("Launcher artifact exists");
    assert_eq!(launcher.entries[0].spawns[0].outputs[0].actor, "Child");
    assert_eq!(
        launcher.entries[0]
            .hidden_params
            .iter()
            .filter(|param| {
                matches!(
                    param.purpose,
                    HiddenParamPurposeArtifact::TemplatePrefixBytes | HiddenParamPurposeArtifact::TemplateSuffixBytes
                )
            })
            .count(),
        2,
        "two fixed outputs for one actor share one prefix/suffix pair"
    );
    assert!(launcher.entries[0].hidden_params.iter().any(|param| {
        param.name == "gen__child_prefix" && param.subject == HiddenParamSubjectArtifact::Actor { actor: "Child".to_string() }
    }));
    assert!(!launcher.entries[0].hidden_params.iter().any(|param| {
        matches!(param.subject, HiddenParamSubjectArtifact::SpawnActor { .. })
            && matches!(
                param.purpose,
                HiddenParamPurposeArtifact::TemplatePrefixBytes | HiddenParamPurposeArtifact::TemplateSuffixBytes
            )
    }));
    artifact.check_template_plan_consistency().expect("fixed spawn template closure verifies");
    let mut malformed = artifact.clone();
    malformed.argent.actors[0].entries[0].hidden_params.retain(|param| param.name != "gen__child_suffix");
    assert!(
        matches!(malformed.check_template_plan_consistency(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
        "static spawn metadata must retain one complete actor-scoped template pair"
    );

    let unselected = source.replace("                actor Child;\n", "");
    let err = parse_and_validate(&unselected).expect_err("fixed spawn actor must belong to the selected app");
    assert!(err.to_string().contains("selected-app or linked actor"), "unexpected error: {err}");
}

#[test]
fn fixed_actor_spawn_reuses_consumed_template_in_pinned_sil() {
    let source = "tests/fixtures/runtime/context_static_actor_spawn/app.ag";
    let (launcher_sil, launcher_artifact) = emit_selected_fixture(source, "StaticActorSpawn", "Launcher");
    let (child_sil, _) = emit_selected_fixture(source, "StaticActorSpawn", "Child");

    assert_eq!(launcher_sil, include_str!("../../../../tests/fixtures/runtime/context_static_actor_spawn/Launcher.sil"));
    assert_eq!(child_sil, include_str!("../../../../tests/fixtures/runtime/context_static_actor_spawn/Child.sil"));
    let launch = launcher_artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "launch").expect("launch entry exists");
    assert_eq!(
        launch.hidden_params.iter().map(|param| (param.name.as_str(), &param.subject, param.purpose)).collect::<Vec<_>>(),
        vec![
            (
                "gen__child_prefix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Child".to_string() },
                HiddenParamPurposeArtifact::TemplatePrefixLen,
            ),
            (
                "gen__child_suffix_len",
                &HiddenParamSubjectArtifact::Actor { actor: "Child".to_string() },
                HiddenParamPurposeArtifact::TemplateSuffixLen,
            ),
            (
                "gen__child_group_child_output_idx",
                &HiddenParamSubjectArtifact::SpawnActor {
                    spawn: "child_group".to_string(),
                    handle: "child".to_string(),
                    actor: "Child".to_string(),
                },
                HiddenParamPurposeArtifact::SpawnOutputIndex,
            ),
        ]
    );
    launcher_artifact.check_template_plan_consistency().expect("pinned fixed-spawn template plan verifies");
}

#[test]
fn fixed_actor_self_spawn_uses_the_active_template() {
    let artifact = inline_artifact(
        "fixed_actor_self_spawn",
        r#"
            state NodeState {
                int amount;
            }

            actor Node owns NodeState {
                entry fork(int next_amount)
                spawns child_group by child_id {
                    outputs {
                        child: Node,
                    }
                }
                emits next: Node {
                    unrestricted(child_group.outputs.child.value);
                    unrestricted(next.value);
                    NodeState child_state = { amount: next_amount };
                    NodeState next_state = { amount: next_amount + 1 };
                    require child_group.outputs become {
                        child <- Node(child_state),
                    };
                    become next <- Node(next_state);
                }
            }

            app Test {
                actor Node;
            }
            "#,
    );

    assert!(runtime_state_plan(&artifact, "Node").is_none(), "self-spawning Node needs no stored route context");
    let fork = artifact.argent.actors[0].entries.iter().find(|entry| entry.name == "fork").expect("fork entry exists");
    assert!(!fork.hidden_params.iter().any(|param| {
        matches!(
            param.purpose,
            HiddenParamPurposeArtifact::TemplatePrefixBytes
                | HiddenParamPurposeArtifact::TemplateSuffixBytes
                | HiddenParamPurposeArtifact::TemplatePrefixLen
                | HiddenParamPurposeArtifact::TemplateSuffixLen
        )
    }));
    artifact.check_template_plan_consistency().expect("fixed self-spawn template plan verifies");
}

#[test]
fn fixed_actor_spawn_opens_the_target_family_cut() {
    let artifact = inline_artifact(
        "fixed_actor_spawn_family",
        r#"
            state LauncherState {
                int launches;
            }

            state BoardState {
                int turn;
            }

            actor Launcher owns LauncherState {
                entry launch()
                spawns game by game_id {
                    outputs {
                        mux: Mux,
                    }
                }
                emits next: Launcher {
                    unrestricted(game.outputs.mux.value);
                    unrestricted(next.value);
                    BoardState board = { turn: 0 };
                    LauncherState next_state = { launches: launches + 1 };
                    require game.outputs become {
                        mux <- Mux(board),
                    };
                    become next <- Launcher(next_state);
                }
            }

            actor Mux owns BoardState {
                entry move() emits next: Pawn {
                    unrestricted(next.value);
                    BoardState next_state = { turn: turn + 1 };
                    become next <- Pawn(next_state);
                }
            }

            actor Pawn owns BoardState {
                entry finish() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_state = { turn: turn + 1 };
                    become next <- Mux(next_state);
                }
            }

            actor Knight owns BoardState {
                entry finish() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_state = { turn: turn + 2 };
                    become next <- Mux(next_state);
                }
            }

            app Test {
                actor Launcher;
                actor Mux;
                actor Pawn;
                actor Knight;
            }
            "#,
    );

    let launcher = artifact.argent.actors.iter().find(|actor| actor.name == "Launcher").expect("Launcher artifact exists");
    let launch = launcher.entries.iter().find(|entry| entry.name == "launch").expect("launch entry exists");
    assert!(launch.hidden_params.iter().any(|param| param.purpose == HiddenParamPurposeArtifact::RouteFamilyTable));
    assert!(launch.hidden_params.iter().any(|param| {
        param.name == "gen__mux_prefix" && param.subject == HiddenParamSubjectArtifact::Actor { actor: "Mux".to_string() }
    }));
    assert!(launch.hidden_params.iter().any(|param| {
        param.name == "gen__mux_suffix" && param.subject == HiddenParamSubjectArtifact::Actor { actor: "Mux".to_string() }
    }));
    artifact.check_template_plan_consistency().expect("fixed family spawn template plan verifies");
}

#[test]
fn rejects_spawn_name_shared_with_observe() {
    let err = parse_and_validate(
        r#"
            state PairState {}
            state LauncherState {
                cov_id observed_id;
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch()
                observes pair by self.observed_id {}
                spawns pair by pair_id {
                    outputs {
                        next_pair: self.pair_type,
                    }
                }
                emits next: Launcher {
                    unrestricted(pair.outputs.next_pair.value);
                    unrestricted(next.value);
                    require(1 == 1);
                    become next <- self;
                }
            }

            app Test {
                actor Launcher;
            }
            "#,
    )
    .expect_err("observe and spawn names must not be ambiguous");

    assert!(err.to_string().contains("uses `pair` as both an observe and a spawn"), "unexpected error: {err}");
}

#[test]
fn rejects_spawn_covenant_binding_shared_with_source_value() {
    let err = parse_and_validate(
        r#"
            state PairState {}
            state LauncherState {
                cov_id pair_id;
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch()
                spawns pair by pair_id {
                    outputs {
                        next_pair: self.pair_type,
                    }
                }
                emits next: Launcher {
                    unrestricted(pair.outputs.next_pair.value);
                    unrestricted(next.value);
                    require(1 == 1);
                    become next <- self;
                }
            }

            app Test {
                actor Launcher;
            }
            "#,
    )
    .expect_err("spawn covenant bindings must not shadow source values");

    assert!(err.to_string().contains("spawn covenant binding `pair_id` collides with a source value"), "unexpected error: {err}");
}

#[test]
fn rejects_compiler_fixture_with_ambiguous_actor_template_frames() {
    let program = load_fixture_program("template_frame_ambiguity");
    let model = Model::from_program(&program).expect("fixture model validates");
    let actor_sil = actor_sil_for_model(&model);

    let error = emit_artifact(&program, &model, &actor_sil).expect_err("indistinguishable actors must fail artifact construction");
    let message = error.to_string();
    for expected in [
        "invalid generated artifact",
        "conservative frame rule found an ambiguity",
        "actors `Alpha`",
        "`Beta`",
        "prefix length",
        "state length",
        "suffix length",
        "total length",
    ] {
        assert!(message.contains(expected), "missing `{expected}` in compiler diagnostic: {message}");
    }
}

#[test]
fn normal_multi_actor_app_has_distinct_template_frames() {
    let artifact = inline_artifact(
        "distinct-template-frames",
        r#"
            state SharedState {
                int count;
            }

            actor Alpha owns SharedState {
                entry inspect() emits none {
                    require(count >= 0);
                }
            }

            actor Beta owns SharedState {
                entry inspect() emits none {
                    require(count >= 1);
                }
            }

            app DistinctFrames {
                actor Alpha;
                actor Beta;
            }
        "#,
    );

    artifact.verify_template_frames().expect("ordinary distinct actor scripts verify");
}

fn emit_fixture(case: &str, actor: &str) -> (String, Artifact) {
    let program = load_fixture_program(case);
    let model = Model::from_program(&program).expect("fixture model validates");
    let actor = model.actor(actor).expect("fixture actor exists");
    let sil = emit_actor(actor, &model).expect("fixture actor emits");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("fixture artifact emits");
    (sil, artifact)
}

fn load_fixture_program(case: &str) -> Program {
    let path = PathBuf::from("tests/fixtures/emit").join(case).join("app.ag");
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&path)).expect("fixture source exists");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source).expect("fixture source parses");
    Program { root: path, modules: vec![module] }
}

fn emit_fixture_manifest(case: &str) -> serde_json::Value {
    let program = load_fixture_program(case);
    let model = Model::from_program(&program).expect("fixture model validates");
    serde_json::from_str(&emit_manifest(&program, &model)).expect("fixture manifest is valid JSON")
}

fn assert_fixture_artifact(case: &str, artifact: &Artifact) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/emit").join(case).join("artifact.json");
    let expected = fs::read_to_string(path).expect("fixture artifact exists");
    let mut actual = silverscript_abi::to_pretty_json(artifact).expect("fixture artifact serializes");
    actual.push('\n');
    assert_eq!(actual, expected);
}

fn emit_selected_fixture(path: &str, app: &str, actor: &str) -> (String, Artifact) {
    let path = PathBuf::from(path);
    let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&path)).expect("fixture source exists");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source).expect("fixture source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program_app(&program, app).expect("selected fixture model validates");
    let actor = model.actor(actor).expect("selected fixture actor exists");
    let sil = emit_actor(actor, &model).expect("selected fixture actor emits");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("selected fixture artifact emits");
    (sil, artifact)
}

fn emit_inline_error(source: &str) -> ArgentError {
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    for actor in &model.actors {
        if let Err(err) = emit_actor(actor, &model) {
            return err;
        }
    }
    panic!("expected inline source to fail during emission")
}

fn emit_inline_actor(source: &str, actor_name: &str) -> String {
    let path = PathBuf::from("inline-emission.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
    let program = Program { root: path, modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor(actor_name).expect("actor exists");
    emit_actor(actor, &model).expect("actor emits")
}

fn parse_and_validate(source: &str) -> Result<()> {
    let path = PathBuf::from("test.ag");
    let module = crate::compiler::syntax::parser::parse_module(path.clone(), source.to_string())?;
    let program = Program { root: path, modules: vec![module] };
    Model::from_program(&program).map(|_| ())
}

fn toy_chess_source() -> String {
    r#"
            state LeagueState {
                int nonce;
            }

            state PlayerState {
                int nonce;
            }

            state BoardState {
                int selector;
                int ply;
            }

            actor enum MoveActor {
                Pawn;
                Knight;
            }

            actor League owns LeagueState {
                entry register() emits next: Player {
                    unrestricted(next.value);
                    PlayerState next_player = {
                        nonce: nonce,
                    };
                    become next <- Player(next_player);
                }
            }

            actor Player owns PlayerState {
                entry enter_mux() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: nonce,
                        ply: 0,
                    };
                    become next <- Mux(next_board);
                }
            }

            actor Mux owns BoardState {
                entry choose(MoveActor target) emits next: MoveActor {
                    unrestricted(next.value);
                    if (target == MoveActor::Knight) {
                        require(selector >= 0);
                    }

                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };

                    become next <- target(next_board);
                }

                entry choose_knight_const() emits next: MoveActor {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };

                    actor_type<BoardState> target = MoveActor::Knight;
                    become next <- target(next_board);
                }

                entry choose_pawn() emits next: Pawn {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- Pawn(next_board);
                }

                entry choose_knight() emits next: Knight {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- Knight(next_board);
                }
            }

            actor Pawn owns BoardState {
                entry back_to_mux() emits next: Mux {
                    unrestricted(next.value);
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- Mux(next_board);
                }
            }

            actor Knight owns BoardState {
                entry back_to_mux() emits next: Mux {
                    unrestricted(next.value);
                    require(selector >= 0);

                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become next <- Mux(next_board);
                }
            }

            app ToyChess {
                actor League;
                actor Player;
                actor Mux;
                actor Pawn;
                actor Knight;
            }
            "#
    .to_string()
}

#[test]
fn artifact_codec_uses_compiled_sil_dispatch_tags() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state FooState {
                int count;
                byte[4] tag;
                bool flag;
            }

            actor Foo owns FooState {
                entry bump(int amount, byte[4] next_tag, bool next_flag, byte b) emits none {
                    require(amount >= 0);
                }

                entry done() emits none {
                    require(1 == 1);
                }
            }

            app Test {
                actor Foo;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor = model.actor("Foo").expect("actor exists");
    let actor_sil = actor_sil_for_model(&model);
    let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");
    let sil_abi_json = serde_json::to_string(&artifact.sil_abi).expect("Sil ABI artifact serializes");
    let sil_abi: SilAbiArtifact = serde_json::from_str(&sil_abi_json).expect("Sil ABI artifact deserializes");
    sil_abi.check_schema_version().expect("Sil ABI schema version is current");
    let sil = actor_sil.get("Foo").expect("Foo Sil exists");
    let constructor_args = constructor_args_for_actor(actor, &model).expect("constructor args build");
    let compiled = compile_contract(sil, &constructor_args, CompileOptions::default()).expect("generated Sil compiles");

    let sil_contract = sil_abi.contract("Foo").expect("Foo Sil ABI exists");
    let bump = sil_contract.entry("bump").expect("bump entry exists");
    let done = sil_contract.entry("done").expect("done entry exists");
    assert_eq!(bump.dispatch_tag.into_bytes(), compiled.dispatch_tags["bump"]);
    assert_eq!(done.dispatch_tag.into_bytes(), compiled.dispatch_tags["done"]);

    let portable_bump = crate::codec::encode_contract_entry_sig_script(
        &sil_abi,
        "Foo",
        "bump",
        &[
            crate::codec::ArtifactValue::Int(17),
            crate::codec::ArtifactValue::Bytes(vec![1, 2, 3, 4]),
            crate::codec::ArtifactValue::Bool(true),
            crate::codec::ArtifactValue::Byte(1),
        ],
    )
    .expect("portable bump sigscript builds");
    assert_eq!(encode_hex(&portable_bump), "011104010203045151045bdffea8");

    let portable_done =
        crate::codec::encode_contract_entry_sig_script(&sil_abi, "Foo", "done", &[]).expect("portable done sigscript builds");
    assert_eq!(portable_done, [vec![4], done.dispatch_tag.as_bytes().to_vec()].concat());
}

#[test]
fn sil_signature_builtins_pass_through() {
    let module = crate::compiler::syntax::parser::parse_module(
        PathBuf::from("test.ag"),
        r#"
            state AuthState {
                int nonce;
            }

            actor Auth owns AuthState {
                entry verify(
                    sig tx_signature,
                    byte[33] ecdsa_key,
                    datasig message_signature,
                    byte[32] digest,
                    pubkey schnorr_key,
                ) emits none {
                    require(checkSig(tx_signature, schnorr_key));
                    require(checkSigEcdsa(tx_signature, ecdsa_key));
                    require(checkMsgSig(message_signature, digest, schnorr_key));
                    require(checkMsgSigEcdsa(message_signature, digest, ecdsa_key));
                }
            }

            app Test {
                actor Auth;
            }
            "#
        .to_string(),
    )
    .expect("source parses");
    let program = Program { root: PathBuf::from("test.ag"), modules: vec![module] };
    let model = Model::from_program(&program).expect("model validates");
    let actor_sil = actor_sil_for_model(&model);
    let sil = actor_sil.get("Auth").expect("Auth Sil exists");

    for call in ["checkSig(", "checkSigEcdsa(", "checkMsgSig(", "checkMsgSigEcdsa("] {
        assert!(sil.contains(call), "missing `{call}` in generated Sil:\n{sil}");
    }
    emit_artifact(&program, &model, &actor_sil).expect("generated Sil compiles");
}

#[test]
fn manifest_uses_relative_paths_when_possible() {
    let cwd = std::env::current_dir().expect("current dir");
    let mut program = test_program();
    program.root = cwd.join("examples/tickets.ag");
    program.modules[0].path = cwd.join("examples/tickets.ag");
    program.modules[0].actors[0].entries.clear();
    let model = Model::from_program(&program).expect("model validates");

    let manifest = emit_manifest(&program, &model);

    assert!(manifest.contains(r#""root": "examples/tickets.ag""#), "{manifest}");
    assert!(manifest.contains(r#""examples/tickets.ag""#), "{manifest}");
    assert!(!manifest.contains(&display_path(&cwd)), "{manifest}");
}

#[test]
fn generated_snake_suffixes_preserve_acronym_runs() {
    assert_eq!(to_snake("MinterProxy"), "minter_proxy");
    assert_eq!(to_snake("KCC20"), "kcc20");
    assert_eq!(to_snake("KCC20Minter"), "kcc20_minter");
}

fn assert_duplicate_top_level_error(err: &ArgentError, kind: &str, name: &str) {
    let message = err.to_string();
    assert!(message.contains(&format!("duplicate top-level {kind} `{name}`")), "unexpected error: {err}");
    assert!(message.contains("second.ag"), "expected duplicate path in error: {err}");
    assert!(message.contains("test.ag"), "expected first declaration path in error: {err}");
}

fn empty_module(path: &str) -> Module {
    Module {
        path: PathBuf::from(path),
        imports: Vec::new(),
        consts: Vec::new(),
        states: Vec::new(),
        functions: Vec::new(),
        actors: Vec::new(),
        actor_enums: Vec::new(),
        apps: Vec::new(),
    }
}

fn actor_sil_for_model(model: &Model<'_>) -> BTreeMap<String, String> {
    model.actors.iter().map(|actor| (actor.name.clone(), emit_actor(actor, model).expect("actor emits"))).collect()
}

fn assert_example_build_artifact(input: &str, name: &str, expected_hashes: &[(&str, &str)]) {
    let out_dir = std::env::temp_dir().join(format!("argent-{name}-artifact-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);

    let artifact = crate::build_file(input, &out_dir).expect("example builds");
    artifact.check_schema_version().expect("artifact schema version is supported");
    artifact.check_template_plan_consistency().expect("template plan receipt verifies");

    let expected_hashes = expected_hashes.iter().copied().collect::<BTreeMap<_, _>>();
    assert!(!artifact.argent.actors.is_empty(), "artifact should contain Argent actors");
    for actor in &artifact.argent.actors {
        let sil_contract = artifact
            .sil_abi
            .contract(&actor.abi.contract)
            .unwrap_or_else(|| panic!("actor `{}` should reference a Sil ABI contract", actor.name));
        assert_compiled_projection(&actor.abi.contract, &sil_contract.compiled);
        assert_runtime_state_round_trip(&artifact.sil_abi, &actor.abi.contract, sil_contract, &sil_contract.compiled);
        if let Some(expected_hash) = expected_hashes.get(actor.abi.contract.as_str()) {
            assert_eq!(
                &encode_hex(&sil_contract.compiled.template_hash),
                expected_hash,
                "actor `{}` template hash changed",
                actor.name
            );
        }
    }

    let _ = fs::remove_dir_all(out_dir);
}

fn assert_runtime_state_round_trip(
    abi: &SilAbiArtifact,
    actor: &str,
    contract: &SilContractArtifact,
    compiled: &CompiledContractArtifact,
) {
    let (_, state_script, _) = compiled.script_parts(&compiled.bytecode).expect("state span fits the compiled script");
    let state_values =
        crate::codec::decode_runtime_state_script(abi, &contract.runtime_state, state_script).expect("runtime state decodes");
    let reencoded =
        crate::codec::encode_runtime_state_script(abi, &contract.runtime_state, &state_values).expect("runtime state re-encodes");
    assert_eq!(reencoded, state_script, "actor `{actor}` runtime state must re-encode byte-for-byte");
}

fn assert_compiled_projection(actor: &str, compiled: &CompiledContractArtifact) {
    assert!(!compiled.bytecode.is_empty(), "actor `{actor}` should have script bytes");
    assert!(compiled.state_span.len > 0, "actor `{actor}` should have a non-empty state span");

    let (prefix, _, suffix) = compiled.script_parts(&compiled.bytecode).expect("state span fits the compiled script");
    let template_hash = silverscript_lang::template::template_hash(prefix, suffix);
    assert_eq!(template_hash, compiled.template_hash, "actor `{actor}` template hash must use the Sil template hash");
}

fn runtime_state_plan<'a>(artifact: &'a Artifact, contract: &str) -> Option<&'a RuntimeStatePlanArtifact> {
    artifact.argent.template_plan.runtime_states.iter().find(|state| state.contract == contract)
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

fn test_program() -> Program {
    Program {
        root: PathBuf::from("test.ag"),
        modules: vec![Module {
            path: PathBuf::from("test.ag"),
            imports: Vec::new(),
            consts: Vec::new(),
            states: vec![
                StateDecl { name: "PlayerState".to_string(), fields: Vec::new(), expansion: None },
                StateDecl { name: "GameState".to_string(), fields: Vec::new(), expansion: None },
            ],
            functions: Vec::new(),
            actors: vec![
                ActorDecl {
                    name: "Player".to_string(),
                    state: "PlayerState".to_string(),
                    functions: Vec::new(),
                    entries: vec![EntryDecl {
                        kind: EntryKind::Leader,
                        name: "step".to_string(),
                        params: Vec::new(),
                        consumes: Vec::new(),
                        observes: Vec::new(),
                        spawns: Vec::new(),
                        emits: EmitSpec::Outputs(vec![EmitOutput {
                            name: "next".to_string(),
                            actors: vec!["Player".to_string()],
                            cardinality: Cardinality::One,
                            auth_index: 0,
                        }]),
                        body: EntryBody::default(),
                        routes: Vec::new(),
                        terminal_route_sets: Vec::new(),
                    }],
                },
                ActorDecl { name: "Game".to_string(), state: "GameState".to_string(), functions: Vec::new(), entries: Vec::new() },
            ],
            actor_enums: Vec::new(),
            apps: vec![AppDecl { name: "Test".to_string(), actors: vec!["Player".to_string(), "Game".to_string()] }],
        }],
    }
}

fn set_entry_body(entry: &mut EntryDecl, source: &str) {
    let body = EntryBody::new(source).expect("test entry body parses");
    let analysis = crate::compiler::syntax::body::routes::analyze_entry_routes(&body).expect("test entry routes analyze");
    entry.body = body;
    entry.routes = analysis.routes;
    entry.terminal_route_sets = analysis.terminal_route_sets;
}

fn resolved_constructed_actor(route: &ResolvedRoute) -> &str {
    let ResolvedSuccessor::Constructed { actor, .. } = &route.successor else { panic!("expected constructed successor") };
    actor
}

fn artifact_constructed_actor(route: &RouteArtifact) -> &str {
    let RouteSuccessorArtifact::Constructed { actor, .. } = &route.successor else {
        panic!("expected constructed successor artifact")
    };
    actor
}
