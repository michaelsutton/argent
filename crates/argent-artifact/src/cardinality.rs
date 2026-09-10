//! Checks interaction cardinalities stored in portable Argent artifacts.
//! The checks cover valid bounds and the range shapes supported by the current
//! compiler and runtime.

use thiserror::Error;

use crate::{Artifact, CardinalityArtifact, EmitArtifact, EntryKindArtifact};

/// Maximum range cardinality accepted by Argent compilers and runtimes.
///
/// Keeping the limit in the portable artifact layer prevents compiler and
/// consumer implementations from drifting on generated-loop resource bounds.
pub const MAX_ENTRY_RANGE_CARDINALITY: i64 = 512;

/// Invalid or currently unsupported entry cardinality in an Argent artifact.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactCardinalityError {
    #[error("entry `{actor}::{entry}` has invalid cardinality {minimum}..={maximum} for {section} `{handle}`")]
    InvalidRange { actor: String, entry: String, section: &'static str, handle: String, minimum: i64, maximum: i64 },
    #[error("entry `{actor}::{entry}` uses unsupported ranged {section} interaction `{handle}`")]
    UnsupportedRange { actor: String, entry: String, section: &'static str, handle: String },
}

impl Artifact {
    /// Checks that every interaction range has valid bounds and uses a
    /// cardinality shape supported by the current compiler and runtime.
    ///
    /// A leader entry may have at most one ranged consume and at most one
    /// ranged emit. A ranged emit must resolve to one actor, not an actor union
    /// or actor-enum domain. Delegate consumes, observe inputs and outputs, and
    /// spawn outputs must be singletons.
    ///
    /// Transaction-specific input and output counts are checked when a runtime
    /// context is bound.
    pub fn check_cardinality_consistency(&self) -> Result<(), ArtifactCardinalityError> {
        for actor in &self.argent.actors {
            for entry in &actor.entries {
                let check = |section, handle: &str, cardinality| {
                    if let CardinalityArtifact::Range { minimum, maximum } = cardinality
                        && (minimum < 0 || minimum > maximum || maximum > MAX_ENTRY_RANGE_CARDINALITY)
                    {
                        return Err(ArtifactCardinalityError::InvalidRange {
                            actor: actor.name.clone(),
                            entry: entry.name.clone(),
                            section,
                            handle: handle.to_string(),
                            minimum,
                            maximum,
                        });
                    }
                    Ok(())
                };
                let reject_unsupported_range = |section, handle: &str, cardinality| {
                    check(section, handle, cardinality)?;
                    if matches!(cardinality, CardinalityArtifact::Range { .. }) {
                        return Err(ArtifactCardinalityError::UnsupportedRange {
                            actor: actor.name.clone(),
                            entry: entry.name.clone(),
                            section,
                            handle: handle.to_string(),
                        });
                    }
                    Ok(())
                };

                let mut has_consume_range = false;
                for consume in &entry.consumes {
                    if entry.kind == EntryKindArtifact::Delegate {
                        reject_unsupported_range("delegate consume", &consume.name, consume.cardinality)?;
                    } else {
                        check("consume", &consume.name, consume.cardinality)?;
                        if matches!(consume.cardinality, CardinalityArtifact::Range { .. }) {
                            if has_consume_range {
                                reject_unsupported_range("consume", &consume.name, consume.cardinality)?;
                            }
                            has_consume_range = true;
                        }
                    }
                }
                if let EmitArtifact::Outputs { outputs } = &entry.emits {
                    let mut has_emit_range = false;
                    for output in outputs {
                        check("emit", &output.name, output.cardinality)?;
                        if matches!(output.cardinality, CardinalityArtifact::Range { .. }) {
                            if has_emit_range || output.actors.len() != 1 {
                                reject_unsupported_range("emit", &output.name, output.cardinality)?;
                            }
                            has_emit_range = true;
                        }
                    }
                }
                for observe in &entry.observes {
                    for input in &observe.inputs {
                        reject_unsupported_range("observed input", &format!("{}.{}", observe.name, input.name), input.cardinality)?;
                    }
                    for output in &observe.outputs {
                        reject_unsupported_range("observed output", &format!("{}.{}", observe.name, output.name), output.cardinality)?;
                    }
                }
                for spawn in &entry.spawns {
                    for output in &spawn.outputs {
                        reject_unsupported_range("spawn output", &format!("{}.{}", spawn.name, output.name), output.cardinality)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        ARTIFACT_SCHEMA_VERSION, ActorAbiRefArtifact, ActorArtifact, ActorTargetArtifact, ArgentArtifact, ConsumeArtifact,
        CovenantIdSourceArtifact, EmitOutputArtifact, EntryAbiRefArtifact, EntryArtifact, EntryRoutePlanArtifact, GeneratorArtifact,
        InterfaceSetArtifact, ObserveArtifact, ObservedActorArtifact, SIL_ABI_SCHEMA_VERSION, SilAbiArtifact, SpawnArtifact,
        SpawnOutputArtifact, TemplatePlanArtifact,
    };

    #[test]
    fn accepts_supported_entry_ranges() {
        let mut artifact = artifact_with_entry();
        let entry = &mut artifact.argent.actors[0].entries[0];
        entry.consumes.push(ranged_consume("accounts", 0, 3));
        entry.emits = EmitArtifact::Outputs { outputs: vec![ranged_emit("next", &["Counter"], 1, 3)] };

        artifact.check_cardinality_consistency().expect("supported input and output ranges are consistent");
    }

    #[test]
    fn rejects_invalid_ranges() {
        for (minimum, maximum) in [(-1, 3), (4, 3), (0, MAX_ENTRY_RANGE_CARDINALITY + 1)] {
            let mut artifact = artifact_with_entry();
            artifact.argent.actors[0].entries[0].consumes.push(ranged_consume("accounts", minimum, maximum));

            assert_eq!(
                artifact.check_cardinality_consistency().expect_err("invalid range must be rejected"),
                ArtifactCardinalityError::InvalidRange {
                    actor: "Counter".to_string(),
                    entry: "merge".to_string(),
                    section: "consume",
                    handle: "accounts".to_string(),
                    minimum,
                    maximum,
                }
            );
        }
    }

    #[test]
    fn rejects_unsupported_range_shapes() {
        let mut delegate = artifact_with_entry();
        let entry = &mut delegate.argent.actors[0].entries[0];
        entry.kind = EntryKindArtifact::Delegate;
        entry.consumes.push(ranged_consume("accounts", 1, 3));
        assert_unsupported(delegate, "delegate consume", "accounts");

        let mut consumes = artifact_with_entry();
        consumes.argent.actors[0].entries[0].consumes = vec![ranged_consume("first", 0, 2), ranged_consume("second", 0, 2)];
        assert_unsupported(consumes, "consume", "second");

        let mut emits = artifact_with_entry();
        emits.argent.actors[0].entries[0].emits = EmitArtifact::Outputs {
            outputs: vec![ranged_emit("first", &["Counter"], 0, 2), ranged_emit("second", &["Counter"], 0, 2)],
        };
        assert_unsupported(emits, "emit", "second");

        let mut dynamic_emit = artifact_with_entry();
        dynamic_emit.argent.actors[0].entries[0].emits =
            EmitArtifact::Outputs { outputs: vec![ranged_emit("next", &["Counter", "Archive"], 0, 2)] };
        assert_unsupported(dynamic_emit, "emit", "next");

        let mut observed_input = artifact_with_entry();
        observed_input.argent.actors[0].entries[0].observes.push(ObserveArtifact {
            name: "asset".to_string(),
            covenant_expr: "asset_id".to_string(),
            covenant_id_source: CovenantIdSourceArtifact::StateField { field: "asset_id".to_string() },
            inputs: vec![ranged_observed_actor("inputs")],
            outputs: Vec::new(),
        });
        assert_unsupported(observed_input, "observed input", "asset.inputs");

        let mut observed_output = artifact_with_entry();
        observed_output.argent.actors[0].entries[0].observes.push(ObserveArtifact {
            name: "asset".to_string(),
            covenant_expr: "asset_id".to_string(),
            covenant_id_source: CovenantIdSourceArtifact::StateField { field: "asset_id".to_string() },
            inputs: Vec::new(),
            outputs: vec![ranged_observed_actor("outputs")],
        });
        assert_unsupported(observed_output, "observed output", "asset.outputs");

        let mut spawn = artifact_with_entry();
        spawn.argent.actors[0].entries[0].spawns.push(SpawnArtifact {
            name: "children".to_string(),
            covenant: "child_id".to_string(),
            outputs: vec![SpawnOutputArtifact {
                name: "items".to_string(),
                actor: "Counter".to_string(),
                state: "CounterState".to_string(),
                group_index: 0,
                cardinality: CardinalityArtifact::Range { minimum: 1, maximum: 3 },
                target: Some(static_actor_target()),
            }],
        });
        assert_unsupported(spawn, "spawn output", "children.items");
    }

    fn artifact_with_entry() -> Artifact {
        Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            dependencies: Vec::new(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: vec![ActorArtifact {
                    name: "Counter".to_string(),
                    state: "CounterState".to_string(),
                    abi: ActorAbiRefArtifact { contract: "Counter".to_string() },
                    leader_for: Vec::new(),
                    entries: vec![EntryArtifact {
                        name: "merge".to_string(),
                        kind: EntryKindArtifact::Leader,
                        abi: EntryAbiRefArtifact { contract: "Counter".to_string(), entry: "merge".to_string() },
                        route_plan: EntryRoutePlanArtifact::default(),
                        hidden_params: Vec::new(),
                        template_selectors: Vec::new(),
                        observes: Vec::new(),
                        spawns: Vec::new(),
                        witnesses: Vec::new(),
                        consumes: Vec::new(),
                        emits: EmitArtifact::None,
                        routes: Vec::new(),
                    }],
                }],
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                compiler_version: "test".to_string(),
                structs: BTreeMap::new(),
                contracts: BTreeMap::new(),
            },
        }
    }

    fn ranged_consume(name: &str, minimum: i64, maximum: i64) -> ConsumeArtifact {
        ConsumeArtifact {
            name: name.to_string(),
            actor: "Counter".to_string(),
            cardinality: CardinalityArtifact::Range { minimum, maximum },
        }
    }

    fn ranged_emit(name: &str, actors: &[&str], minimum: i64, maximum: i64) -> EmitOutputArtifact {
        EmitOutputArtifact {
            name: name.to_string(),
            auth_index: None,
            actors: actors.iter().map(|actor| (*actor).to_string()).collect(),
            cardinality: CardinalityArtifact::Range { minimum, maximum },
        }
    }

    fn ranged_observed_actor(name: &str) -> ObservedActorArtifact {
        ObservedActorArtifact {
            name: name.to_string(),
            target: static_actor_target(),
            cardinality: CardinalityArtifact::Range { minimum: 1, maximum: 3 },
        }
    }

    fn static_actor_target() -> ActorTargetArtifact {
        ActorTargetArtifact::StaticActor { app: "Tiny".to_string(), actor: "Counter".to_string() }
    }

    fn assert_unsupported(artifact: Artifact, section: &'static str, handle: &str) {
        assert_eq!(
            artifact.check_cardinality_consistency().expect_err("unsupported range shape must be rejected"),
            ArtifactCardinalityError::UnsupportedRange {
                actor: "Counter".to_string(),
                entry: "merge".to_string(),
                section,
                handle: handle.to_string(),
            }
        );
    }
}
