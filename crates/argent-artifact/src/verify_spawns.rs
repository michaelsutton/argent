use crate::{EntryArtifact, HiddenParamPurposeArtifact, HiddenParamSubjectArtifact, SpawnOutputArtifact, TemplatePlanError};
use std::collections::{BTreeMap, BTreeSet};

/// Validated lookup state shared by the spawn-specific verification phases.
struct SpawnIndex<'a> {
    outputs: BTreeMap<(&'a str, &'a str), &'a SpawnOutputArtifact>,
    template_subjects: BTreeMap<&'a str, (&'a str, &'a str)>,
}

/// Verifies the complete spawn metadata contract for one entry.
///
/// On success, every declared spawn has a valid ordered output group, every
/// output has exactly one index witness, every distinct actor expression has
/// one shared prefix/suffix witness pair anchored to its first declared output,
/// and every spawn-related hidden parameter refers to a matching declaration.
/// Generic hidden-parameter-to-recipe matching remains the caller's concern.
pub(crate) fn verify_entry_spawns(entry_id: &str, entry: &EntryArtifact) -> Result<(), TemplatePlanError> {
    let index = index_spawn_outputs(entry_id, entry)?;
    verify_spawn_output_index_params(entry_id, entry, &index)?;
    verify_spawn_template_params(entry_id, entry, &index)?;
    verify_spawn_param_subjects(entry_id, entry, &index)
}

/// Validates and indexes the spawn declarations of one entry.
///
/// Spawn names and covenant bindings must be unique within the entry. Each
/// spawn must declare at least one output, output handles must be unique within
/// their spawn, and group indices must be contiguous in declaration order. The
/// returned template subject for an actor expression is its first declared
/// spawn output, matching the compiler's witness-deduplication rule.
fn index_spawn_outputs<'a>(entry_id: &str, entry: &'a EntryArtifact) -> Result<SpawnIndex<'a>, TemplatePlanError> {
    let mut spawn_names = BTreeSet::new();
    let mut spawn_covenants = BTreeSet::new();
    let mut outputs = BTreeMap::new();
    let mut template_subjects = BTreeMap::new();

    for spawn in &entry.spawns {
        if !spawn_names.insert(spawn.name.as_str()) {
            return Err(invalid_spawn_metadata(entry_id, format!("duplicate spawn `{}`", spawn.name)));
        }
        if !spawn_covenants.insert(spawn.covenant.as_str()) {
            return Err(invalid_spawn_metadata(entry_id, format!("duplicate covenant binding `{}`", spawn.covenant)));
        }
        if spawn.outputs.is_empty() {
            return Err(invalid_spawn_metadata(entry_id, format!("spawn `{}` has no outputs", spawn.name)));
        }

        for (expected_index, output) in spawn.outputs.iter().enumerate() {
            if output.group_index != expected_index {
                return Err(invalid_spawn_metadata(
                    entry_id,
                    format!(
                        "spawn `{}.{}` has group index {}, expected {expected_index}",
                        spawn.name, output.name, output.group_index
                    ),
                ));
            }
            if outputs.insert((spawn.name.as_str(), output.name.as_str()), output).is_some() {
                return Err(invalid_spawn_metadata(entry_id, format!("spawn `{}` repeats output `{}`", spawn.name, output.name)));
            }
            template_subjects.entry(output.actor.as_str()).or_insert((spawn.name.as_str(), output.name.as_str()));
        }
    }

    Ok(SpawnIndex { outputs, template_subjects })
}

/// Requires exactly one output-index hidden parameter for each spawned output.
///
/// The parameter subject must identify the declaration by spawn name, output
/// handle, and actor expression. This gives the runtime one unambiguous global
/// transaction index to resolve for every member of the genesis output group.
fn verify_spawn_output_index_params(entry_id: &str, entry: &EntryArtifact, index: &SpawnIndex<'_>) -> Result<(), TemplatePlanError> {
    for ((spawn, handle), output) in &index.outputs {
        let subject = HiddenParamSubjectArtifact::SpawnActor {
            spawn: (*spawn).to_string(),
            handle: (*handle).to_string(),
            actor: output.actor.clone(),
        };
        let count = entry
            .hidden_params
            .iter()
            .filter(|param| param.subject == subject && param.purpose == HiddenParamPurposeArtifact::SpawnOutputIndex)
            .count();
        if count != 1 {
            return Err(invalid_spawn_metadata(
                entry_id,
                format!(
                    "spawn `{spawn}.{handle}` has {count} hidden params for {:?}, expected one",
                    HiddenParamPurposeArtifact::SpawnOutputIndex
                ),
            ));
        }
    }
    Ok(())
}

/// Requires one shared template prefix and suffix parameter per actor expression.
///
/// Repeated outputs with the same actor expression reuse template material. The
/// unique prefix and suffix parameters must therefore use the first such output
/// in declaration order as their common subject.
fn verify_spawn_template_params(entry_id: &str, entry: &EntryArtifact, index: &SpawnIndex<'_>) -> Result<(), TemplatePlanError> {
    for (actor_expr, (spawn, handle)) in &index.template_subjects {
        let subject = HiddenParamSubjectArtifact::SpawnActor {
            spawn: (*spawn).to_string(),
            handle: (*handle).to_string(),
            actor: (*actor_expr).to_string(),
        };
        for purpose in [HiddenParamPurposeArtifact::TemplatePrefixBytes, HiddenParamPurposeArtifact::TemplateSuffixBytes] {
            let params = entry
                .hidden_params
                .iter()
                .filter(|param| {
                    matches!(
                        &param.subject,
                        HiddenParamSubjectArtifact::SpawnActor { actor, .. } if actor == actor_expr
                    ) && param.purpose == purpose
                })
                .collect::<Vec<_>>();
            if params.len() != 1 {
                return Err(invalid_spawn_metadata(
                    entry_id,
                    format!("spawn actor expression `{actor_expr}` has {} hidden params for {purpose:?}, expected one", params.len()),
                ));
            }
            if params[0].subject != subject {
                return Err(invalid_spawn_metadata(
                    entry_id,
                    format!(
                        "spawn actor expression `{actor_expr}` {purpose:?} must use first output `{spawn}.{handle}` as its subject"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Rejects orphaned or semantically invalid spawn hidden parameters.
///
/// A spawn subject must resolve to a declared output with the same actor
/// expression and may only provide its output index or shared template bytes.
/// Conversely, an output-index purpose is valid only with a spawn subject.
fn verify_spawn_param_subjects(entry_id: &str, entry: &EntryArtifact, index: &SpawnIndex<'_>) -> Result<(), TemplatePlanError> {
    for param in &entry.hidden_params {
        if let HiddenParamSubjectArtifact::SpawnActor { spawn, handle, actor } = &param.subject {
            let Some(output) = index.outputs.get(&(spawn.as_str(), handle.as_str())) else {
                return Err(invalid_spawn_metadata(
                    entry_id,
                    format!("hidden param `{}` references unknown spawn output `{spawn}.{handle}`", param.name),
                ));
            };
            if actor != &output.actor
                || !matches!(
                    param.purpose,
                    HiddenParamPurposeArtifact::SpawnOutputIndex
                        | HiddenParamPurposeArtifact::TemplatePrefixBytes
                        | HiddenParamPurposeArtifact::TemplateSuffixBytes
                )
            {
                return Err(invalid_spawn_metadata(
                    entry_id,
                    format!("hidden param `{}` does not match spawn output `{spawn}.{handle}`", param.name),
                ));
            }
        } else if param.purpose == HiddenParamPurposeArtifact::SpawnOutputIndex {
            return Err(invalid_spawn_metadata(
                entry_id,
                format!("spawn output index param `{}` has a non-spawn subject", param.name),
            ));
        }
    }
    Ok(())
}

/// Constructs a spawn-scoped template-plan error for the current entry.
fn invalid_spawn_metadata(entry_id: &str, message: String) -> TemplatePlanError {
    TemplatePlanError::InvalidSpawnMetadata { entry: entry_id.to_string(), message }
}
