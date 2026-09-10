//! Emits one selected Argent app as Sil, artifact, and manifest files.
//!
//! This is the current source-text implementation of the codegen backend.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::artifact::*;
use crate::codec::encode_hex;
use crate::compiler::model::link::LinkedActor;
use crate::compiler::model::{
    ClauseActorTypeRef, CovenantGroup, CovenantIdSource, EntryInteraction, EntryModel, GeneratedFieldId, InteractionLocation,
    InteractionSource, Model, PhysicalFieldId, PhysicalStateLayout, ResolvedRoute, ResolvedSuccessor, RouteFamily, SilStateType,
    SourceStateId, StaticActorTarget, actor_enum_variant_const_expr, clause_actor_type_ref, observed_is_dynamic_binding,
    observed_open_state_for_decl, packed_field_len, resolve_observe_covenant_id_source, source_actor_type_state_for_expr,
    spawn_target_state,
};
use crate::compiler::naming::{is_identifier, to_snake};
use crate::compiler::syntax::body::RouteArity;
use crate::compiler::syntax::lexer::{RESERVED_GENERATED_PREFIX, RESERVED_GENERATED_TYPE_PREFIX, TokenKind, lex};
use crate::compiler::syntax::word;
use crate::compiler::syntax::*;
use crate::error::{ArgentError, Result};
use silverscript_lang::ast::Expr as SilExpr;
use silverscript_lang::compiler::{COMPILER_VERSION, CompileOptions, compile_contract, sil_abi_artifact_from_compiled};

use super::sil::{
    ContractStateValuePlan, EntryInputReferencePlan, EntryInputReferenceView, GlobalFunctionLowerer,
    audit_omitted_equivalent_state_structs, authored_state_payload_digest_expr, lower_entry_body, lower_entry_expr,
    lower_expression_state_types, lower_function_body_state_types, plan_actor_output_state, plan_entry_input_references,
    plan_open_output_state, plan_selector_output_state, reject_function_input_state_calls,
    reject_function_physical_state_constructors, validate_actor_function_captures,
};

#[cfg(test)]
mod tests;

pub fn emit_build(program: &Program, out_dir: impl AsRef<Path>) -> Result<()> {
    emit_build_selected(program, None, &BTreeMap::new(), out_dir)
}

#[cfg(test)]
pub fn emit_build_app(program: &Program, app_name: &str, out_dir: impl AsRef<Path>) -> Result<()> {
    emit_build_selected(program, Some(app_name), &BTreeMap::new(), out_dir)
}

/// Build one app with its direct app dependencies already compiled.
///
/// The map is keyed by the source app name used in explicit app imports or
/// exposed by an ordinary module import.
pub(crate) fn emit_build_app_linked(
    program: &Program,
    app_name: &str,
    dependencies: &BTreeMap<String, &Artifact>,
    out_dir: impl AsRef<Path>,
) -> Result<()> {
    emit_build_selected(program, Some(app_name), dependencies, out_dir)
}

fn emit_build_selected(
    program: &Program,
    app_name: Option<&str>,
    dependencies: &BTreeMap<String, &Artifact>,
    out_dir: impl AsRef<Path>,
) -> Result<()> {
    let out_dir = out_dir.as_ref();
    let sil_dir = out_dir.join("sil");

    let model = match app_name {
        Some(app_name) => Model::from_program_app_linked(program, app_name, dependencies)?,
        None => Model::from_program(program)?,
    };
    let mut actor_sil = BTreeMap::new();
    for actor in &model.actors {
        let sil = emit_actor(actor, &model)?;
        actor_sil.insert(actor.name.clone(), sil);
    }
    let manifest = emit_manifest(program, &model);
    let artifact = emit_artifact_json(program, &model, &actor_sil)?;

    if sil_dir.exists() {
        fs::remove_dir_all(&sil_dir).map_err(|err| ArgentError::at(&sil_dir, err.to_string()))?;
    }
    fs::create_dir_all(&sil_dir).map_err(|err| ArgentError::at(&sil_dir, err.to_string()))?;
    for (actor, sil) in &actor_sil {
        let path = sil_dir.join(format!("{actor}.sil"));
        fs::write(&path, sil).map_err(|err| ArgentError::at(path, err.to_string()))?;
    }

    fs::write(out_dir.join("manifest.json"), manifest)
        .map_err(|err| ArgentError::at(out_dir.join("manifest.json"), err.to_string()))?;

    fs::write(out_dir.join("artifact.json"), artifact)
        .map_err(|err| ArgentError::at(out_dir.join("artifact.json"), err.to_string()))?;
    Ok(())
}

fn emit_actor(actor: &ActorDecl, model: &Model<'_>) -> Result<String> {
    validate_actor_function_captures(actor, model)?;
    let state = model.storage_state(&actor.state)?;
    let state_values = ContractStateValuePlan::new(actor, model)?;
    let input_reference_plans = actor
        .entries
        .iter()
        .map(|entry| plan_entry_input_references(actor, entry, model, &state_values))
        .collect::<Result<Vec<_>>>()?;
    let emitted_entries = actor
        .entries
        .iter()
        .zip(&input_reference_plans)
        .map(|(entry, input_references)| {
            let mut out = String::new();
            let digest_helpers = emit_entry(&mut out, actor, entry, model, input_references, &state_values)?;
            Ok((out, digest_helpers))
        })
        .collect::<Result<Vec<_>>>()?;
    let digest_helpers = emitted_entries.iter().flat_map(|(_, helpers)| helpers.iter().cloned()).collect::<BTreeSet<_>>();
    let mut out = String::new();
    out.push_str("pragma silverscript ^0.1.0;\n\n");
    out.push_str("// Generated by argentc. Do not edit by hand.\n\n");

    out.push_str(&format!("contract {}(\n", actor.name));
    let mut args = Vec::new();
    args.extend(hidden_template_init_args_for_actor(actor, model)?.into_iter().map(|arg| format!("    {arg}")));
    for field in &state.fields {
        args.push(format!("    {} init_{}", lower_type_ref(&field.ty, model), field.name));
    }
    out.push_str(&args.join(",\n"));
    out.push_str("\n) {\n");

    emit_shared_constants(&mut out, model, &state_values)?;
    emit_imported_template_constants(&mut out, &imported_template_specs_for_actor(actor, model));
    let omitted_authored_structs = emit_state_layouts(&mut out, actor, model, &input_reference_plans, &state_values)?;
    emit_global_functions(&mut out, model, &state_values)?;
    emit_actor_functions(&mut out, actor, model, &state_values)?;
    emit_authored_state_digest_helpers(&mut out, actor, model, &state_values, &digest_helpers)?;
    emit_range_functions(&mut out, actor, model)?;

    emit_section_header(&mut out, "Route templates");
    emit_route_template_table(&mut out, actor, model)?;
    out.push('\n');

    emit_section_header_raw(&mut out, &format!("state fields: {}", actor.name));
    for field in &state.fields {
        out.push_str(&format!("    {} {} = init_{};\n", lower_type_ref(&field.ty, model), field.name, field.name));
    }
    out.push('\n');

    emit_section_header(&mut out, "Entrypoints");
    for (entry, _) in emitted_entries {
        out.push_str(&entry);
        out.push('\n');
    }

    out.push_str("}\n");
    audit_omitted_equivalent_state_structs(&out, &omitted_authored_structs, &state_values)?;
    Ok(out)
}

fn emit_section_header(out: &mut String, title: &str) {
    out.push_str(&format!("    // :: {}\n", title.to_ascii_lowercase()));
}

fn emit_section_header_raw(out: &mut String, title: &str) {
    out.push_str(&format!("    // :: {title}\n"));
}

fn emit_shared_constants(out: &mut String, model: &Model<'_>, state_values: &ContractStateValuePlan) -> Result<()> {
    if !model.consts.is_empty() {
        emit_section_header(out, "Shared constants");
        for ct in &model.consts {
            let sil_type = state_values.sil_type_for_type_ref(&ct.ty).unwrap_or_else(|| lower_type_ref(&ct.ty, model));
            let value = lower_actor_enum_literals(&ct.value, model)?;
            let value =
                if state_values.has_equivalent_state_sources() { lower_expression_state_types(&value, state_values)? } else { value };
            out.push_str(&format!("    {} constant {} = {};\n", sil_type, ct.name, value));
        }
        out.push('\n');
    }
    Ok(())
}

fn emit_imported_template_constants(out: &mut String, specs: &[ImportedTemplateSpec]) {
    if specs.is_empty() {
        return;
    }

    emit_section_header(out, "Linked templates");
    for spec in specs {
        out.push_str(&format!(
            "    byte[32] constant {} = byte[32](0x{});\n",
            hidden_imported_template_const_name(spec),
            spec.hash_hex
        ));
    }
    out.push('\n');
}

fn emit_state_layouts(
    out: &mut String,
    current_actor: &ActorDecl,
    model: &Model<'_>,
    input_reference_plans: &[EntryInputReferencePlan],
    state_values: &ContractStateValuePlan,
) -> Result<BTreeSet<String>> {
    emit_section_header(out, "State layouts");
    let mut emitted = BTreeSet::new();
    let mut omitted_authored_structs =
        state_values.equivalent_state_sources().map(|source| source.as_str().to_string()).collect::<BTreeSet<_>>();
    let named_authored_states =
        state_values.required_named_source_declarations().map(|source| source.as_str().to_string()).collect::<BTreeSet<_>>();
    let mut open_output_states = BTreeSet::new();
    for entry in &current_actor.entries {
        for observe in &entry.observes {
            for observed in &observe.outputs {
                if let Some(state) = observed_open_state_for_decl(current_actor, entry, observe, observed, model)? {
                    open_output_states.insert(state.to_string());
                }
            }
        }
        for group in model.entry_model(current_actor, entry)?.genesis_groups() {
            for interaction in group.outputs() {
                let InteractionSource::SpawnOutput(output) = interaction.source() else {
                    unreachable!("genesis covenant outputs are spawn outputs");
                };
                let state = spawn_target_state(interaction.target(), &output.actor, current_actor, entry, model)?
                    .expect("spawn target checked during model validation");
                if model.resolve_static_actor_target(interaction.target()).is_none() {
                    open_output_states.insert(state.clone());
                }
            }
        }
    }

    // Keep local declarations in their established order, then append linked
    // declarations discovered authoritatively by the contract value plan.
    let mut state_names = model.actors.iter().map(|actor| actor.state.clone()).collect::<Vec<_>>();
    state_names.extend(model.states.keys().cloned());
    state_names.extend(named_authored_states.iter().cloned());
    for state_name in state_names {
        if !named_authored_states.contains(&state_name) || emitted.contains(&state_name) {
            continue;
        }
        emitted.insert(state_name.clone());
        let state = model.state(&state_name)?;
        let storage_state = model.storage_state(&state_name)?;
        out.push_str(&format!("    struct {state_name} {{\n"));
        if !storage_state.fields.is_empty() {
            out.push_str("        // :: user declared fields\n");
            for field in &storage_state.fields {
                let ty = state
                    .expansion
                    .as_ref()
                    .and_then(|expansion| expansion.digests.iter().find(|digest| digest.field == field.name))
                    .map_or_else(
                        || state_values.sil_type_for_type_ref(&field.ty).unwrap_or_else(|| lower_type_ref(&field.ty, model)),
                        |digest| state_values.authored_sil_type_for_name(&digest.state).unwrap_or(&digest.state).to_string(),
                    );
                out.push_str(&format!("        {ty} {};\n", field.name));
            }
        }
        out.push_str("    }\n");
    }

    let lowering = model.state_lowering(&current_actor.name)?;
    let mut named_physical_layouts = BTreeMap::new();
    for input_references in input_reference_plans {
        for input in input_references.external_references() {
            let sil_type = input.physical_type();
            if sil_type == "State" {
                continue;
            }
            let target = lowering.target(input.physical_target()).ok_or_else(|| {
                ArgentError::new(format!("input physical type `{sil_type}` has no target layout in actor `{}`", current_actor.name))
            })?;
            insert_named_physical_layout(&mut named_physical_layouts, sil_type, target.physical(), current_actor)?;
        }
    }

    let mut referenced_actors = BTreeSet::new();
    for entry in &current_actor.entries {
        referenced_actors
            .extend(entry.observes.iter().flat_map(|observe| observe.outputs.iter()).map(|observed| observed.actor.clone()));
        referenced_actors.extend(entry.spawns.iter().flat_map(|spawn| &spawn.outputs).map(|output| output.actor.clone()));
        let entry_model = model.entry_model(current_actor, entry)?;
        let selectors = entry_model.template_selectors();
        for route in entry_model.routes() {
            let ResolvedSuccessor::Constructed { actor, .. } = &route.successor else {
                continue;
            };
            if !selectors.contains_key(actor) {
                referenced_actors.insert(actor.clone());
            }
        }
    }
    for actor_name in referenced_actors {
        if model.static_actor_target(&actor_name).is_none() {
            continue;
        }
        let output = plan_actor_output_state(current_actor, &actor_name, model)?;
        if let Some((sil_type, layout)) = output.named_physical_layout() {
            insert_named_physical_layout(&mut named_physical_layouts, sil_type, layout, current_actor)?;
        }
    }

    for entry in &current_actor.entries {
        for selector in model.entry_model(current_actor, entry)?.template_selectors().values() {
            let output = plan_selector_output_state(current_actor, selector, model)?;
            if let Some((sil_type, layout)) = output.named_physical_layout() {
                insert_named_physical_layout(&mut named_physical_layouts, sil_type, layout, current_actor)?;
            }
        }
    }

    for state_name in open_output_states {
        let output = plan_open_output_state(current_actor, &state_name, model)?;
        if let Some((sil_type, layout)) = output.named_physical_layout() {
            insert_named_physical_layout(&mut named_physical_layouts, sil_type, layout, current_actor)?;
        }
    }
    for (sil_type, layout) in named_physical_layouts {
        if !emitted.insert(sil_type.clone()) {
            continue;
        }
        omitted_authored_structs.remove(&sil_type);
        emit_planned_physical_struct(out, &sil_type, &layout);
    }
    out.push('\n');
    Ok(omitted_authored_structs)
}

fn insert_named_physical_layout(
    layouts: &mut BTreeMap<String, PhysicalStateLayout>,
    sil_type: &str,
    layout: &PhysicalStateLayout,
    actor: &ActorDecl,
) -> Result<()> {
    if let Some(existing) = layouts.get(sil_type)
        && !layout.is_sil_compatible_with(existing)
    {
        return Err(ArgentError::new(format!(
            "physical type `{sil_type}` names incompatible target layouts in actor `{}`",
            actor.name
        )));
    }
    layouts.insert(sil_type.to_string(), layout.clone());
    Ok(())
}

fn emit_planned_physical_struct(out: &mut String, sil_type: &str, layout: &PhysicalStateLayout) {
    out.push_str(&format!("    struct {sil_type} {{\n"));
    let generated = layout.fields().iter().filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_))).collect::<Vec<_>>();
    if !generated.is_empty() {
        out.push_str("        // :: generated fields\n");
        for field in generated {
            out.push_str(&format!("        {} {};\n", field.sil_type(), field.sil_name()));
        }
    }
    let storage = layout.fields().iter().filter(|field| matches!(field.id(), PhysicalFieldId::Storage(_))).collect::<Vec<_>>();
    if !storage.is_empty() {
        out.push_str("        // :: user declared fields\n");
        for field in storage {
            out.push_str(&format!("        {} {};\n", field.sil_type(), field.sil_name()));
        }
    }
    out.push_str("    }\n");
}

fn emit_global_functions(out: &mut String, model: &Model<'_>, state_values: &ContractStateValuePlan) -> Result<()> {
    if !model.functions.is_empty() {
        emit_section_header(out, "Global functions (isolated using the gen__glob_ namespace)");
        let lowerer = GlobalFunctionLowerer::new(model);
        for function in &model.functions {
            reject_function_input_state_calls(&function.name, &function.body, "global")?;
            reject_function_physical_state_constructors(&function.name, &function.body, "global")?;
            let function = lowerer.lower(function)?;
            let signature = state_values.signature(function.name).expect("global function has a contract-local signature plan");
            let params = function
                .params
                .iter()
                .enumerate()
                .map(|(index, param)| {
                    let ty = signature
                        .param(index)
                        .map(|value| state_values.sil_type(value))
                        .unwrap_or_else(|| lower_type_ref(param.ty, model));
                    format!("{ty} {}", param.name)
                })
                .collect::<Vec<_>>();
            let return_type = signature
                .result()
                .map(|value| state_values.sil_type(value))
                .or_else(|| function.return_ty.map(|ty| lower_type_ref(ty, model)));
            let body = lower_function_body_state_types(function.name, &params, return_type.as_deref(), &function.body, state_values)?;
            emit_function(out, function.name, &params, return_type.as_deref(), &body);
        }
        out.push('\n');
    }
    Ok(())
}

fn emit_actor_functions(out: &mut String, actor: &ActorDecl, model: &Model<'_>, state_values: &ContractStateValuePlan) -> Result<()> {
    let actor_model = model.actor_model(&actor.name)?;
    if actor.functions.is_empty() {
        return Ok(());
    }

    emit_section_header(out, "Actor functions");
    for function in actor_model.functions() {
        reject_function_input_state_calls(&function.name, &function.body, &format!("actor `{}`", actor.name))?;
        reject_function_physical_state_constructors(&function.name, &function.body, &format!("actor `{}`", actor.name))?;
        let signature = state_values.signature(&function.name).expect("actor function has a contract-local signature plan");
        let params = function
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| {
                let ty = signature
                    .param(index)
                    .map(|value| state_values.sil_type(value))
                    .unwrap_or_else(|| lower_type_ref(&param.ty, model));
                format!("{ty} {}", param.name)
            })
            .collect::<Vec<_>>();
        let return_type = signature
            .result()
            .map(|value| state_values.sil_type(value))
            .or_else(|| function.return_ty.as_ref().map(|ty| lower_type_ref(ty, model)));
        let body = lower_function_body_state_types(&function.name, &params, return_type.as_deref(), &function.body, state_values)?;
        emit_function(out, &function.name, &params, return_type.as_deref(), &body);
    }
    out.push('\n');
    Ok(())
}

fn emit_authored_state_digest_helpers(
    out: &mut String,
    actor: &ActorDecl,
    model: &Model<'_>,
    state_values: &ContractStateValuePlan,
    sources: &BTreeSet<SourceStateId>,
) -> Result<()> {
    if sources.is_empty() {
        return Ok(());
    }
    emit_section_header(out, "Authored state digests");
    let lowering = model.state_lowering(&actor.name)?;
    for source in sources {
        let sil_type = state_values
            .authored_sil_type_for_name(source.as_str())
            .ok_or_else(|| ArgentError::new(format!("state `{}` has no contract-local authored representation", source.as_str())))?;
        let name = state_values.digest_helper_name(source);
        let value = format!("{name}_value");
        let param = format!("{sil_type} {value}");
        let digest = authored_state_payload_digest_expr(source, &value, lowering, model)?;
        emit_function(out, &name, &[param], Some("byte[32]"), &format!("return {digest};"));
    }
    out.push('\n');
    Ok(())
}

fn emit_function(out: &mut String, name: &str, params: &[String], return_ty: Option<&str>, body: &str) {
    let return_type = return_ty.map(|ty| format!(" : {ty}")).unwrap_or_default();
    out.push_str(&format!("    function {name}({}){return_type} {{\n", params.join(", ")));
    out.push_str(&indent_block_body(body, 8));
    out.push_str("    }\n");
}

fn emit_range_functions(out: &mut String, actor: &ActorDecl, model: &Model<'_>) -> Result<()> {
    let mut uses_ranges = false;
    for entry in &actor.entries {
        let entry = model.entry_model(actor, entry)?;
        uses_ranges =
            entry.current().inputs().iter().chain(entry.current().outputs()).any(|interaction| interaction.cardinality().is_range());
        if uses_ranges {
            break;
        }
    }
    if !uses_ranges {
        return Ok(());
    }

    emit_section_header(out, "Range helpers");
    let index = hidden_range_index_arg_name();
    let count = hidden_range_count_arg_name();
    out.push_str(&format!("    function {}(int {index}, int {count}) : int {{\n", hidden_checked_range_index_name()));
    out.push_str(&format!("        require({index} >= 0);\n"));
    out.push_str(&format!("        require({index} < {count});\n"));
    out.push_str(&format!("        return {index};\n"));
    out.push_str("    }\n\n");
    Ok(())
}

fn emit_entry(
    out: &mut String,
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    input_references: &EntryInputReferencePlan,
    state_values: &ContractStateValuePlan,
) -> Result<BTreeSet<SourceStateId>> {
    let entry_model = model.entry_model(actor, entry)?;
    validate_entry_cardinality_support(actor, entry, entry_model)?;
    let lowered_body = lower_entry_body(actor, entry, model, input_references, state_values)?;
    let witness_specs = entry_witness_specs(actor, entry, model)?;
    let sil_params = lower_entry_params(entry, &witness_specs, model, state_values);
    match entry.kind {
        EntryKind::Leader => {
            let shape = if entry.consumes.is_empty() { "1:N" } else { "M:N" };
            out.push_str(&format!("    // :: leader entry ({shape})\n"));
        }
        EntryKind::Delegate => out.push_str("    // :: delegate entry\n"),
    }
    push_entry_signature(out, &entry.name, &sil_params);

    let emitted_imported_templates = emit_entry_imported_template_locals(out, &imported_template_specs_for_entry(actor, entry, model));
    let emitted_route_templates = emit_entry_template_locals(out, actor, &witness_specs, model);
    if emitted_imported_templates || emitted_route_templates {
        out.push('\n');
    }

    // Covenant batching places multiple independent inputs with the same
    // covenant ID in one transaction. A consumes-free leader entry in a
    // contract that no delegate trusts can allow this because it does not
    // treat the other inputs as a coordinated group. Every other entry needs
    // the covenant-input prelude: consumes require peer reads, delegates
    // validate their leader, and leader entries of leader actors must reject
    // undeclared delegates.
    let allows_cov_batching = entry.kind == EntryKind::Leader && entry.consumes.is_empty() && !model.is_leader_actor(&actor.name);
    if !allows_cov_batching {
        out.push_str("        // :: cov inputs\n");
        let cov_id = hidden_cov_id_name();
        out.push_str(&format!("        byte[32] {cov_id} = OpInputCovenantId(this.activeInputIndex);\n"));
        let has_consume_range = entry_model.current().inputs().iter().any(|interaction| interaction.cardinality().is_range());
        match entry.kind {
            EntryKind::Leader => {
                if has_consume_range {
                    out.push_str(&format!("        require(OpCovInputIdx({cov_id}, 0) == this.activeInputIndex);\n"));
                } else {
                    let count = entry.consumes.len() + 1;
                    out.push_str(&format!("        require(OpCovInputCount({cov_id}) == {count});\n"));
                    // If count == 1, the assertion below follows from the preceding
                    // OpCovInputCount check: cov_id is the active input's ID, so the
                    // only matching input at cov[0] must be this.activeInputIndex.
                    if count > 1 {
                        out.push_str(&format!("        require(OpCovInputIdx({cov_id}, 0) == this.activeInputIndex);\n"));
                    }
                }
            }
            EntryKind::Delegate => {
                let min_count = entry.consumes.len() + 1;
                out.push_str(&format!("        require(OpCovInputCount({cov_id}) >= {min_count});\n"));
                out.push_str(&format!("        require(OpCovInputIdx({cov_id}, 0) != this.activeInputIndex);\n"));
            }
        }

        let slot_offset = match entry.kind {
            EntryKind::Leader => 1,
            EntryKind::Delegate => 0,
        };
        for interaction in entry_model.current().inputs() {
            let InteractionSource::Consume(consume) = interaction.source() else {
                unreachable!("current entry inputs are consumes");
            };
            if interaction.cardinality().is_range() {
                emit_ranged_current_input(out, interaction, &cov_id, slot_offset, input_references)?;
                continue;
            }
            let cov_index =
                lower_singleton_interaction_index(interaction.location(), &format!("OpCovInputCount({cov_id})"), slot_offset)?;
            let input_idx = hidden_input_idx_name(&consume.name);
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {input_idx} = OpCovInputIdx({cov_id}, {cov_index})"),
                &format!("input {} at cov[{}]", consume.actor, cov_index),
            );
            // SECURITY: readInputState omits template validation. This path is valid
            // only for a self-consume in a single-actor covenant domain. The domain
            // restricts every input with this covenant ID to one of its contracts.
            // With one actor, every group input has this contract's template.
            let input_reference = input_references.consumed(&consume.name)?;
            if input_reference.uses_covenant_domain_proof() {
                out.push_str("        // :: direct input state (single-actor covenant has one template)\n");
            }
            input_reference.emit_read(out, 8);
        }
        out.push('\n');
    }

    if !entry.observes.is_empty() {
        emit_observed_inputs(out, actor, entry, entry_model, model, input_references)?;
    }

    emit_state_expansion_prelude(out, actor, model)?;

    out.push_str("        // :: auth outputs\n");
    let has_output_range = entry_model.current().outputs().iter().any(|interaction| interaction.cardinality().is_range());
    if !has_output_range {
        let auth_output_count = emitted_auth_output_count(&entry.emits);
        out.push_str(&format!("        require(OpAuthOutputCount(this.activeInputIndex) == {auth_output_count});\n"));
    }
    match &entry.emits {
        EmitSpec::None => {}
        EmitSpec::Outputs(_) => {
            for interaction in entry_model.current().outputs() {
                let InteractionSource::CurrentOutput(output) = interaction.source() else {
                    unreachable!("current entry outputs are emits outputs");
                };
                if interaction.cardinality().is_range() {
                    emit_ranged_current_output_count(out, interaction);
                    continue;
                }
                let auth_index =
                    lower_singleton_interaction_index(interaction.location(), "OpAuthOutputCount(this.activeInputIndex)", 0)?;
                let output_idx = hidden_output_idx_name(&output.name);
                push_generated_statement_with_comment(
                    out,
                    8,
                    &format!("int {output_idx} = OpAuthOutputIdx(this.activeInputIndex, {auth_index})"),
                    &format!("output {}: {}", output.name, output.actors.join(" | ")),
                );
            }
        }
    }
    out.push('\n');
    emit_spawn_prelude(out, entry)?;
    out.push_str(&lowered_body.sil);
    out.push_str("    }\n");
    Ok(lowered_body.digest_helpers)
}

fn validate_entry_cardinality_support(actor: &ActorDecl, entry: &EntryDecl, entry_model: &EntryModel<'_>) -> Result<()> {
    for interaction in entry_model.current().inputs() {
        if interaction.location().is_range() && entry.kind == EntryKind::Delegate {
            return Err(ArgentError::new(format!(
                "delegate `{}::{}` cannot use range `{}` in `consumes` yet",
                actor.name,
                entry.name,
                interaction.handle()
            )));
        }
    }
    for interaction in entry_model.current().outputs() {
        if interaction.location().is_range() && interaction.target().single_static_actor().is_none() {
            return Err(ArgentError::new(format!(
                "entry `{}::{}` range output `{}` must use one fixed actor target in this compiler version",
                actor.name,
                entry.name,
                interaction.handle()
            )));
        }
    }
    for interaction in entry_model
        .existing_groups()
        .chain(entry_model.genesis_groups())
        .flat_map(|group| group.inputs().iter().chain(group.outputs()))
    {
        if interaction.location().is_range() {
            debug_assert!(interaction.cardinality().is_range());
            return Err(ArgentError::new(format!(
                "entry `{}::{}` declares range `{}`, but range code generation is not implemented yet",
                actor.name,
                entry.name,
                interaction.handle()
            )));
        }
    }
    Ok(())
}

fn emit_ranged_current_output_count(out: &mut String, interaction: &EntryInteraction<'_>) {
    let Some((minimum, maximum)) = interaction.cardinality().range_bounds() else {
        unreachable!("ranged current output has resolved range bounds");
    };
    let InteractionLocation::Range { singleton_count, .. } = interaction.location() else {
        unreachable!("ranged current output has a ranged location");
    };
    let auth_count = "OpAuthOutputCount(this.activeInputIndex)";
    let count_expr = if singleton_count == 0 { auth_count.to_string() } else { format!("{auth_count} - {singleton_count}") };
    let count = hidden_output_count_name(interaction.handle());
    out.push_str(&format!("        int {count} = {count_expr};\n"));
    out.push_str(&format!("        require({count} >= {minimum});\n"));
    out.push_str(&format!("        require({count} <= {maximum});\n"));
}

fn emit_ranged_current_input(
    out: &mut String,
    interaction: &EntryInteraction<'_>,
    cov_id: &str,
    slot_offset: usize,
    input_references: &EntryInputReferencePlan,
) -> Result<()> {
    let Some((minimum, maximum)) = interaction.cardinality().range_bounds() else {
        unreachable!("ranged current input has resolved range bounds");
    };
    let InteractionLocation::Range { start, singleton_count } = interaction.location() else {
        unreachable!("ranged current input has a ranged location");
    };
    let excluded = slot_offset + singleton_count;
    let group_count = format!("OpCovInputCount({cov_id})");
    let count_expr = if excluded == 0 { group_count } else { format!("{group_count} - {excluded}") };
    let count = hidden_input_count_name(interaction.handle());
    out.push_str(&format!("        int {count} = {count_expr};\n"));
    out.push_str(&format!("        require({count} >= {minimum});\n"));
    out.push_str(&format!("        require({count} <= {maximum});\n"));

    let input_reference = input_references.consumed(interaction.handle())?;
    // A ranged consume is a collection of authenticated input references, not
    // an authored state array. Authenticate every member here even when the
    // authored body does not project it. Cache only authored projections; the
    // compiler-owned physical route fields never cross into the source value.
    input_reference.emit_range_cache_declarations(out, 8, interaction.handle());
    let position = hidden_input_position_name(interaction.handle());
    out.push_str(&format!("        for ({position}, 0, {count}, {maximum}) {{\n"));
    let first_cov_index = slot_offset + start;
    let cov_index = if first_cov_index == 0 { position.clone() } else { format!("{first_cov_index} + {position}") };
    let input_idx = hidden_input_idx_name(interaction.handle());
    out.push_str(&format!("            int {input_idx} = OpCovInputIdx({cov_id}, {cov_index});\n"));
    input_reference.emit_read(out, 12);
    input_reference.emit_range_cache_append(out, 12, interaction.handle())?;
    out.push_str("        }\n");
    Ok(())
}
fn lower_singleton_interaction_index(location: InteractionLocation, total_count: &str, start_offset: usize) -> Result<String> {
    match location {
        InteractionLocation::FromStart(index) => Ok((start_offset + index).to_string()),
        InteractionLocation::FromEnd(distance) => Ok(format!("{total_count} - {distance}")),
        InteractionLocation::Range { .. } => Err(ArgentError::new("cannot lower a range as a singleton transaction index")),
    }
}

fn emitted_auth_output_count(emits: &EmitSpec) -> usize {
    match emits {
        EmitSpec::None => 0,
        EmitSpec::Outputs(outputs) => outputs.len(),
    }
}

// Sil's validateOutputState-style builtins require a version-0 P2SH SPK:
// two version bytes followed by a fixed 35-byte script.
const P2SH_SPK_VERSION: [u8; 2] = [0, 0];
const SPK_VERSION_LEN: usize = P2SH_SPK_VERSION.len();
const P2SH_SCRIPT_LEN: usize = 35;

fn emit_spawn_prelude(out: &mut String, entry: &EntryDecl) -> Result<()> {
    if entry.spawns.is_empty() {
        return Ok(());
    }

    // Security
    //
    // Scripts cannot enumerate the genesis outputs authorized by an input, so each
    // spawn clause receives its declared outputs' global indices as untrusted
    // witnesses. The witnesses select outputs only; the active input outpoint and
    // every selected output's value and script bytes are read directly from the
    // transaction. Spawned actors are validated elsewhere as version-0 P2SH outputs
    // with 35-byte scripts, so the generated preimage uses that fixed version and
    // script length.
    //
    // For each clause, the generated code reconstructs the canonical consensus
    // CovenantID preimage from:
    // - the active input outpoint;
    // - the statically declared output count;
    // - the witnessed output indices, in declaration order;
    // - the corresponding transaction-derived output data.
    //
    // Consensus independently derives each genesis covenant ID from the complete
    // output group carrying that ID, ordered by global output index. Requiring the
    // reconstructed ID to equal the ID carried by one selected output therefore
    // proves, under hash collision resistance, that the witnessed sequence is
    // exactly that complete group authorized by the active input. Omitting, adding,
    // reordering, duplicating, or substituting an output changes the preimage.
    // Checking the remaining group members' IDs would add no further proof.
    //
    // For multiple spawn clauses, the complete-group proof above means that the same
    // group always has the same first output index. Requiring those indices to be
    // strictly increasing binds source declaration order to runtime group order and
    // prevents one group from satisfying more than one clause.
    //
    // This authenticates every declared spawn group because the application protocol
    // may grant authority to the resulting covenant IDs, e.g. by registering them as
    // authorized covenants over specific resources. It intentionally does not forbid
    // additional undeclared genesis groups, since their covenant IDs receive no such
    // authority from the protocol.
    out.push_str("        // :: genesis covenants\n");
    let mut previous_first_output_idx = None;
    for spawn in &entry.spawns {
        let preimage = hidden_spawn_preimage_name(&spawn.name);
        out.push_str(&format!("        byte[] {preimage} =\n"));
        out.push_str("            OpOutpointTxId(this.activeInputIndex)\n");
        out.push_str("            + (OpOutpointIndex(this.activeInputIndex) as byte[8]).slice(0, 4)\n");
        out.push_str(&format!("            + ({} as byte[8])\n", spawn.outputs.len()));
        for (output_position, output) in spawn.outputs.iter().enumerate() {
            let output_idx = hidden_spawn_output_idx_name(&spawn.name, &output.name);
            out.push_str(&format!("            + ({output_idx} as byte[8]).slice(0, 4)\n"));
            out.push_str(&format!("            + (tx.outputs[{output_idx}].value as byte[8])\n"));
            out.push_str(&format!("            + byte[2](0x{:02x}{:02x})\n", P2SH_SPK_VERSION[0], P2SH_SPK_VERSION[1]));
            out.push_str(&format!("            + ({P2SH_SCRIPT_LEN} as byte[8])\n"));
            let terminator = if output_position + 1 == spawn.outputs.len() { ";" } else { "" };
            out.push_str(&format!(
                "            + OpTxOutputSpkSubstr({output_idx}, {SPK_VERSION_LEN}, {}){terminator}\n",
                SPK_VERSION_LEN + P2SH_SCRIPT_LEN
            ));
        }
        out.push_str(&format!("        byte[32] {} = blake2bWithKey({preimage}, byte[](\"CovenantID\"));\n", spawn.covenant));
        let first_output = spawn.outputs.first().expect("spawn outputs checked during model validation");
        let first_output_idx = hidden_spawn_output_idx_name(&spawn.name, &first_output.name);
        if let Some(previous_first_output_idx) = &previous_first_output_idx {
            // Each first index is committed by its reconstructed genesis covenant ID. Strict ordering therefore proves
            // that adjacent spawn groups, and transitively all spawn groups, are distinct under collision resistance.
            out.push_str(&format!("        require({previous_first_output_idx} < {first_output_idx});\n"));
        }
        // Consensus derives a genesis covenant ID from the complete output group carrying that ID. Matching one member
        // proves that the reconstructed preimage contains the complete group; checking the remaining members is redundant.
        out.push_str(&format!("        require(OpOutputCovenantId({first_output_idx}) == {});\n", spawn.covenant));
        previous_first_output_idx = Some(first_output_idx);
    }
    out.push('\n');
    Ok(())
}

fn emit_state_expansion_prelude(out: &mut String, actor: &ActorDecl, model: &Model<'_>) -> Result<()> {
    let specs = state_expansion_witness_specs_for_actor(actor, model);
    if specs.is_empty() {
        return Ok(());
    }

    out.push_str("        // :: expanded state\n");
    for spec in specs {
        let hidden = hidden_state_expansion_preimage_name(&spec);
        let digest = format!("blake3(byte[]({hidden}))");
        push_generated_binary_require(out, 8, &digest, "==", &spec.field);
        let mut offset = 0usize;
        for field in &model.state(&spec.memory_state)?.fields {
            let len = packed_field_len(&field.ty)?;
            let end = offset + len;
            let expr = unpack_packed_field_expr(&field.ty, &hidden, offset, end)?;
            push_indent(out, 8);
            out.push_str(&format!(
                "{} {} = {};\n",
                lower_type_ref(&field.ty, model),
                hidden_state_expansion_field_name(&spec, &field.name),
                expr
            ));
            offset = end;
        }
    }
    out.push('\n');
    Ok(())
}

fn emit_observed_inputs(
    out: &mut String,
    actor: &ActorDecl,
    entry: &EntryDecl,
    entry_model: &EntryModel<'_>,
    model: &Model<'_>,
    input_references: &EntryInputReferencePlan,
) -> Result<()> {
    out.push_str("        // :: observed covenants\n");
    for group in entry_model.existing_groups() {
        let observe = group.observe().expect("existing covenant group retains its observe clause");
        let cov_id = hidden_observe_cov_id_name(&observe.name);
        let cov_expr = lower_entry_expr(actor, entry, model, EntryInputReferenceView::None, &observe.covenant_expr, Some("byte[32]"))?;
        out.push_str(&format!("        byte[32] {cov_id} = {cov_expr}; // observe {}\n", observe.name));
        out.push_str(&format!("        require(OpCovInputCount({cov_id}) == {});\n", group.inputs().len()));
        out.push_str(&format!("        require(OpCovOutputCount({cov_id}) == {});\n", group.outputs().len()));
        let mut materialized_open_bindings = BTreeSet::new();
        for output in &observe.outputs {
            if !observed_is_dynamic_binding(observe, output) || !materialized_open_bindings.insert(output.actor.as_str()) {
                continue;
            }
            let input =
                first_observed_input_for_actor(observe, &output.actor).expect("dynamic observed output requires its binding input");
            let spec = observed_input_spec(actor, entry, observe, input, model)?;
            out.push_str(&format!("        byte[32] {} = {};\n", output.actor, hidden_observed_actor_template_name(&spec)));
        }
        for interaction in group.inputs() {
            let InteractionSource::ObserveInput(input) = interaction.source() else {
                unreachable!("existing covenant inputs are observed inputs");
            };
            let input_idx = hidden_observed_input_idx_name(&observe.name, &input.name);
            let cov_index = lower_singleton_interaction_index(interaction.location(), &format!("OpCovInputCount({cov_id})"), 0)?;
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {input_idx} = OpCovInputIdx({cov_id}, {cov_index})"),
                &format!("observed input {}.{}: {}", observe.name, input.name, input.actor),
            );
            input_references.observed(&observe.name, &input.name)?.emit_read(out, 8);
        }
        for interaction in group.outputs() {
            let InteractionSource::ObserveOutput(output) = interaction.source() else {
                unreachable!("existing covenant outputs are observed outputs");
            };
            let output_idx = hidden_observed_output_idx_name(&observe.name, &output.name);
            let cov_index = lower_singleton_interaction_index(interaction.location(), &format!("OpCovOutputCount({cov_id})"), 0)?;
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {output_idx} = OpCovOutputIdx({cov_id}, {cov_index})"),
                &format!("observed output {}.{}: {}", observe.name, output.name, output.actor),
            );
        }
    }
    out.push('\n');
    Ok(())
}

fn state_packed_len(state_name: &str, model: &Model<'_>) -> Result<usize> {
    model.state(state_name)?.fields.iter().try_fold(0usize, |sum, field| packed_field_len(&field.ty).map(|len| sum + len))
}

pub(super) fn packed_field_expr(ty: &TypeRef, expr: &str) -> Result<String> {
    if ty.is_actor_type() {
        return Ok(format!("byte[]({expr})"));
    }
    match (ty.name.as_str(), ty.array) {
        ("int", None) => Ok(format!("(({expr}) as byte[8])")),
        ("temporal", None) => Ok(format!("((int({expr})) as byte[8])")),
        // Sil booleans use the VM's numeric representation, where false is
        // empty. Normalize through int before fixing the one-byte state width.
        ("bool", None) => Ok(format!("((({expr}) as int) as byte[1])")),
        ("byte", None) => Ok(format!("byte[]({expr})")),
        ("byte", Some(ArrayDim::Fixed(_))) | ("pubkey", None) | (word::COVENANT_ID, None) | ("sig", None) | ("datasig", None) => {
            Ok(format!("byte[]({expr})"))
        }
        ("bytes", None) | ("string", None) | (_, Some(_)) => {
            Err(ArgentError::new(format!("cannot pack field `{expr}` with unsupported variable or array type")))
        }
        (name, None) => Err(ArgentError::new(format!("cannot digest field `{expr}` of unsupported type `{name}`"))),
    }
}

fn unpack_packed_field_expr(ty: &TypeRef, packed_expr: &str, offset: usize, end: usize) -> Result<String> {
    // Indexing a byte sequence already produces scalar byte. Other fixed-width
    // values are decoded from their packed slice.
    if matches!((ty.name.as_str(), ty.array), ("byte", None)) {
        return Ok(format!("{packed_expr}[{offset}]"));
    }
    let slice_expr = format!("{packed_expr}.slice({offset}, {end})");
    if ty.is_actor_type() {
        return Ok(format!("byte[32]({slice_expr})"));
    }
    match (ty.name.as_str(), ty.array) {
        ("int", None) => Ok(format!("OpBin2Num({slice_expr})")),
        ("temporal", None) => Ok(format!("temporal(OpBin2Num({slice_expr}))")),
        ("bool", None) => Ok(format!("OpBin2Num({slice_expr}) != 0")),
        ("byte", Some(ArrayDim::Fixed(len))) => Ok(format!("byte[{len}]({slice_expr})")),
        ("pubkey", None) | (word::COVENANT_ID, None) => Ok(format!("byte[32]({slice_expr})")),
        ("sig", None) => Ok(format!("byte[65]({slice_expr})")),
        ("datasig", None) => Ok(format!("byte[64]({slice_expr})")),
        ("bytes", None) | ("string", None) | (_, Some(_)) => {
            Err(ArgentError::new(format!("cannot unpack unsupported variable or array field from `{slice_expr}`")))
        }
        (name, None) => Err(ArgentError::new(format!("cannot unpack unsupported type `{name}` from `{slice_expr}`"))),
    }
}

fn emit_entry_template_locals(out: &mut String, _actor: &ActorDecl, witness_specs: &EntryWitnessSpecs, _model: &Model<'_>) -> bool {
    let template_locals = witness_specs
        .templates
        .iter()
        .filter(|spec| matches!(spec.source, TemplateWitnessSource::FamilyTable { .. }))
        .collect::<Vec<_>>();
    if template_locals.is_empty() && witness_specs.families.is_empty() {
        return false;
    }

    let labels = witness_specs
        .families
        .iter()
        .map(|spec| spec.family_id.as_str())
        .chain(template_locals.iter().map(|spec| spec.actor.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    out.push_str(&format!("        // :: routes: {labels}\n"));
    for spec in &witness_specs.families {
        let table = hidden_route_family_table_name_by_id(&spec.family_id);
        let commitment = hidden_route_family_commitment_name_by_id(&spec.family_id);
        out.push_str(&format!("        require(blake3(byte[]({table})) == {commitment});\n"));
    }
    for spec in template_locals {
        if let TemplateWitnessSource::FamilyTable { family_id, offset } = &spec.source {
            let start = *offset;
            let end = start + 32;
            out.push_str(&format!(
                "        byte[32] {} = byte[32]({}.slice({start}, {end}));\n",
                hidden_template_name(&spec.actor),
                hidden_route_family_table_name_by_id(family_id)
            ));
        }
    }
    true
}

fn emit_entry_imported_template_locals(out: &mut String, specs: &[ImportedTemplateSpec]) -> bool {
    if specs.is_empty() {
        return false;
    }

    out.push_str("        // :: linked templates\n");
    for spec in specs {
        out.push_str(&format!(
            "        byte[32] {} = {};\n",
            hidden_imported_template_name(spec),
            hidden_imported_template_const_name(spec)
        ));
    }
    true
}

const GENERATED_SIL_LINE_LIMIT: usize = 100;

pub(super) fn push_indent(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
}

fn push_entry_signature(out: &mut String, name: &str, params: &[String]) {
    let single = format!("    entry {name}({}) {{", params.join(", "));
    if single.len() <= GENERATED_SIL_LINE_LIMIT {
        out.push_str(&single);
        out.push('\n');
        return;
    }

    out.push_str(&format!("    entry {name}(\n"));
    for (idx, param) in params.iter().enumerate() {
        out.push_str("        ");
        out.push_str(param);
        if idx + 1 != params.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("    ) {\n");
}

pub(super) fn push_generated_call(out: &mut String, indent: usize, prefix: &str, function: &str, args: &[String]) {
    let ind = " ".repeat(indent);
    let single = format!("{ind}{prefix}{function}({});", args.join(", "));
    if single.len() <= GENERATED_SIL_LINE_LIMIT {
        out.push_str(&single);
        out.push('\n');
        return;
    }

    out.push_str(&format!("{ind}{prefix}{function}(\n"));
    let arg_indent = " ".repeat(indent + 4);
    for (idx, arg) in args.iter().enumerate() {
        out.push_str(&arg_indent);
        out.push_str(arg);
        if idx + 1 != args.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&format!("{ind});\n"));
}

pub(super) fn push_generated_binary_require(out: &mut String, indent: usize, lhs: &str, op: &str, rhs: &str) {
    let ind = " ".repeat(indent);
    let single = format!("{ind}require({lhs} {op} {rhs});");
    if single.len() <= GENERATED_SIL_LINE_LIMIT {
        out.push_str(&single);
        out.push('\n');
        return;
    }

    out.push_str(&format!("{ind}require(\n"));
    out.push_str(&format!("{}{}\n", " ".repeat(indent + 4), lhs));
    out.push_str(&format!("{}{} {}\n", " ".repeat(indent + 8), op, rhs));
    out.push_str(&format!("{ind});\n"));
}

fn push_generated_statement_with_comment(out: &mut String, indent: usize, statement: &str, comment: &str) {
    let ind = " ".repeat(indent);
    let single = format!("{ind}{statement}; // {comment}");
    if single.len() <= GENERATED_SIL_LINE_LIMIT {
        out.push_str(&single);
        out.push('\n');
        return;
    }

    out.push_str(&format!("{ind}// :: {comment}\n"));
    out.push_str(&format!("{ind}{statement};\n"));
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum TemplateWitnessForm {
    Bytes,
    Len,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TemplateWitnessSpec {
    actor: String,
    form: TemplateWitnessForm,
    source: TemplateWitnessSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TemplateWitnessSource {
    Field,
    FamilyTable { family_id: String, offset: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteFamilyWitnessSpec {
    family_id: String,
    byte_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TemplateSelectorWitnessSpec {
    name: String,
    actor_enum: String,
    variants: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ObservedActorWitnessSpec {
    pub(super) observe: String,
    pub(super) side: ObservedActorSideArtifact,
    pub(super) handle: String,
    pub(super) actor: String,
    pub(super) source: Option<ClauseActorTypeRef>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct ImportedTemplateSpec {
    pub(super) app: String,
    pub(super) actor: String,
    pub(super) hash_hex: String,
}

impl ImportedTemplateSpec {
    pub(super) fn from_linked(actor: &LinkedActor) -> Self {
        Self { app: actor.app.clone(), actor: actor.actor.clone(), hash_hex: encode_hex(&actor.template.hash) }
    }

    pub(super) fn actor_reference(&self) -> String {
        format!("{}::{}", self.app, self.actor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct SpawnActorWitnessSpec {
    pub(super) spawn: String,
    pub(super) handle: String,
    pub(super) actor: String,
    pub(super) source: Option<ClauseActorTypeRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ActorTypeSourceWitnessProvider {
    Observed(ObservedActorWitnessSpec),
    Spawn(SpawnActorWitnessSpec),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActorTypeSourceWitnessSpec {
    /// The actor-type value identifies one template across all clause uses.
    source: ClauseActorTypeRef,
    /// Inputs need lengths; outputs need bytes, so the forms remain distinct.
    form: TemplateWitnessForm,
    /// The first clause use supplies the concrete template at runtime.
    provider: ActorTypeSourceWitnessProvider,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StateExpansionWitnessSpec {
    pub(super) state: String,
    pub(super) field: String,
    pub(super) memory_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ObservedOutputFieldWitnessSpec {
    pub(super) observe: String,
    pub(super) handle: String,
    pub(super) state: String,
    pub(super) field: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryWitnessSpecs {
    templates: Vec<TemplateWitnessSpec>,
    families: Vec<RouteFamilyWitnessSpec>,
    selectors: Vec<TemplateSelectorWitnessSpec>,
    observed_actors: Vec<ObservedActorWitnessSpec>,
    spawn_outputs: Vec<SpawnActorWitnessSpec>,
    actor_type_source_templates: Vec<ActorTypeSourceWitnessSpec>,
    state_expansions: Vec<StateExpansionWitnessSpec>,
    observed_output_fields: Vec<ObservedOutputFieldWitnessSpec>,
}

fn lower_entry_params(
    entry: &EntryDecl,
    witness_specs: &EntryWitnessSpecs,
    model: &Model<'_>,
    state_values: &ContractStateValuePlan,
) -> Vec<String> {
    let mut out = Vec::new();
    for param in &entry.params {
        let ty = state_values.sil_type_for_type_ref(&param.ty).unwrap_or_else(|| lower_type_ref(&param.ty, model));
        out.push(format!("{ty} {}", param.name));
    }
    for spec in &witness_specs.templates {
        match spec.form {
            TemplateWitnessForm::Bytes => {
                out.push(format!("byte[] {}", hidden_witness_prefix_name(&spec.actor)));
                out.push(format!("byte[] {}", hidden_witness_suffix_name(&spec.actor)));
            }
            TemplateWitnessForm::Len => {
                out.push(format!("int {}", hidden_witness_prefix_len_name(&spec.actor)));
                out.push(format!("int {}", hidden_witness_suffix_len_name(&spec.actor)));
            }
        }
    }
    for spec in &witness_specs.families {
        out.push(format!("byte[{}] {}", spec.byte_len, hidden_route_family_table_name_by_id(&spec.family_id)));
    }
    for spec in &witness_specs.selectors {
        out.push(format!("byte[] {}", hidden_template_selector_prefix_name(&spec.name)));
        out.push(format!("byte[] {}", hidden_template_selector_suffix_name(&spec.name)));
    }
    for spec in &witness_specs.observed_actors {
        match spec.side {
            ObservedActorSideArtifact::Input => {
                out.push(format!("int {}", hidden_observed_actor_prefix_len_name(spec)));
                out.push(format!("int {}", hidden_observed_actor_suffix_len_name(spec)));
                if observed_spec_is_dynamic_binding(entry, spec) {
                    out.push(format!("byte[32] {}", hidden_observed_actor_template_name(spec)));
                }
            }
            ObservedActorSideArtifact::Output => {
                out.push(format!("byte[] {}", hidden_observed_actor_prefix_name(spec)));
                out.push(format!("byte[] {}", hidden_observed_actor_suffix_name(spec)));
            }
        }
    }
    for spec in &witness_specs.spawn_outputs {
        out.push(format!("int {}", hidden_spawn_output_idx_name(&spec.spawn, &spec.handle)));
    }
    for spec in &witness_specs.actor_type_source_templates {
        match spec.form {
            TemplateWitnessForm::Bytes => {
                out.push(format!("byte[] {}", hidden_actor_type_source_prefix_name(&spec.source)));
                out.push(format!("byte[] {}", hidden_actor_type_source_suffix_name(&spec.source)));
            }
            TemplateWitnessForm::Len => {
                out.push(format!("int {}", hidden_actor_type_source_prefix_len_name(&spec.source)));
                out.push(format!("int {}", hidden_actor_type_source_suffix_len_name(&spec.source)));
            }
        }
    }
    for spec in &witness_specs.state_expansions {
        let len = state_packed_len(&spec.memory_state, model).expect("state expansion memory fields were validated before codegen");
        out.push(format!("byte[{len}] {}", hidden_state_expansion_preimage_name(spec)));
    }
    for spec in &witness_specs.observed_output_fields {
        out.push(format!("byte[32] {}", hidden_observed_output_field_name(spec)));
    }
    out
}

fn entry_witness_specs(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<EntryWitnessSpecs> {
    let uses = model.entry_template_uses(actor, entry)?;
    let optional_input_actors = model
        .entry_model(actor, entry)?
        .current()
        .inputs()
        .iter()
        .filter(|interaction| interaction.cardinality().range_bounds().is_some_and(|(minimum, _)| minimum == 0))
        .flat_map(|interaction| interaction.target().static_actors().map(str::to_string))
        .collect::<BTreeSet<_>>();
    let mut writes_without_input_template = BTreeSet::new();
    for target in uses.writes.intersection(&optional_input_actors) {
        if template_input_index_for_actor(actor, entry, target, model)?.is_none() {
            writes_without_input_template.insert(target.clone());
        }
    }
    let selectors = model.template_selectors_for_entry(actor, entry).expect("entry selectors are valid after model validation");
    let selector_specs = selectors
        .values()
        .cloned()
        .map(|selector| TemplateSelectorWitnessSpec {
            name: selector.name,
            actor_enum: selector.actor_enum,
            variants: selector.variants,
        })
        .collect::<Vec<_>>();
    let mut specs = template_witness_specs_for_actor(actor, model, uses.reads, uses.writes);
    // A read dependency may be optional. Keep full witness bytes unless one
    // declared input is guaranteed to authenticate the emitted template.
    for spec in &mut specs.templates {
        if writes_without_input_template.contains(&spec.actor) {
            spec.form = TemplateWitnessForm::Bytes;
        }
    }
    specs.selectors = selector_specs;
    let observed_actors = observed_actor_witness_specs(actor, entry, model)?;
    specs.spawn_outputs = spawn_output_witness_specs(actor, entry, model)?;
    specs.actor_type_source_templates = actor_type_source_witness_specs(&observed_actors, &specs.spawn_outputs);
    specs.observed_actors = observed_actors.into_iter().filter(|spec| spec.source.is_none()).collect();
    specs.state_expansions = state_expansion_witness_specs_for_actor(actor, model);
    specs.observed_output_fields = observed_output_field_witness_specs(actor, entry, model);
    Ok(specs)
}

pub(in crate::compiler::codegen) fn entry_template_witness_uses_bytes(
    actor: &ActorDecl,
    entry: &EntryDecl,
    target: &str,
    model: &Model<'_>,
) -> Result<bool> {
    entry_witness_specs(actor, entry, model)?
        .templates
        .iter()
        .find(|spec| spec.actor == target)
        .map(|spec| spec.form == TemplateWitnessForm::Bytes)
        .ok_or_else(|| {
            ArgentError::new(format!(
                "entry `{}::{}` has no template witness plan for consumed actor `{target}`",
                actor.name, entry.name
            ))
        })
}

fn observed_actor_witness_specs(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<Vec<ObservedActorWitnessSpec>> {
    let mut specs = Vec::new();
    for observe in &entry.observes {
        specs.extend(observed_actor_witness_specs_for_observe(actor, entry, observe, model)?);
    }
    Ok(specs)
}

fn spawn_output_witness_specs(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<Vec<SpawnActorWitnessSpec>> {
    let mut specs = Vec::new();
    for group in model.entry_model(actor, entry)?.genesis_groups() {
        let spawn = group.spawn().expect("genesis covenant group retains its spawn declaration");
        for interaction in group.outputs() {
            let InteractionSource::SpawnOutput(output) = interaction.source() else {
                unreachable!("genesis covenant outputs are spawn outputs");
            };
            let source =
                if interaction.target().is_source() { clause_actor_type_ref(&output.actor, actor, entry, model)? } else { None };
            specs.push(SpawnActorWitnessSpec {
                spawn: spawn.name.clone(),
                handle: output.name.clone(),
                actor: output.actor.clone(),
                source,
            });
        }
    }
    Ok(specs)
}

fn actor_type_source_witness_specs(
    observed: &[ObservedActorWitnessSpec],
    spawned: &[SpawnActorWitnessSpec],
) -> Vec<ActorTypeSourceWitnessSpec> {
    let mut seen = BTreeSet::new();
    let mut specs = Vec::new();
    for spec in observed {
        let Some(source) = &spec.source else {
            continue;
        };
        let form = match spec.side {
            ObservedActorSideArtifact::Input => TemplateWitnessForm::Len,
            ObservedActorSideArtifact::Output => TemplateWitnessForm::Bytes,
        };
        if seen.insert((source.clone(), form)) {
            specs.push(ActorTypeSourceWitnessSpec {
                source: source.clone(),
                form,
                provider: ActorTypeSourceWitnessProvider::Observed(spec.clone()),
            });
        }
    }
    for spec in spawned {
        let Some(source) = &spec.source else {
            continue;
        };
        if seen.insert((source.clone(), TemplateWitnessForm::Bytes)) {
            specs.push(ActorTypeSourceWitnessSpec {
                source: source.clone(),
                form: TemplateWitnessForm::Bytes,
                provider: ActorTypeSourceWitnessProvider::Spawn(spec.clone()),
            });
        }
    }
    specs
}

fn actor_type_source_witness_subject(provider: &ActorTypeSourceWitnessProvider) -> HiddenParamSubjectArtifact {
    match provider {
        ActorTypeSourceWitnessProvider::Observed(spec) => HiddenParamSubjectArtifact::ObservedActor {
            observe: spec.observe.clone(),
            side: spec.side,
            handle: spec.handle.clone(),
            actor: spec.actor.clone(),
        },
        ActorTypeSourceWitnessProvider::Spawn(spec) => HiddenParamSubjectArtifact::SpawnActor {
            spawn: spec.spawn.clone(),
            handle: spec.handle.clone(),
            actor: spec.actor.clone(),
        },
    }
}

pub(super) fn observed_output_field_witness_specs(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
) -> Vec<ObservedOutputFieldWitnessSpec> {
    let mut seen = BTreeSet::new();
    let mut specs = Vec::new();
    for observe in &entry.observes {
        for output in &observe.outputs {
            let Ok(Some(state_name)) = observed_open_state_for_decl(actor, entry, observe, output, model) else {
                continue;
            };
            let Ok(state) = model.storage_state(&state_name) else {
                continue;
            };
            for field in &state.fields {
                if !field.virtual_slot {
                    continue;
                }
                let spec = ObservedOutputFieldWitnessSpec {
                    observe: observe.name.clone(),
                    handle: output.name.clone(),
                    state: state_name.to_string(),
                    field: field.name.clone(),
                };
                if seen.insert(spec.clone()) {
                    specs.push(spec);
                }
            }
        }
    }
    specs
}

fn template_witness_specs_for_actor(
    actor: &ActorDecl,
    model: &Model<'_>,
    read_actors: BTreeSet<String>,
    write_actors: BTreeSet<String>,
) -> EntryWitnessSpecs {
    let mut specs = template_witness_specs(model, read_actors, write_actors.clone());
    let mut family_specs = BTreeMap::<String, RouteFamilyWitnessSpec>::new();
    for target in &write_actors {
        if target == &actor.name || !model.app_actors.contains(target) {
            continue;
        }
        let transition =
            model.route_transition(&actor.name, target).expect("validated foreign-template route has a planned cut transition");
        for family_id in &transition.families_to_open {
            let family = model.route_family(family_id).expect("validated route transition references a known family");
            family_specs
                .entry(family.id.clone())
                .or_insert(RouteFamilyWitnessSpec { family_id: family.id.clone(), byte_len: family.table_byte_len() });
        }
    }
    for spec in &mut specs {
        spec.source = model
            .route_family_for_actor(&spec.actor)
            .filter(|family| family_specs.contains_key(&family.id))
            .and_then(|family| {
                family
                    .table_actors()
                    .iter()
                    .position(|candidate| candidate == &spec.actor)
                    .map(|index| TemplateWitnessSource::FamilyTable { family_id: family.id.clone(), offset: index * 32 })
            })
            .unwrap_or_else(|| template_source_for_actor(&actor.state, &spec.actor, model));
    }
    EntryWitnessSpecs {
        templates: specs,
        families: family_specs.into_values().collect(),
        selectors: Vec::new(),
        observed_actors: Vec::new(),
        spawn_outputs: Vec::new(),
        actor_type_source_templates: Vec::new(),
        state_expansions: Vec::new(),
        observed_output_fields: Vec::new(),
    }
}

pub(super) fn state_expansion_witness_specs_for_actor(actor: &ActorDecl, model: &Model<'_>) -> Vec<StateExpansionWitnessSpec> {
    model
        .state(&actor.state)
        .ok()
        .and_then(|state| state.expansion.as_ref())
        .map(|expansion| {
            expansion
                .digests
                .iter()
                .map(|digest| StateExpansionWitnessSpec {
                    state: actor.state.clone(),
                    field: digest.field.clone(),
                    memory_state: digest.state.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn state_expansion_digest_fields_for_state(state_name: &str, model: &Model<'_>) -> BTreeSet<String> {
    model
        .state(state_name)
        .ok()
        .and_then(|state| state.expansion.as_ref())
        .map(|expansion| expansion.digests.iter().map(|digest| digest.field.clone()).collect())
        .unwrap_or_default()
}

fn template_witness_specs(
    model: &Model<'_>,
    read_actors: BTreeSet<String>,
    write_actors: BTreeSet<String>,
) -> Vec<TemplateWitnessSpec> {
    let mut required = read_actors.union(&write_actors).cloned().collect::<BTreeSet<_>>();
    let mut ordered = Vec::new();
    for actor in model.app_actors.iter() {
        if required.remove(actor) {
            ordered.push(TemplateWitnessSpec {
                actor: actor.clone(),
                form: witness_form(actor, &read_actors, &write_actors),
                source: TemplateWitnessSource::Field,
            });
        }
    }
    ordered.extend(required.into_iter().map(|actor| {
        let form = witness_form(&actor, &read_actors, &write_actors);
        TemplateWitnessSpec { actor, form, source: TemplateWitnessSource::Field }
    }));
    ordered
}

fn witness_form(actor: &str, read_actors: &BTreeSet<String>, write_actors: &BTreeSet<String>) -> TemplateWitnessForm {
    if write_actors.contains(actor) && !read_actors.contains(actor) { TemplateWitnessForm::Bytes } else { TemplateWitnessForm::Len }
}

fn template_source_for_actor(state: &str, actor: &str, model: &Model<'_>) -> TemplateWitnessSource {
    let Some(family) = model.route_family_for_actor(actor) else {
        return TemplateWitnessSource::Field;
    };
    if family.state != state || family.direct_template_actors().iter().any(|direct_actor| direct_actor == actor) {
        return TemplateWitnessSource::Field;
    }
    family
        .table_actors()
        .iter()
        .position(|candidate| candidate == actor)
        .map(|index| TemplateWitnessSource::FamilyTable { family_id: family.id.clone(), offset: index * 32 })
        .unwrap_or(TemplateWitnessSource::Field)
}

fn imported_template_specs_for_actor(actor: &ActorDecl, model: &Model<'_>) -> Vec<ImportedTemplateSpec> {
    actor
        .entries
        .iter()
        .flat_map(|entry| imported_template_specs_for_entry(actor, entry, model))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn imported_template_specs_for_entry(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Vec<ImportedTemplateSpec> {
    let entry_model = model.entry_model(actor, entry).expect("selected app entry has a model");
    entry_model
        .existing_groups()
        .chain(entry_model.genesis_groups())
        .flat_map(|group| group.inputs().iter().chain(group.outputs()))
        .flat_map(|interaction| interaction.target().static_actors())
        .filter_map(|target| match model.static_actor_target(target) {
            Some(StaticActorTarget::CrossApp(linked)) => Some(ImportedTemplateSpec::from_linked(linked)),
            Some(StaticActorTarget::InApp(_)) | None => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn observed_actor_witness_specs_for_observe(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    model: &Model<'_>,
) -> Result<Vec<ObservedActorWitnessSpec>> {
    observed_actor_specs_for_observe(actor, entry, observe, model)?
        .into_iter()
        .filter_map(|spec| {
            let observed = observed_decl_for_spec(observe, &spec)?;
            match static_observed_actor_target(actor, entry, observe, observed, model) {
                Ok(Some(_)) => None,
                Ok(None) => Some(Ok(spec)),
                Err(err) => Some(Err(err)),
            }
        })
        .collect()
}

fn observed_actor_specs_for_observe(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    model: &Model<'_>,
) -> Result<Vec<ObservedActorWitnessSpec>> {
    let mut seen = BTreeSet::new();
    let mut specs = Vec::new();

    for output in &observe.outputs {
        let spec = if observed_reuses_input_template(observe, output) {
            let input = first_observed_input_for_actor(observe, &output.actor)
                .expect("input-template reuse requires a matching observed input");
            observed_input_spec(actor, entry, observe, input, model)?
        } else {
            observed_actor_spec(actor, entry, observe, ObservedActorSideArtifact::Output, output, model)?
        };
        if seen.insert((spec.side, observed_witness_key(actor, entry, observe, output, model)?)) {
            specs.push(spec);
        }
    }
    for input in &observe.inputs {
        if first_observed_output_for_actor(observe, &input.actor).is_some() {
            continue;
        }
        let spec = observed_actor_spec(actor, entry, observe, ObservedActorSideArtifact::Input, input, model)?;
        if seen.insert((spec.side, observed_witness_key(actor, entry, observe, input, model)?)) {
            specs.push(spec);
        }
    }
    Ok(specs)
}

fn observed_decl_for_spec<'a>(observe: &'a ObserveDecl, spec: &ObservedActorWitnessSpec) -> Option<&'a ObservedActorDecl> {
    match spec.side {
        ObservedActorSideArtifact::Input => observe.inputs.iter().find(|input| input.name == spec.handle),
        ObservedActorSideArtifact::Output => observe.outputs.iter().find(|output| output.name == spec.handle),
    }
}

fn observed_witness_key(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<String> {
    if observed_is_dynamic_binding(observe, observed) {
        return Ok(format!("binding:{}", observed.actor));
    }
    if observed_is_source_actor_type(actor, entry, observed, model)? {
        return Ok(format!("expr:{}", compact_expr(&observed.actor)));
    }
    Ok(format!("actor:{}", observed.actor))
}

/// Resolve a fixed observed target without admitting it to local routing.
pub(super) fn static_observed_actor_target<'m>(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    model: &'m Model<'_>,
) -> Result<Option<StaticActorTarget<'m>>> {
    if observed_open_state_for_decl(actor, entry, observe, observed, model)?.is_some() {
        return Ok(None);
    }
    Ok(model.static_actor_target(&observed.actor))
}

/// Return the first entry input that authenticated a selected-app actor template.
pub(super) fn template_input_index_for_actor(
    actor: &ActorDecl,
    entry: &EntryDecl,
    target: &str,
    model: &Model<'_>,
) -> Result<Option<String>> {
    let target = model.static_actor_target(target).expect("template input target is a fixed actor");
    template_input_index_for_target(actor, entry, target, model)
}

/// Return the first entry input that authenticated a fixed actor template.
pub(super) fn template_input_index_for_target(
    actor: &ActorDecl,
    entry: &EntryDecl,
    target: StaticActorTarget<'_>,
    model: &Model<'_>,
) -> Result<Option<String>> {
    for interaction in model.entry_model(actor, entry)?.current().inputs() {
        let InteractionSource::Consume(consume) = interaction.source() else {
            unreachable!("current entry inputs are consumes");
        };
        if model.static_actor_target(&consume.actor).is_some_and(|candidate| candidate.same_actor(&target)) {
            let input_index = match interaction.location() {
                InteractionLocation::Range { start, .. }
                    if interaction.cardinality().range_bounds().is_some_and(|(minimum, _)| minimum > 0) =>
                {
                    let slot_offset = match entry.kind {
                        EntryKind::Leader => 1,
                        EntryKind::Delegate => 0,
                    };
                    Some(format!("OpCovInputIdx({}, {})", hidden_cov_id_name(), slot_offset + start))
                }
                InteractionLocation::Range { .. } => None,
                InteractionLocation::FromStart(_) | InteractionLocation::FromEnd(_) => Some(hidden_input_idx_name(&consume.name)),
            };
            if input_index.is_some() {
                return Ok(input_index);
            }
        }
    }
    // Genesis groups have no inputs, so only existing groups can authenticate
    // a template beyond the current covenant's consumes.
    for group in model.entry_model(actor, entry)?.existing_groups() {
        let observe = group.observe().expect("existing covenant group retains its observe declaration");
        for interaction in group.inputs() {
            let InteractionSource::ObserveInput(input) = interaction.source() else {
                unreachable!("existing covenant inputs are observed inputs");
            };
            if static_observed_actor_target(actor, entry, observe, input, model)?
                .is_some_and(|candidate| candidate.same_actor(&target))
            {
                return Ok(Some(hidden_observed_input_idx_name(&observe.name, &input.name)));
            }
        }
    }
    Ok(None)
}

pub(super) fn observed_is_source_actor_type(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<bool> {
    Ok(source_actor_type_state_for_expr(&observed.actor, actor, entry, model)?.is_some())
}

pub(super) fn observed_actor_template_expr_for_entry(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    spec: &ObservedActorWitnessSpec,
) -> Result<String> {
    if let Some(target) = static_observed_actor_target(actor, entry, observe, observed, model)? {
        return Ok(match target {
            StaticActorTarget::InApp(target) => hidden_template_name(&target.name),
            StaticActorTarget::CrossApp(target) => hidden_imported_template_name(&ImportedTemplateSpec::from_linked(target)),
        });
    }
    if observed_is_dynamic_binding(observe, observed) {
        return Ok(observed.actor.clone());
    }
    if observed_is_source_actor_type(actor, entry, observed, model)? {
        return lower_entry_expr(actor, entry, model, EntryInputReferenceView::None, &observed.actor, Some("byte[32]"));
    }
    Ok(hidden_observed_actor_template_name(spec))
}

pub(super) fn observed_input_spec(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    input: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<ObservedActorWitnessSpec> {
    observed_actor_spec(actor, entry, observe, ObservedActorSideArtifact::Input, input, model)
}

pub(super) fn observed_output_spec(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    output: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<ObservedActorWitnessSpec> {
    observed_actor_spec(actor, entry, observe, ObservedActorSideArtifact::Output, output, model)
}

fn observed_actor_spec(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    side: ObservedActorSideArtifact,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<ObservedActorWitnessSpec> {
    let source = if observed_is_dynamic_binding(observe, observed) {
        None
    } else {
        clause_actor_type_ref(&observed.actor, actor, entry, model)?
    };
    Ok(ObservedActorWitnessSpec {
        observe: observe.name.clone(),
        side,
        handle: observed.name.clone(),
        actor: observed.actor.clone(),
        source,
    })
}

pub(super) fn observed_reuses_input_template(observe: &ObserveDecl, output: &ObservedActorDecl) -> bool {
    observe.inputs.iter().any(|input| input.actor == output.actor)
}

fn observed_spec_is_dynamic_binding(entry: &EntryDecl, spec: &ObservedActorWitnessSpec) -> bool {
    let Some(observe) = entry.observes.iter().find(|observe| observe.name == spec.observe) else {
        return false;
    };
    observed_decl_for_spec(observe, spec).is_some_and(|observed| observed_is_dynamic_binding(observe, observed))
}

fn first_observed_output_for_actor<'a>(observe: &'a ObserveDecl, actor: &str) -> Option<&'a ObservedActorDecl> {
    observe.outputs.iter().find(|output| output.actor == actor)
}

pub(super) fn first_observed_input_for_actor<'a>(observe: &'a ObserveDecl, actor: &str) -> Option<&'a ObservedActorDecl> {
    observe.inputs.iter().find(|input| input.actor == actor)
}

fn emit_manifest(program: &Program, model: &Model<'_>) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"app\": \"{}\",\n", json_escape(&model.app_name)));
    out.push_str(&format!("  \"root\": \"{}\",\n", json_escape(&manifest_path(&program.root))));

    out.push_str("  \"modules\": [\n");
    for (idx, module) in program.modules.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!("    \"{}\"", json_escape(&manifest_path(&module.path))));
    }
    out.push_str("\n  ],\n");

    out.push_str("  \"templates\": [\n");
    for (idx, actor) in model.app_actors.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "    {{ \"actor\": \"{}\", \"symbol\": \"{}\", \"hash\": null }}",
            json_escape(actor),
            json_escape(&hidden_template_name(actor))
        ));
    }
    out.push_str("\n  ],\n");

    out.push_str("  \"actors\": [\n");
    for (idx, actor) in model.actors.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", json_escape(&actor.name)));
        out.push_str(&format!("      \"state\": \"{}\",\n", json_escape(&actor.state)));
        out.push_str(&format!("      \"sil\": \"sil/{}.sil\",\n", json_escape(&actor.name)));
        out.push_str("      \"entries\": [\n");
        for (entry_idx, entry) in actor.entries.iter().enumerate() {
            if entry_idx > 0 {
                out.push_str(",\n");
            }
            out.push_str("        {\n");
            out.push_str(&format!("          \"name\": \"{}\",\n", json_escape(&entry.name)));
            out.push_str(&format!(
                "          \"kind\": \"{}\",\n",
                match entry.kind {
                    EntryKind::Leader => word::LEADER,
                    EntryKind::Delegate => word::DELEGATE,
                }
            ));
            let entry_model = model.entry_model(actor, entry).expect("manifest entry has a compiler model");
            out.push_str("          \"emits\": ");
            emit_emit_spec_json(&mut out, entry_model);
            out.push_str(",\n");
            out.push_str("          \"consumes\": [");
            for (consume_idx, interaction) in entry_model.current().inputs().iter().enumerate() {
                if consume_idx > 0 {
                    out.push_str(", ");
                }
                let InteractionSource::Consume(consume) = interaction.source() else {
                    unreachable!("current entry inputs are consumes");
                };
                out.push_str(&format!(
                    "{{ \"name\": \"{}\", \"actor\": \"{}\"",
                    json_escape(&consume.name),
                    json_escape(&consume.actor)
                ));
                emit_manifest_cardinality(&mut out, interaction);
                out.push_str(" }");
            }
            out.push_str("],\n");
            out.push_str("          \"routes\": [");
            for (route_idx, route) in entry_model.routes().iter().enumerate() {
                if route_idx > 0 {
                    out.push_str(", ");
                }
                match &route.successor {
                    ResolvedSuccessor::ExactSelf => out.push_str(&format!(
                        "{{ \"output\": \"{}\", \"successor\": {{ \"kind\": \"exact_self\" }} }}",
                        json_escape(&route.output)
                    )),
                    ResolvedSuccessor::Constructed { actor, state, arity } => {
                        let arity = if *arity == RouteArity::Many { ", \"arity\": \"many\"" } else { "" };
                        out.push_str(&format!(
                            "{{ \"output\": \"{}\", \"successor\": {{ \"kind\": \"constructed\"{arity}, \"actor\": \"{}\", \"state\": \"{}\" }} }}",
                            json_escape(&route.output),
                            json_escape(actor),
                            json_escape(&compact_expr(state))
                        ));
                    }
                }
            }
            out.push_str("]\n");
            out.push_str("        }");
        }
        out.push_str("\n      ]\n");
        out.push_str("    }");
    }
    out.push_str("\n  ]\n");
    out.push_str("}\n");
    out
}

fn emit_artifact_json(program: &Program, model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<String> {
    let artifact = emit_artifact(program, model, actor_sil)?;
    let mut json = silverscript_abi::to_pretty_json(&artifact).map_err(|err| ArgentError::new(err.to_string()))?;
    json.push('\n');
    Ok(json)
}

fn emit_artifact(program: &Program, model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<Artifact> {
    let templates = model.app_actors.iter().map(|actor| template_ref_artifact(actor)).collect::<Vec<_>>();

    let argent_states = model
        .all_states()
        .map(|state| ArgentStateArtifact {
            name: state.name.clone(),
            fields: model
                .storage_state(&state.name)
                .expect("state expansions are valid after model validation")
                .fields
                .iter()
                .map(|field| ArgentFieldArtifact {
                    name: field.name.clone(),
                    ty: type_artifact(&field.ty, model),
                    source_type: source_type_annotation(&field.ty, model),
                    virtual_slot: field.virtual_slot,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let state_expansions = model
        .all_states()
        .filter_map(|state| {
            state.expansion.as_ref().map(|expansion| StateExpansionArtifact {
                state: state.name.clone(),
                base: expansion.base.clone(),
                digests: expansion
                    .digests
                    .iter()
                    .map(|digest| StateDigestExpansionArtifact { field: digest.field.clone(), state: digest.state.clone() })
                    .collect(),
            })
        })
        .collect::<Vec<_>>();

    let sil_abi = sil_abi_artifact(model, actor_sil)?;
    let actor_enums = model
        .actor_enums
        .values()
        .map(|actor_enum| ActorEnumArtifact {
            name: actor_enum.name.clone(),
            state: actor_enum.state.clone(),
            variants: actor_enum.variants.clone(),
        })
        .collect::<Vec<_>>();
    let argent_actors = model.actors.iter().map(|actor| actor_artifact(actor, model)).collect::<Result<Vec<_>>>()?;
    let template_plan = template_plan_artifact(model, &templates, &argent_actors, &sil_abi.contracts, actor_sil)?;
    let interfaces = interface_set_artifact(model)?;

    let mut artifact = Artifact {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        id: String::new(),
        generator: GeneratorArtifact { name: "argentc".to_string(), version: env!("CARGO_PKG_VERSION").to_string() },
        app: model.app_name.clone(),
        dependencies: model.app_dependencies.clone(),
        root: manifest_path(&program.root),
        modules: program.modules.iter().map(|module| manifest_path(&module.path)).collect(),
        argent: ArgentArtifact {
            templates,
            template_plan,
            interfaces,
            states: argent_states,
            state_expansions,
            actor_enums,
            actors: argent_actors,
        },
        sil_abi,
    };
    artifact.id =
        artifact.computed_id_hex().map_err(|err| ArgentError::new(format!("failed to compute generated artifact id: {err}")))?;
    artifact.check_consistency().map_err(|err| ArgentError::new(format!("invalid generated artifact: {err}")))?;
    Ok(artifact)
}

fn source_type_artifact(ty: &TypeRef) -> SourceTypeArtifact {
    SourceTypeArtifact {
        name: ty.name.clone(),
        array: ty.array.map(|array| match array {
            ArrayDim::Dynamic => SourceArrayArtifact::Dynamic,
            ArrayDim::Fixed(len) => SourceArrayArtifact::Fixed(len),
        }),
        actor_state: ty.actor_state.clone(),
    }
}

fn source_type_annotation(ty: &TypeRef, model: &Model<'_>) -> Option<SourceTypeArtifact> {
    (ty.name == word::COVENANT_ID || ty.is_actor_type() || model.is_actor_enum_type(ty)).then(|| source_type_artifact(ty))
}

fn interface_set_artifact(model: &Model<'_>) -> Result<InterfaceSetArtifact> {
    let exports = model.app_actors.iter().map(|actor| actor_interface_artifact(actor, model)).collect::<Result<Vec<_>>>()?;

    let mut imports = BTreeMap::new();
    for actor in &model.actors {
        for entry in &actor.entries {
            for observe in &entry.observes {
                for observed in observe.inputs.iter().chain(observe.outputs.iter()) {
                    if observed_open_state_for_decl(actor, entry, observe, observed, model)?.is_some() {
                        continue;
                    }
                    if let Some(StaticActorTarget::CrossApp(linked)) = model.static_actor_target(&observed.actor) {
                        imports.entry((linked.app.clone(), linked.actor.clone())).or_insert_with(|| linked.interface.clone());
                    }
                }
            }
            for group in model.entry_model(actor, entry)?.genesis_groups() {
                for output in group.outputs() {
                    if let Some(StaticActorTarget::CrossApp(linked)) = model.resolve_static_actor_target(output.target()) {
                        imports.entry((linked.app.clone(), linked.actor.clone())).or_insert_with(|| linked.interface.clone());
                    }
                }
            }
        }
    }

    Ok(InterfaceSetArtifact { exports, imports: imports.into_values().collect() })
}

fn actor_interface_artifact(actor_name: &str, model: &Model<'_>) -> Result<ActorInterfaceArtifact> {
    let actor = model.actor(actor_name)?;
    let runtime_fields = runtime_state_fields_for_actor(actor, model)?;
    let fingerprint_hex = actor_interface_fingerprint_hex(&actor.name, &actor.state, &runtime_fields)
        .map_err(|err| ArgentError::new(format!("failed to compute actor interface fingerprint for `{}`: {err}", actor.name)))?;
    Ok(ActorInterfaceArtifact {
        id: actor_interface_id(&actor.name),
        app: model.app_name.clone(),
        actor: actor.name.clone(),
        state: actor.state.clone(),
        fingerprint_hex,
    })
}

fn template_ref_artifact(actor: &str) -> TemplateRefArtifact {
    TemplateRefArtifact { id: template_receipt_id(actor), actor: actor.to_string(), symbol: hidden_template_name(actor) }
}

#[derive(Debug)]
struct TemplateReceiptDraft {
    id: String,
    actor: String,
    contract: String,
    symbol: String,
    sil_template_hash: [u8; 32],
    compiled_template: ActorTemplateArtifact,
}

#[derive(Debug)]
struct TemplatePlanDraft {
    templates: Vec<TemplateReceiptDraft>,
    templates_by_id: BTreeMap<String, usize>,
    templates_by_actor: BTreeMap<String, usize>,
    runtime_states: Vec<RuntimeStatePlanArtifact>,
    route_tables: Vec<RouteTemplateTableArtifact>,
    route_proofs: Vec<RouteTemplateProofArtifact>,
    route_families: Vec<RouteTemplateFamilyArtifact>,
}

impl TemplateHashLookup for TemplatePlanDraft {
    fn template_hash_by_id(&self, id: &str) -> Option<TemplateHashRef<'_>> {
        self.templates_by_id.get(id).map(|index| &self.templates[*index]).map(|template| TemplateHashRef {
            id: &template.id,
            actor: &template.actor,
            hash: &template.sil_template_hash,
        })
    }

    fn template_hash_by_actor(&self, actor: &str) -> Option<TemplateHashRef<'_>> {
        self.templates_by_actor.get(actor).map(|index| &self.templates[*index]).map(|template| TemplateHashRef {
            id: &template.id,
            actor: &template.actor,
            hash: &template.sil_template_hash,
        })
    }
}

impl TemplatePlanLookup for TemplatePlanDraft {
    fn route_tables(&self) -> &[RouteTemplateTableArtifact] {
        &self.route_tables
    }

    fn route_proofs(&self) -> &[RouteTemplateProofArtifact] {
        &self.route_proofs
    }

    fn route_families(&self) -> &[RouteTemplateFamilyArtifact] {
        &self.route_families
    }
}

fn template_plan_artifact(
    model: &Model<'_>,
    templates: &[TemplateRefArtifact],
    actors: &[ActorArtifact],
    sil_contracts: &BTreeMap<String, SilContractArtifact>,
    actor_sil: &BTreeMap<String, String>,
) -> Result<TemplatePlanArtifact> {
    let templates = templates
        .iter()
        .map(|template| {
            let contract = sil_contracts
                .get(&template.actor)
                .ok_or_else(|| ArgentError::new(format!("missing Sil ABI contract for template actor `{}`", template.actor)))?;
            Ok(TemplateReceiptDraft {
                id: template.id.clone(),
                actor: template.actor.clone(),
                contract: template.actor.clone(),
                symbol: template.symbol.clone(),
                sil_template_hash: contract.compiled.template_hash,
                compiled_template: extract_sil_template(&contract.compiled)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut runtime_states = Vec::new();
    for actor in &model.actors {
        if let Some(runtime_state) = runtime_state_plan_artifact(actor, model)? {
            runtime_states.push(runtime_state);
        }
    }
    let route_tables = route_template_tables_artifact(&runtime_states, sil_contracts)?;
    let route_families = route_template_families_artifact(model);
    let templates_by_id = templates.iter().enumerate().map(|(index, template)| (template.id.clone(), index)).collect();
    let templates_by_actor = templates.iter().enumerate().map(|(index, template)| (template.actor.clone(), index)).collect();
    let mut draft = TemplatePlanDraft {
        templates,
        templates_by_id,
        templates_by_actor,
        runtime_states,
        route_tables,
        route_proofs: Vec::new(),
        route_families,
    };
    draft.route_proofs = route_template_proofs_artifact(&draft.route_tables, &draft)?;

    let mut seen = BTreeSet::new();
    let mut witness_recipes = Vec::new();
    for actor in actors {
        for entry in &actor.entries {
            for param in &entry.hidden_params {
                if seen.insert(param.recipe_id.clone()) {
                    witness_recipes.push(WitnessRecipeArtifact {
                        id: param.recipe_id.clone(),
                        template_id: match &param.subject {
                            HiddenParamSubjectArtifact::Actor { actor } if model.app_actors.contains(actor) => {
                                Some(template_receipt_id(actor))
                            }
                            HiddenParamSubjectArtifact::Actor { .. } => None,
                            HiddenParamSubjectArtifact::ObservedActor { .. } => None,
                            HiddenParamSubjectArtifact::SpawnActor { .. } => None,
                            HiddenParamSubjectArtifact::ObservedOutputField { .. } => None,
                            HiddenParamSubjectArtifact::RouteFamily { .. } => None,
                            HiddenParamSubjectArtifact::TemplateSelector { .. } => None,
                            HiddenParamSubjectArtifact::StateExpansion { .. } => None,
                        },
                        subject: param.subject.clone(),
                        param: param.name.clone(),
                        purpose: param.purpose,
                        route_proof_id: param.route_proof_id.clone(),
                    });
                }
            }
        }
    }

    let handles = draft
        .templates
        .iter()
        .map(|template| actor_type_handle_artifact(template, &draft, model, actor_sil))
        .collect::<Result<Vec<_>>>()?;
    let templates = draft
        .templates
        .into_iter()
        .zip(handles)
        .map(|(template, actor_type_handle)| TemplateReceiptArtifact {
            id: template.id,
            actor: template.actor,
            contract: template.contract,
            symbol: template.symbol,
            sil_template_hash: template.sil_template_hash,
            actor_type_handle,
        })
        .collect();
    Ok(TemplatePlanArtifact {
        templates,
        runtime_states: draft.runtime_states,
        route_tables: draft.route_tables,
        route_proofs: draft.route_proofs,
        route_families: draft.route_families,
        witness_recipes,
    })
}

fn actor_type_handle_artifact(
    template: &TemplateReceiptDraft,
    plan: &TemplatePlanDraft,
    model: &Model<'_>,
    actor_sil: &BTreeMap<String, String>,
) -> Result<ActorTypeHandleArtifact> {
    let actor = model.actor(&template.actor)?;
    let expansion = model.state(&actor.state)?.expansion.as_ref();
    let source_state = expansion.map_or(actor.state.as_str(), |expansion| expansion.base.as_str());
    let runtime_plan = plan.runtime_states.iter().find(|runtime_state| runtime_state.contract == actor.name);
    let context_fields = runtime_plan
        .map(|runtime_state| runtime_state.field_roles.iter().map(|field| field.name.clone()).collect::<Vec<_>>())
        .unwrap_or_default();
    if context_fields.is_empty() {
        return Ok(ActorTypeHandleArtifact {
            state: source_state.to_string(),
            context_fields,
            template: template.compiled_template.clone(),
        });
    }
    let context_values = runtime_plan
        .map(|runtime_state| {
            runtime_state
                .field_roles
                .iter()
                .map(|field| {
                    fixed_runtime_context_value(plan, runtime_state, field)
                        .map_err(|err| ArgentError::new(format!("cannot derive fixed source-state context: {err}")))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let runtime_fields = runtime_state_fields_for_actor(actor, model)?;
    let context_state = RuntimeStateArtifact {
        source: source_state.to_string(),
        fields: runtime_fields.iter().take(context_fields.len()).cloned().collect(),
    };
    let context_state_values =
        context_fields.iter().cloned().zip(context_values.iter().cloned().map(ArtifactValue::Bytes)).collect::<BTreeMap<_, _>>();
    // Fixed route context contains only byte leaves, so it needs no named
    // struct definitions from the contract ABI.
    let context_abi = SilAbiArtifact {
        schema_version: SIL_ABI_SCHEMA_VERSION,
        compiler_version: String::new(),
        structs: BTreeMap::new(),
        contracts: BTreeMap::new(),
    };
    let context_script = silverscript_abi::encode_runtime_state_script(&context_abi, &context_state, &context_state_values)
        .map_err(|err| ArgentError::new(format!("cannot encode actor_type<{source_state}> context: {err}")))?;

    let mut args = context_values.into_iter().map(SilExpr::from).collect::<Vec<_>>();
    for field in &model.storage_state(&actor.state)?.fields {
        args.push(placeholder_expr_for_type(&field.ty).map_err(|err| {
            ArgentError::new(format!(
                "cannot build actor_type<{}> placeholder for actor `{}` field `{}`: {err}",
                source_state, actor.name, field.name
            ))
        })?);
    }

    let sil = actor_sil
        .get(&actor.name)
        .ok_or_else(|| ArgentError::new(format!("missing generated Silverscript for actor `{}`", actor.name)))?;
    let compiled = compile_contract(sil, &args, CompileOptions::default()).map_err(|err| {
        ArgentError::new(format!("generated Silverscript for actor `{}` failed to compile its source-state cut: {err}", actor.name))
    })?;
    if compiled.template_hash() != template.sil_template_hash {
        return Err(ArgentError::new(format!("actor `{}` Sil template changed while resolving its capsule context", actor.name)));
    }
    if compiled.ast.fields.len() != runtime_fields.len() {
        return Err(ArgentError::new(format!("actor `{}` compiled state fields do not match its runtime state layout", actor.name)));
    }

    let state_start = compiled.state_layout.start;
    let context_end = state_start
        .checked_add(context_script.len())
        .ok_or_else(|| ArgentError::new(format!("actor `{}` capsule context offset overflow", actor.name)))?;
    let state_end = state_start
        .checked_add(compiled.state_layout.len)
        .ok_or_else(|| ArgentError::new(format!("actor `{}` state offset overflow", actor.name)))?;
    if compiled.bytecode.get(state_start..context_end) != Some(context_script.as_slice()) {
        return Err(ArgentError::new(format!("actor `{}` compiled capsule context does not match its runtime state ABI", actor.name)));
    }
    let prefix = &compiled.bytecode[..context_end];
    let suffix = &compiled.bytecode[state_end..];
    let hash = silverscript_lang::template::template_hash(prefix, suffix);
    Ok(ActorTypeHandleArtifact {
        state: source_state.to_string(),
        context_fields,
        template: ActorTemplateArtifact { prefix: prefix.to_vec(), suffix: suffix.to_vec(), hash },
    })
}

fn route_template_families_artifact(model: &Model<'_>) -> Vec<RouteTemplateFamilyArtifact> {
    model
        .route_families
        .iter()
        .map(|family| RouteTemplateFamilyArtifact {
            id: family.id.clone(),
            state: family.state.clone(),
            representative_actor: family.rep().to_string(),
            entry_actors: family.entry_actors.clone(),
            table_id: route_template_table_receipt_id(&family.state, &hidden_route_family_table_name(family)),
            actors: family.actors.clone(),
        })
        .collect()
}

fn route_template_tables_artifact(
    runtime_states: &[RuntimeStatePlanArtifact],
    sil_contracts: &BTreeMap<String, SilContractArtifact>,
) -> Result<Vec<RouteTemplateTableArtifact>> {
    let mut tables = BTreeMap::<String, RouteTemplateTableArtifact>::new();
    for runtime_state in runtime_states {
        let contract = sil_contracts
            .get(&runtime_state.contract)
            .ok_or_else(|| ArgentError::new(format!("missing Sil ABI contract for runtime state `{}`", runtime_state.contract)))?;
        for field in &runtime_state.field_roles {
            let sil_field = contract.runtime_state.fields.iter().find(|sil_field| sil_field.name == field.name).ok_or_else(|| {
                ArgentError::new(format!(
                    "runtime role for `{}::{}` points at a missing Sil ABI state field",
                    runtime_state.contract, field.name
                ))
            })?;
            let (leaves, expected_field_ty) = match &field.role {
                RuntimeFieldRoleArtifact::TemplateTable { contracts } => {
                    let leaves = contracts
                        .iter()
                        .map(|actor| RuntimeRouteLeafArtifact::Contract { contract: actor.clone() })
                        .collect::<Vec<_>>();
                    let expected_ty = TypeArtifact::FixedBytes { len: leaves.len() * 32 };
                    (leaves, expected_ty)
                }
                RuntimeFieldRoleArtifact::TemplateDigest { .. } => continue,
                RuntimeFieldRoleArtifact::TemplateRoot { leaves } => (leaves.clone(), TypeArtifact::FixedBytes { len: 32 }),
                RuntimeFieldRoleArtifact::Template { .. } => continue,
            };
            let id = route_template_table_receipt_id(&runtime_state.source, &field.name);
            let byte_len = leaves.len() * 32;
            let entries = leaves
                .iter()
                .enumerate()
                .map(|(index, leaf)| RouteTemplateTableEntryArtifact {
                    index,
                    offset: index * 32,
                    leaf: route_table_leaf_for_runtime_leaf(leaf),
                })
                .collect::<Vec<_>>();
            let table = RouteTemplateTableArtifact {
                id: id.clone(),
                state: runtime_state.source.clone(),
                field: field.name.clone(),
                byte_len,
                entries,
            };
            if sil_field.ty != expected_field_ty {
                return Err(ArgentError::new(format!("runtime route template table `{id}` field type does not match generated role")));
            }
            if let Some(existing) = tables.get(&id) {
                if existing != &table {
                    return Err(ArgentError::new(format!("runtime route template table `{id}` is emitted with conflicting layouts")));
                }
                continue;
            }
            tables.insert(id, table);
        }
    }
    Ok(tables.into_values().collect())
}

fn route_template_proofs_artifact(
    route_tables: &[RouteTemplateTableArtifact],
    templates: &(impl TemplateHashLookup + ?Sized),
) -> Result<Vec<RouteTemplateProofArtifact>> {
    let mut pending = route_tables.iter().collect::<Vec<_>>();
    let mut digest_roots = BTreeMap::<String, String>::new();
    let mut proofs = Vec::new();
    while !pending.is_empty() {
        let before = pending.len();
        let mut next_pending = Vec::new();
        for table in pending {
            let ready = table.entries.iter().all(|entry| match &entry.leaf {
                RouteTemplateLeafArtifact::Template { .. } => true,
                RouteTemplateLeafArtifact::RouteFamily { proof_id, .. } => digest_roots.contains_key(proof_id),
            });
            if !ready {
                next_pending.push(table);
                continue;
            }
            let proof =
                route_template_proof_from_table(table, templates, &digest_roots).map_err(|err| ArgentError::new(err.to_string()))?;
            digest_roots.insert(proof.id.clone(), proof.root_hex.clone());
            proofs.push(proof);
        }
        if next_pending.len() == before {
            return Err(ArgentError::new("route template tables contain an unresolved family digest dependency"));
        }
        pending = next_pending;
    }
    Ok(proofs)
}

fn actor_artifact(actor: &ActorDecl, model: &Model<'_>) -> Result<ActorArtifact> {
    let entries = actor.entries.iter().map(|entry| entry_artifact(actor, entry, model)).collect::<Result<Vec<_>>>()?;
    let leader_for = model.leader_for(&actor.name).to_vec();

    Ok(ActorArtifact {
        name: actor.name.clone(),
        state: actor.state.clone(),
        abi: ActorAbiRefArtifact { contract: actor.name.clone() },
        leader_for,
        entries,
    })
}

fn sil_abi_artifact(model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<SilAbiArtifact> {
    let mut combined = SilAbiArtifact {
        schema_version: SIL_ABI_SCHEMA_VERSION,
        compiler_version: COMPILER_VERSION.to_string(),
        structs: BTreeMap::new(),
        contracts: BTreeMap::new(),
    };

    for actor in &model.actors {
        let sil = actor_sil
            .get(&actor.name)
            .ok_or_else(|| ArgentError::new(format!("missing generated Silverscript for actor `{}`", actor.name)))?;
        let args = constructor_args_for_actor(actor, model)?;
        let compiled = compile_contract(sil, &args, CompileOptions::default())
            .map_err(|err| ArgentError::new(format!("generated Silverscript for actor `{}` failed to compile: {err}", actor.name)))?;
        let mut artifact = sil_abi_artifact_from_compiled(&compiled, &args)
            .map_err(|err| ArgentError::new(format!("cannot build Sil ABI for actor `{}`: {err}", actor.name)))?;
        if artifact.contract(&actor.name).is_none() {
            return Err(ArgentError::new(format!("generated Sil ABI has no contract for actor `{}`", actor.name)));
        }
        canonicalize_sil_abi_struct_state_refs(actor, model, &mut artifact)?;
        combined = merge_sil_abi_artifacts(combined, artifact)?;
    }

    Ok(combined)
}

/// Remove contract-local `State` references from globally stored Sil structs.
///
/// Argent emits such a reference only when the actor's authored state and
/// physical `State` layouts are identical. Preserve that layout under its
/// stable Argent name before artifacts from several contracts are merged.
fn canonicalize_sil_abi_struct_state_refs(actor: &ActorDecl, model: &Model<'_>, artifact: &mut SilAbiArtifact) -> Result<()> {
    if !artifact.structs.values().any(struct_references_state) {
        return Ok(());
    }

    let source = SourceStateId::new(&actor.state);
    let representation = model
        .state_lowering(&actor.name)?
        .source_representation(&source)
        .ok_or_else(|| ArgentError::new(format!("actor `{}` has no authored state representation", actor.name)))?;
    if representation.sil_type() != &SilStateType::State {
        return Err(ArgentError::new(format!(
            "generated Sil ABI for actor `{}` contains a global struct that references physical `State`, but `{}` is not equivalent to `State`",
            actor.name, actor.state
        )));
    }

    let contract = artifact
        .contract(&actor.name)
        .ok_or_else(|| ArgentError::new(format!("generated Sil ABI has no contract for actor `{}`", actor.name)))?;
    let authored_state = StructArtifact {
        fields: contract
            .runtime_state
            .fields
            .iter()
            .map(|field| FieldArtifact { name: field.name.clone(), ty: field.ty.clone() })
            .collect(),
    };

    if let Some(existing) = artifact.structs.get(&actor.state)
        && existing != &authored_state
    {
        return Err(ArgentError::new(format!(
            "cannot canonicalize Sil `State` as authored state `{}` for actor `{}`: their fields differ",
            actor.state, actor.name
        )));
    }
    artifact.structs.insert(actor.state.clone(), authored_state);

    for structure in artifact.structs.values_mut() {
        for field in &mut structure.fields {
            replace_state_type_ref(&mut field.ty, &actor.state);
        }
    }
    Ok(())
}

fn struct_references_state(structure: &StructArtifact) -> bool {
    structure.fields.iter().any(|field| type_references_state(&field.ty))
}

fn type_references_state(ty: &TypeArtifact) -> bool {
    match ty {
        TypeArtifact::Struct { name } => name == "State",
        TypeArtifact::FixedArray { item, .. } | TypeArtifact::DynamicArray { item } => type_references_state(item),
        TypeArtifact::Int
        | TypeArtifact::Temporal
        | TypeArtifact::Bool
        | TypeArtifact::Byte
        | TypeArtifact::Bytes
        | TypeArtifact::Text
        | TypeArtifact::Pubkey
        | TypeArtifact::Sig
        | TypeArtifact::Datasig
        | TypeArtifact::FixedBytes { .. } => false,
    }
}

fn replace_state_type_ref(ty: &mut TypeArtifact, authored_state: &str) {
    match ty {
        TypeArtifact::Struct { name } if name == "State" => *name = authored_state.to_string(),
        TypeArtifact::FixedArray { item, .. } | TypeArtifact::DynamicArray { item } => {
            replace_state_type_ref(item, authored_state);
        }
        TypeArtifact::Int
        | TypeArtifact::Temporal
        | TypeArtifact::Bool
        | TypeArtifact::Byte
        | TypeArtifact::Bytes
        | TypeArtifact::Text
        | TypeArtifact::Pubkey
        | TypeArtifact::Sig
        | TypeArtifact::Datasig
        | TypeArtifact::FixedBytes { .. }
        | TypeArtifact::Struct { .. } => {}
    }
}

/// Merge two complete Sil ABI artifacts without changing their contracts or
/// struct definitions.
fn merge_sil_abi_artifacts(mut left: SilAbiArtifact, right: SilAbiArtifact) -> Result<SilAbiArtifact> {
    if left.schema_version != right.schema_version {
        return Err(ArgentError::new(format!(
            "cannot merge Sil ABI schema versions {} and {}",
            left.schema_version, right.schema_version
        )));
    }
    if left.compiler_version != right.compiler_version {
        return Err(ArgentError::new(format!(
            "cannot merge Sil ABI compiler versions `{}` and `{}`",
            left.compiler_version, right.compiler_version
        )));
    }

    for (name, structure) in right.structs {
        if let Some(existing) = left.structs.get(&name) {
            if existing != &structure {
                return Err(ArgentError::new(format!("cannot merge conflicting Sil struct `{name}`")));
            }
        } else {
            left.structs.insert(name, structure);
        }
    }
    for (name, contract) in right.contracts {
        if left.contracts.insert(name.clone(), contract).is_some() {
            return Err(ArgentError::new(format!("cannot merge duplicate Sil contract `{name}`")));
        }
    }

    Ok(left)
}

fn constructor_args_for_actor<'i>(actor: &ActorDecl, model: &Model<'_>) -> Result<Vec<SilExpr<'i>>> {
    let state = model.storage_state(&actor.state)?;
    let lowering = model.state_lowering(&actor.name)?;
    let generated_fields = lowering
        .active()
        .physical()
        .fields()
        .iter()
        .filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_)))
        .collect::<Vec<_>>();
    let mut args = Vec::with_capacity(generated_fields.len() + state.fields.len());

    // These placeholders are valid because Argent-generated constructor
    // arguments are state initializers: hidden template commitments and source
    // state fields. If a constructor argument affects code shape outside the
    // compiled state span, the template hash changes and the contract must be
    // recompiled for that value.
    for field in generated_fields {
        args.push(placeholder_expr_for_type(field.ty()).map_err(|err| {
            ArgentError::new(format!(
                "cannot build placeholder constructor argument for actor `{}` generated field `{}`: {err}",
                actor.name,
                field.sil_name()
            ))
        })?);
    }
    for field in &state.fields {
        args.push(placeholder_expr_for_type(&field.ty).map_err(|err| {
            ArgentError::new(format!(
                "cannot build placeholder constructor argument for actor `{}` field `{}`: {err}",
                actor.name, field.name
            ))
        })?);
    }

    Ok(args)
}

fn placeholder_expr_for_type<'i>(ty: &TypeRef) -> Result<SilExpr<'i>> {
    if ty.is_actor_type() {
        return Ok(zero_byte_array_expr(32));
    }
    match (&ty.name[..], ty.array) {
        ("byte", Some(ArrayDim::Fixed(len))) => Ok(zero_byte_array_expr(len)),
        (_, Some(ArrayDim::Fixed(len))) => {
            let item = TypeRef::new(ty.name.clone());
            let values = (0..len).map(|_| placeholder_expr_for_type(&item)).collect::<Result<Vec<_>>>()?;
            SilExpr::try_from(values).map_err(|err| ArgentError::new(err.to_string()))
        }
        (_, Some(ArrayDim::Dynamic)) => Err(ArgentError::new("dynamic arrays are not supported in actor state")),
        ("int", None) => Ok(SilExpr::int(0)),
        ("temporal", None) => Ok(SilExpr::temporal(0)),
        ("bool", None) => Ok(SilExpr::bool(false)),
        ("byte", None) => Ok(SilExpr::byte(0)),
        ("string", None) => Ok(SilExpr::string("")),
        ("pubkey", None) => Ok(zero_byte_array_expr(32)),
        (word::COVENANT_ID, None) => Ok(zero_byte_array_expr(32)),
        ("sig", None) => Ok(zero_byte_array_expr(65)),
        ("datasig", None) => Ok(zero_byte_array_expr(64)),
        (name, None) => Err(ArgentError::new(format!("unsupported constructor placeholder type `{name}`"))),
    }
}

fn zero_byte_array_expr<'i>(len: usize) -> SilExpr<'i> {
    SilExpr::bytes(vec![0; len])
}

fn extract_sil_template(compiled: &CompiledContractArtifact) -> Result<ActorTemplateArtifact> {
    let (prefix, _, suffix) =
        compiled.script_parts(&compiled.bytecode).ok_or_else(|| ArgentError::new("compiled state span is outside its script"))?;
    Ok(ActorTemplateArtifact { prefix: prefix.to_vec(), suffix: suffix.to_vec(), hash: compiled.template_hash })
}

fn runtime_state_field_defs_for_actor(
    actor: &ActorDecl,
    model: &Model<'_>,
) -> Result<Vec<(String, TypeArtifact, Option<RuntimeFieldRoleArtifact>)>> {
    model
        .state_lowering(&actor.name)?
        .active()
        .physical()
        .fields()
        .iter()
        .map(|field| {
            let role = match field.id() {
                PhysicalFieldId::Storage(_) => None,
                PhysicalFieldId::Generated(GeneratedFieldId::Template(actor)) => {
                    Some(RuntimeFieldRoleArtifact::Template { contract: actor.actor().to_string() })
                }
                PhysicalFieldId::Generated(GeneratedFieldId::RouteFamilyDigest { family, .. }) => {
                    Some(RuntimeFieldRoleArtifact::TemplateDigest { id: family.clone() })
                }
                PhysicalFieldId::Generated(GeneratedFieldId::RouteFamilyTable { actors, .. }) => {
                    Some(RuntimeFieldRoleArtifact::TemplateTable {
                        contracts: actors.iter().map(|actor| actor.actor().to_string()).collect(),
                    })
                }
            };
            Ok((field.sil_name().to_string(), type_artifact(field.ty(), model), role))
        })
        .collect()
}

fn runtime_state_fields_for_actor(actor: &ActorDecl, model: &Model<'_>) -> Result<Vec<RuntimeFieldArtifact>> {
    Ok(runtime_state_field_defs_for_actor(actor, model)?
        .into_iter()
        .map(|(name, ty, _role)| RuntimeFieldArtifact { name, ty })
        .collect())
}

fn runtime_state_plan_artifact(actor: &ActorDecl, model: &Model<'_>) -> Result<Option<RuntimeStatePlanArtifact>> {
    let field_roles = runtime_state_field_defs_for_actor(actor, model)?
        .into_iter()
        .filter_map(|(name, _ty, role)| role.map(|role| RuntimeFieldRolePlanArtifact { name, role }))
        .collect::<Vec<_>>();
    if field_roles.is_empty() {
        return Ok(None);
    }
    Ok(Some(RuntimeStatePlanArtifact { contract: actor.name.clone(), source: actor.state.clone(), field_roles }))
}

fn hidden_params_for_entry(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Vec<HiddenParamArtifact> {
    let witness_specs = entry_witness_specs(actor, entry, model).expect("entry clause references validated before artifact emission");
    let mut hidden_params = Vec::new();
    for spec in &witness_specs.templates {
        let subject = HiddenParamSubjectArtifact::Actor { actor: spec.actor.clone() };
        match spec.form {
            TemplateWitnessForm::Bytes => {
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplatePrefixBytes),
                    name: hidden_witness_prefix_name(&spec.actor),
                    ty: TypeArtifact::Bytes,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplatePrefixBytes,
                    route_proof_id: None,
                });
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplateSuffixBytes),
                    name: hidden_witness_suffix_name(&spec.actor),
                    ty: TypeArtifact::Bytes,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplateSuffixBytes,
                    route_proof_id: None,
                });
            }
            TemplateWitnessForm::Len => {
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplatePrefixLen),
                    name: hidden_witness_prefix_len_name(&spec.actor),
                    ty: TypeArtifact::Int,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplatePrefixLen,
                    route_proof_id: None,
                });
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplateSuffixLen),
                    name: hidden_witness_suffix_len_name(&spec.actor),
                    ty: TypeArtifact::Int,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplateSuffixLen,
                    route_proof_id: None,
                });
            }
        }
    }
    for spec in &witness_specs.families {
        let subject = HiddenParamSubjectArtifact::RouteFamily { family_id: spec.family_id.clone() };
        hidden_params.push(HiddenParamArtifact {
            recipe_id: route_family_witness_recipe_id(&spec.family_id, HiddenParamPurposeArtifact::RouteFamilyTable),
            name: hidden_route_family_table_name_by_id(&spec.family_id),
            ty: TypeArtifact::FixedBytes { len: spec.byte_len },
            subject,
            purpose: HiddenParamPurposeArtifact::RouteFamilyTable,
            route_proof_id: None,
        });
    }
    for spec in &witness_specs.selectors {
        let subject = HiddenParamSubjectArtifact::TemplateSelector { selector: spec.name.clone() };
        hidden_params.push(HiddenParamArtifact {
            recipe_id: template_selector_witness_recipe_id(&spec.name, HiddenParamPurposeArtifact::TemplatePrefixBytes),
            name: hidden_template_selector_prefix_name(&spec.name),
            ty: TypeArtifact::Bytes,
            subject: subject.clone(),
            purpose: HiddenParamPurposeArtifact::TemplatePrefixBytes,
            route_proof_id: None,
        });
        hidden_params.push(HiddenParamArtifact {
            recipe_id: template_selector_witness_recipe_id(&spec.name, HiddenParamPurposeArtifact::TemplateSuffixBytes),
            name: hidden_template_selector_suffix_name(&spec.name),
            ty: TypeArtifact::Bytes,
            subject,
            purpose: HiddenParamPurposeArtifact::TemplateSuffixBytes,
            route_proof_id: None,
        });
    }
    for spec in &witness_specs.observed_actors {
        let subject = HiddenParamSubjectArtifact::ObservedActor {
            observe: spec.observe.clone(),
            side: spec.side,
            handle: spec.handle.clone(),
            actor: spec.actor.clone(),
        };
        match spec.side {
            ObservedActorSideArtifact::Input => {
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: observed_actor_witness_recipe_id(spec, HiddenParamPurposeArtifact::TemplatePrefixLen),
                    name: hidden_observed_actor_prefix_len_name(spec),
                    ty: TypeArtifact::Int,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplatePrefixLen,
                    route_proof_id: None,
                });
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: observed_actor_witness_recipe_id(spec, HiddenParamPurposeArtifact::TemplateSuffixLen),
                    name: hidden_observed_actor_suffix_len_name(spec),
                    ty: TypeArtifact::Int,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplateSuffixLen,
                    route_proof_id: None,
                });
                if observed_spec_is_dynamic_binding(entry, spec) {
                    hidden_params.push(HiddenParamArtifact {
                        recipe_id: observed_actor_witness_recipe_id(spec, HiddenParamPurposeArtifact::TemplateHash),
                        name: hidden_observed_actor_template_name(spec),
                        ty: TypeArtifact::FixedBytes { len: 32 },
                        subject,
                        purpose: HiddenParamPurposeArtifact::TemplateHash,
                        route_proof_id: None,
                    });
                }
            }
            ObservedActorSideArtifact::Output => {
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: observed_actor_witness_recipe_id(spec, HiddenParamPurposeArtifact::TemplatePrefixBytes),
                    name: hidden_observed_actor_prefix_name(spec),
                    ty: TypeArtifact::Bytes,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplatePrefixBytes,
                    route_proof_id: None,
                });
                hidden_params.push(HiddenParamArtifact {
                    recipe_id: observed_actor_witness_recipe_id(spec, HiddenParamPurposeArtifact::TemplateSuffixBytes),
                    name: hidden_observed_actor_suffix_name(spec),
                    ty: TypeArtifact::Bytes,
                    subject: subject.clone(),
                    purpose: HiddenParamPurposeArtifact::TemplateSuffixBytes,
                    route_proof_id: None,
                });
            }
        }
    }
    for spec in &witness_specs.spawn_outputs {
        let subject = HiddenParamSubjectArtifact::SpawnActor {
            spawn: spec.spawn.clone(),
            handle: spec.handle.clone(),
            actor: spec.actor.clone(),
        };
        hidden_params.push(HiddenParamArtifact {
            recipe_id: spawn_actor_witness_recipe_id(actor, entry, spec, HiddenParamPurposeArtifact::SpawnOutputIndex),
            name: hidden_spawn_output_idx_name(&spec.spawn, &spec.handle),
            ty: TypeArtifact::Int,
            subject: subject.clone(),
            purpose: HiddenParamPurposeArtifact::SpawnOutputIndex,
            route_proof_id: None,
        });
    }
    for spec in &witness_specs.actor_type_source_templates {
        let subject = actor_type_source_witness_subject(&spec.provider);
        let (prefix_purpose, suffix_purpose, prefix_name, suffix_name, prefix_ty, suffix_ty) = match spec.form {
            TemplateWitnessForm::Bytes => (
                HiddenParamPurposeArtifact::TemplatePrefixBytes,
                HiddenParamPurposeArtifact::TemplateSuffixBytes,
                hidden_actor_type_source_prefix_name(&spec.source),
                hidden_actor_type_source_suffix_name(&spec.source),
                TypeArtifact::Bytes,
                TypeArtifact::Bytes,
            ),
            TemplateWitnessForm::Len => (
                HiddenParamPurposeArtifact::TemplatePrefixLen,
                HiddenParamPurposeArtifact::TemplateSuffixLen,
                hidden_actor_type_source_prefix_len_name(&spec.source),
                hidden_actor_type_source_suffix_len_name(&spec.source),
                TypeArtifact::Int,
                TypeArtifact::Int,
            ),
        };
        hidden_params.push(HiddenParamArtifact {
            recipe_id: actor_type_source_witness_recipe_id(actor, entry, &spec.source, prefix_purpose),
            name: prefix_name,
            ty: prefix_ty,
            subject: subject.clone(),
            purpose: prefix_purpose,
            route_proof_id: None,
        });
        hidden_params.push(HiddenParamArtifact {
            recipe_id: actor_type_source_witness_recipe_id(actor, entry, &spec.source, suffix_purpose),
            name: suffix_name,
            ty: suffix_ty,
            subject,
            purpose: suffix_purpose,
            route_proof_id: None,
        });
    }
    for spec in &witness_specs.state_expansions {
        let len = state_packed_len(&spec.memory_state, model)
            .expect("state expansion memory fields were validated before artifact emission");
        hidden_params.push(HiddenParamArtifact {
            recipe_id: state_expansion_witness_recipe_id(spec),
            name: hidden_state_expansion_preimage_name(spec),
            ty: TypeArtifact::FixedBytes { len },
            subject: HiddenParamSubjectArtifact::StateExpansion {
                state: spec.state.clone(),
                field: spec.field.clone(),
                memory_state: spec.memory_state.clone(),
            },
            purpose: HiddenParamPurposeArtifact::StateExpansionPreimage,
            route_proof_id: None,
        });
    }
    for spec in &witness_specs.observed_output_fields {
        hidden_params.push(HiddenParamArtifact {
            recipe_id: observed_output_field_witness_recipe_id(spec),
            name: hidden_observed_output_field_name(spec),
            ty: TypeArtifact::FixedBytes { len: 32 },
            subject: HiddenParamSubjectArtifact::ObservedOutputField {
                observe: spec.observe.clone(),
                handle: spec.handle.clone(),
                state: spec.state.clone(),
                field: spec.field.clone(),
            },
            purpose: HiddenParamPurposeArtifact::ObservedOutputFieldValue,
            route_proof_id: None,
        });
    }
    hidden_params
}

fn entry_artifact(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<EntryArtifact> {
    let hidden_params = hidden_params_for_entry(actor, entry, model);
    let entry_model = model.entry_model(actor, entry)?;
    let expanded_routes = entry_model.expanded_routes();
    let witnesses = hidden_params
        .iter()
        .map(|param| WitnessArtifact {
            recipe_id: param.recipe_id.clone(),
            param: param.name.clone(),
            subject: param.subject.clone(),
            purpose: param.purpose,
            route_proof_id: param.route_proof_id.clone(),
        })
        .collect::<Vec<_>>();
    Ok(EntryArtifact {
        name: entry.name.clone(),
        kind: match entry.kind {
            EntryKind::Leader => EntryKindArtifact::Leader,
            EntryKind::Delegate => EntryKindArtifact::Delegate,
        },
        abi: EntryAbiRefArtifact { contract: actor.name.clone(), entry: entry.name.clone() },
        route_plan: entry_route_plan_artifact(actor, entry_model, &witnesses)?,
        hidden_params,
        template_selectors: model
            .template_selectors_for_entry(actor, entry)?
            .into_values()
            .map(|selector| TemplateSelectorArtifact {
                name: selector.name,
                actor_enum: selector.actor_enum,
                state: selector.state,
                variants: selector.variants,
                fixed_actor: selector.fixed_actor,
            })
            .collect(),
        observes: entry_model
            .existing_groups()
            .map(|group| observe_artifact(actor, entry, model, group))
            .collect::<Result<Vec<_>>>()?,
        spawns: entry_model.genesis_groups().map(|group| spawn_artifact(actor, entry, model, group)).collect::<Result<Vec<_>>>()?,
        witnesses,
        consumes: entry_model
            .current()
            .inputs()
            .iter()
            .map(|interaction| {
                let InteractionSource::Consume(consume) = interaction.source() else {
                    unreachable!("current covenant inputs are consumes");
                };
                ConsumeArtifact {
                    name: interaction.handle().to_string(),
                    actor: consume.actor.clone(),
                    cardinality: cardinality_artifact(interaction),
                }
            })
            .collect(),
        emits: emit_spec_artifact(entry_model),
        routes: expanded_routes.iter().map(route_artifact).collect(),
    })
}

fn spawn_artifact(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>, group: &CovenantGroup<'_>) -> Result<SpawnArtifact> {
    let spawn = group.spawn().expect("spawn artifact is built from a genesis covenant group");
    Ok(SpawnArtifact {
        name: spawn.name.clone(),
        covenant: spawn.covenant.clone(),
        outputs: group
            .outputs()
            .iter()
            .map(|interaction| {
                let InteractionSource::SpawnOutput(output) = interaction.source() else {
                    unreachable!("genesis covenant outputs are spawn outputs");
                };
                let state = spawn_target_state(interaction.target(), &output.actor, actor, entry, model)?.ok_or_else(|| {
                    ArgentError::new(format!(
                        "spawn `{}.{}` target `{}` is not an actor_type value or a selected-app or linked actor",
                        spawn.name, output.name, output.actor
                    ))
                })?;
                let target = match model.resolve_static_actor_target(interaction.target()) {
                    Some(StaticActorTarget::CrossApp(linked)) => {
                        Some(ActorTargetArtifact::StaticActor { app: linked.app.clone(), actor: linked.actor.clone() })
                    }
                    Some(StaticActorTarget::InApp(_)) | None => None,
                };
                Ok(SpawnOutputArtifact {
                    name: output.name.clone(),
                    actor: compact_expr(&output.actor),
                    state,
                    group_index: output.group_index,
                    cardinality: cardinality_artifact(interaction),
                    target,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn observe_artifact(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>, group: &CovenantGroup<'_>) -> Result<ObserveArtifact> {
    let observe = group.observe().expect("observe artifact is built from an existing covenant group");
    Ok(ObserveArtifact {
        name: observe.name.clone(),
        covenant_expr: compact_expr(&observe.covenant_expr),
        covenant_id_source: observe_covenant_id_source(actor, entry, model, observe)?,
        inputs: group
            .inputs()
            .iter()
            .map(|interaction| {
                let InteractionSource::ObserveInput(observed) = interaction.source() else {
                    unreachable!("existing covenant inputs are observed inputs");
                };
                observed_actor_artifact(actor, entry, model, observe, observed, interaction)
            })
            .collect::<Result<Vec<_>>>()?,
        outputs: group
            .outputs()
            .iter()
            .map(|interaction| {
                let InteractionSource::ObserveOutput(observed) = interaction.source() else {
                    unreachable!("existing covenant outputs are observed outputs");
                };
                observed_actor_artifact(actor, entry, model, observe, observed, interaction)
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn observe_covenant_id_source(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    observe: &ObserveDecl,
) -> Result<CovenantIdSourceArtifact> {
    Ok(match resolve_observe_covenant_id_source(actor, entry, model, observe)? {
        CovenantIdSource::StateField { field } => CovenantIdSourceArtifact::StateField { field },
        CovenantIdSource::EntryArgument { index } => CovenantIdSourceArtifact::EntryArgument { index },
    })
}

fn observed_actor_artifact(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    interaction: &EntryInteraction<'_>,
) -> Result<ObservedActorArtifact> {
    let target = if let Some(state) = observed_open_state_for_decl(actor, entry, observe, observed, model)? {
        ObservedTargetArtifact::DynamicActor { state }
    } else if let Some(linked) = model.linked_actor(&observed.actor) {
        ObservedTargetArtifact::StaticActor { app: linked.app.clone(), actor: linked.actor.clone() }
    } else {
        ObservedTargetArtifact::StaticActor { app: model.app_name.clone(), actor: observed.actor.clone() }
    };
    Ok(ObservedActorArtifact { name: observed.name.clone(), target, cardinality: cardinality_artifact(interaction) })
}

fn entry_route_plan_artifact(
    actor: &ActorDecl,
    entry_model: &EntryModel<'_>,
    witnesses: &[WitnessArtifact],
) -> Result<EntryRoutePlanArtifact> {
    let entry = entry_model.source();
    let active_input = RouteInputArtifact {
        name: "self".to_string(),
        actor: actor.name.clone(),
        cov_index: matches!(entry.kind, EntryKind::Leader).then_some(0),
    };
    let consumes = entry_model
        .current()
        .inputs()
        .iter()
        .map(|interaction| {
            let InteractionSource::Consume(consume) = interaction.source() else {
                unreachable!("current entry inputs are consumes");
            };
            RouteInputArtifact {
                name: consume.name.clone(),
                actor: consume.actor.clone(),
                cov_index: fixed_interaction_index(interaction.location(), usize::from(entry.kind == EntryKind::Leader)),
            }
        })
        .collect::<Vec<_>>();
    let leader_input = match entry.kind {
        EntryKind::Leader => Some(active_input.clone()),
        EntryKind::Delegate => consumes.first().cloned(),
    };
    let outputs = route_output_handles(entry_model);
    Ok(EntryRoutePlanArtifact {
        active_input: Some(active_input),
        leader_input,
        consumes,
        outputs,
        witness_recipe_ids: witnesses.iter().map(|witness| witness.recipe_id.clone()).collect(),
    })
}

fn fixed_interaction_index(location: InteractionLocation, section_offset: usize) -> Option<usize> {
    match location {
        InteractionLocation::FromStart(index) => Some(section_offset + index),
        InteractionLocation::Range { .. } | InteractionLocation::FromEnd(_) => None,
    }
}

fn route_output_handles(entry: &EntryModel<'_>) -> Vec<RouteOutputHandleArtifact> {
    entry
        .current()
        .outputs()
        .iter()
        .map(|output| RouteOutputHandleArtifact {
            name: output.handle().to_string(),
            auth_index: fixed_interaction_index(output.location(), 0),
            actors: output.target().actors().map(str::to_string).collect(),
        })
        .collect()
}

fn emit_spec_artifact(entry: &EntryModel<'_>) -> EmitArtifact {
    match &entry.source().emits {
        EmitSpec::None => EmitArtifact::None,
        EmitSpec::Outputs(_) => EmitArtifact::Outputs {
            outputs: entry
                .current()
                .outputs()
                .iter()
                .map(|interaction| {
                    let InteractionSource::CurrentOutput(output) = interaction.source() else {
                        unreachable!("named emits output retains its source");
                    };
                    debug_assert_eq!(interaction.handle(), output.name);
                    EmitOutputArtifact {
                        name: interaction.handle().to_string(),
                        auth_index: fixed_interaction_index(interaction.location(), 0),
                        actors: interaction.target().actors().map(str::to_string).collect(),
                        cardinality: cardinality_artifact(interaction),
                    }
                })
                .collect(),
        },
    }
}

fn cardinality_artifact(interaction: &EntryInteraction<'_>) -> CardinalityArtifact {
    interaction
        .cardinality()
        .range_bounds()
        .map_or(CardinalityArtifact::One, |(minimum, maximum)| CardinalityArtifact::Range { minimum, maximum })
}

fn route_artifact(route: &ResolvedRoute) -> RouteArtifact {
    let successor = match &route.successor {
        ResolvedSuccessor::ExactSelf => RouteSuccessorArtifact::ExactSelf,
        ResolvedSuccessor::Constructed { actor, state, .. } => RouteSuccessorArtifact::Constructed {
            actor: actor.clone(),
            template_id: template_receipt_id(actor),
            state_expr: compact_expr(state),
        },
    };
    RouteArtifact { output: route.output.clone(), successor }
}

pub(super) fn lower_type_ref(ty: &TypeRef, model: &Model<'_>) -> String {
    if model.is_actor_enum_type(ty) {
        "int".to_string()
    } else if ty.name == word::COVENANT_ID && ty.array.is_none() {
        "byte[32]".to_string()
    } else {
        ty.to_sil()
    }
}

pub(super) fn source_type_ref(ty: &TypeRef) -> String {
    if let Some(state) = &ty.actor_state { format!("{}<{state}>", word::ACTOR_TYPE) } else { ty.to_sil() }
}

fn type_artifact(ty: &TypeRef, model: &Model<'_>) -> TypeArtifact {
    if ty.is_actor_type() {
        TypeArtifact::FixedBytes { len: 32 }
    } else if ty.name == word::COVENANT_ID {
        match ty.array {
            Some(ArrayDim::Fixed(len)) => TypeArtifact::FixedArray { item: Box::new(TypeArtifact::FixedBytes { len: 32 }), len },
            Some(ArrayDim::Dynamic) => TypeArtifact::dynamic_array(TypeArtifact::FixedBytes { len: 32 }),
            None => TypeArtifact::FixedBytes { len: 32 },
        }
    } else if model.is_actor_enum_type(ty) {
        TypeArtifact::Int
    } else {
        match ty.array {
            Some(ArrayDim::Dynamic) if ty.name == "byte" => TypeArtifact::Bytes,
            Some(ArrayDim::Dynamic) => TypeArtifact::dynamic_array(TypeArtifact::from_parts(&ty.name, None)),
            Some(ArrayDim::Fixed(len)) => TypeArtifact::from_parts(&ty.name, Some(len)),
            None => TypeArtifact::from_parts(&ty.name, None),
        }
    }
}

pub(super) fn lower_actor_enum_literals(expr: &str, model: &Model<'_>) -> Result<String> {
    if !expr.contains("::") {
        return Ok(expr.to_string());
    }
    let tokens =
        lex(expr).map_err(|err| ArgentError::new(format!("failed to lex actor enum expression `{expr}`: {}", err.message)))?;
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut pos = 0usize;
    while pos + 3 < tokens.len() {
        let actor_enum = match &tokens[pos].kind {
            TokenKind::Ident(actor_enum) => actor_enum,
            TokenKind::Eof => break,
            _ => {
                pos += 1;
                continue;
            }
        };
        let is_qualified_variant = matches!(tokens[pos + 1].kind, TokenKind::Symbol(':'))
            && matches!(tokens[pos + 2].kind, TokenKind::Symbol(':'))
            && matches!(tokens[pos + 3].kind, TokenKind::Ident(_));
        if !is_qualified_variant {
            pos += 1;
            continue;
        }
        let Some(actor_enum_info) = model.actor_enums.get(actor_enum) else {
            pos += 1;
            continue;
        };
        let variant = match &tokens[pos + 3].kind {
            TokenKind::Ident(variant) => variant,
            _ => unreachable!("checked qualified variant"),
        };
        let value = actor_enum_variant_const_expr(actor_enum_info, variant)
            .ok_or_else(|| ArgentError::new(format!("actor enum `{actor_enum}` has no variant `{variant}` in expression `{expr}`")))?;
        out.push_str(&expr[cursor..tokens[pos].span.start]);
        out.push_str(&value);
        cursor = tokens[pos + 3].span.end;
        pos += 4;
    }
    out.push_str(&expr[cursor..]);
    Ok(out)
}

fn emit_emit_spec_json(out: &mut String, entry: &EntryModel<'_>) {
    match &entry.source().emits {
        EmitSpec::None => out.push_str("{ \"kind\": \"none\" }"),
        EmitSpec::Outputs(_) => {
            out.push_str("{ \"kind\": \"outputs\", \"outputs\": [");
            for (output_idx, interaction) in entry.current().outputs().iter().enumerate() {
                if output_idx > 0 {
                    out.push_str(", ");
                }
                let InteractionSource::CurrentOutput(output) = interaction.source() else {
                    unreachable!("current entry outputs are emits outputs");
                };
                let auth_index =
                    fixed_interaction_index(interaction.location(), 0).map_or_else(|| "null".to_string(), |index| index.to_string());
                out.push_str(&format!(
                    "{{ \"name\": \"{}\", \"auth_index\": {}, \"actors\": [",
                    json_escape(&output.name),
                    auth_index
                ));
                for (actor_idx, actor) in output.actors.iter().enumerate() {
                    if actor_idx > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("\"{}\"", json_escape(actor)));
                }
                out.push(']');
                emit_manifest_cardinality(out, interaction);
                out.push_str(" }");
            }
            out.push_str("] }");
        }
    }
}

fn emit_manifest_cardinality(out: &mut String, interaction: &EntryInteraction<'_>) {
    if let Some((minimum, maximum)) = interaction.cardinality().range_bounds() {
        out.push_str(&format!(", \"cardinality\": {{ \"kind\": \"range\", \"minimum\": {minimum}, \"maximum\": {maximum} }}"));
    }
}

fn manifest_path(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(relative) = path.strip_prefix(&cwd)
    {
        return display_path(relative);
    }
    display_path(path)
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn to_upper_camel(input: &str) -> String {
    input
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| first.to_ascii_uppercase().to_string() + chars.as_str())
        })
        .collect()
}

fn hidden_actor_suffix(actor: &str) -> String {
    to_snake(&actor.replace(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_', "_"))
}

pub(super) fn hidden_actor_state_type_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_TYPE_PREFIX}{}State", to_upper_camel(actor))
}

pub(super) fn hidden_storage_state_type_name(state: &str) -> String {
    format!("{RESERVED_GENERATED_TYPE_PREFIX}Physical{}", to_upper_camel(state))
}

pub(super) fn hidden_template_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_template", hidden_actor_suffix(actor))
}

fn hidden_template_root_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}template_root")
}

fn route_family_suffix_by_id(family_id: &str) -> String {
    let hub = family_id.strip_prefix("route_family/").and_then(|rest| rest.rsplit('/').next()).unwrap_or(family_id);
    to_snake(hub)
}

fn hidden_route_family_commitment_name_by_id(family_id: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_routes_digest", route_family_suffix_by_id(family_id))
}

pub(super) fn hidden_route_family_table_name(family: &RouteFamily) -> String {
    hidden_route_family_table_name_by_id(&family.id)
}

fn hidden_route_family_table_name_by_id(family_id: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_routes", route_family_suffix_by_id(family_id))
}

fn route_table_leaf_for_runtime_leaf(leaf: &RuntimeRouteLeafArtifact) -> RouteTemplateLeafArtifact {
    match leaf {
        RuntimeRouteLeafArtifact::Contract { contract } => {
            RouteTemplateLeafArtifact::Template { actor: contract.clone(), template_id: template_receipt_id(contract) }
        }
        RuntimeRouteLeafArtifact::Digest { id } => {
            RouteTemplateLeafArtifact::RouteFamily { family_id: id.clone(), proof_id: route_family_proof_id_from_id(id) }
        }
    }
}

fn route_family_proof_id_from_id(family_id: &str) -> String {
    let state = family_id.strip_prefix("route_family/").and_then(|rest| rest.split('/').next()).unwrap_or("");
    route_template_proof_receipt_id(state, &hidden_template_root_name())
}

fn hidden_physical_field_init_name(field: &str) -> String {
    let suffix = field.strip_prefix(RESERVED_GENERATED_PREFIX).expect("generated physical fields use the reserved namespace");
    format!("{RESERVED_GENERATED_PREFIX}init_{suffix}")
}

fn hidden_template_init_args_for_actor(actor: &ActorDecl, model: &Model<'_>) -> Result<Vec<String>> {
    Ok(model
        .state_lowering(&actor.name)?
        .active()
        .physical()
        .fields()
        .iter()
        .filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_)))
        .map(|field| format!("{} {}", field.sil_type(), hidden_physical_field_init_name(field.sil_name())))
        .collect())
}

fn emit_route_template_table(out: &mut String, actor: &ActorDecl, model: &Model<'_>) -> Result<()> {
    for field in model
        .state_lowering(&actor.name)?
        .active()
        .physical()
        .fields()
        .iter()
        .filter(|field| matches!(field.id(), PhysicalFieldId::Generated(_)))
    {
        out.push_str(&format!(
            "    {} {} = {};\n",
            field.sil_type(),
            field.sil_name(),
            hidden_physical_field_init_name(field.sil_name())
        ));
    }
    Ok(())
}

fn template_receipt_id(actor: &str) -> String {
    format!("template/{}", hidden_actor_suffix(actor))
}

fn template_witness_recipe_id(actor: &str, purpose: HiddenParamPurposeArtifact) -> String {
    format!("witness/{}/{}", hidden_actor_suffix(actor), hidden_param_purpose_id(purpose))
}

fn route_family_witness_recipe_id(family_id: &str, purpose: HiddenParamPurposeArtifact) -> String {
    format!("witness/{}/{}", route_family_suffix_by_id(family_id), hidden_param_purpose_id(purpose))
}

fn template_selector_witness_recipe_id(selector: &str, purpose: HiddenParamPurposeArtifact) -> String {
    format!("witness/template_selector/{selector}/{}", hidden_param_purpose_id(purpose))
}

fn observed_actor_witness_recipe_id(spec: &ObservedActorWitnessSpec, purpose: HiddenParamPurposeArtifact) -> String {
    format!(
        "witness/observed/{}/{}/{}/{}",
        spec.observe,
        observed_actor_side_label(spec.side),
        observed_actor_spec_suffix(spec),
        hidden_param_purpose_id(purpose)
    )
}

fn spawn_actor_witness_recipe_id(
    actor: &ActorDecl,
    entry: &EntryDecl,
    spec: &SpawnActorWitnessSpec,
    purpose: HiddenParamPurposeArtifact,
) -> String {
    format!("witness/{}/{}/spawn/{}/{}/{}", actor.name, entry.name, spec.spawn, spec.handle, hidden_param_purpose_id(purpose))
}

fn actor_type_source_witness_recipe_id(
    actor: &ActorDecl,
    entry: &EntryDecl,
    source: &ClauseActorTypeRef,
    purpose: HiddenParamPurposeArtifact,
) -> String {
    format!(
        "witness/{}/{}/actor_type/{}/{}",
        actor.name,
        entry.name,
        clause_actor_type_witness_suffix(source),
        hidden_param_purpose_id(purpose)
    )
}

fn state_expansion_witness_recipe_id(spec: &StateExpansionWitnessSpec) -> String {
    format!(
        "witness/state_expansion/{}/{}/{}/{}",
        spec.state,
        spec.field,
        to_snake(&spec.memory_state),
        hidden_param_purpose_id(HiddenParamPurposeArtifact::StateExpansionPreimage)
    )
}

fn observed_output_field_witness_recipe_id(spec: &ObservedOutputFieldWitnessSpec) -> String {
    format!(
        "witness/observed/{}/output/{}/{}/{}/{}",
        spec.observe,
        spec.handle,
        to_snake(&spec.state),
        spec.field,
        hidden_param_purpose_id(HiddenParamPurposeArtifact::ObservedOutputFieldValue)
    )
}

fn hidden_param_purpose_id(purpose: HiddenParamPurposeArtifact) -> &'static str {
    match purpose {
        HiddenParamPurposeArtifact::SpawnOutputIndex => "spawn_output_index",
        HiddenParamPurposeArtifact::TemplatePrefixBytes => "template_prefix_bytes",
        HiddenParamPurposeArtifact::TemplateSuffixBytes => "template_suffix_bytes",
        HiddenParamPurposeArtifact::TemplatePrefixLen => "template_prefix_len",
        HiddenParamPurposeArtifact::TemplateSuffixLen => "template_suffix_len",
        HiddenParamPurposeArtifact::TemplateHash => "template_hash",
        HiddenParamPurposeArtifact::RouteTemplateLeaf => "route_template_leaf",
        HiddenParamPurposeArtifact::RouteTemplateProof => "route_template_proof",
        HiddenParamPurposeArtifact::RouteFamilyTable => "route_family_table",
        HiddenParamPurposeArtifact::RouteFamilyProof => "route_family_proof",
        HiddenParamPurposeArtifact::StateExpansionPreimage => "state_expansion_preimage",
        HiddenParamPurposeArtifact::ObservedOutputFieldValue => "observed_output_field_value",
    }
}

pub(super) fn hidden_witness_prefix_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_prefix", hidden_actor_suffix(actor))
}

pub(super) fn hidden_witness_suffix_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_suffix", hidden_actor_suffix(actor))
}

pub(super) fn hidden_witness_prefix_len_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_prefix_len", hidden_actor_suffix(actor))
}

pub(super) fn hidden_witness_suffix_len_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_suffix_len", hidden_actor_suffix(actor))
}

pub(super) fn hidden_template_selector_prefix_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_prefix")
}

pub(super) fn hidden_template_selector_suffix_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_suffix")
}

pub(super) fn hidden_template_selector_index_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_selector")
}

pub(super) fn hidden_template_selector_template_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_template")
}

fn observed_actor_spec_suffix(spec: &ObservedActorWitnessSpec) -> String {
    spec.source.as_ref().map_or_else(|| actor_expr_suffix(&spec.actor), clause_actor_type_witness_suffix)
}

fn actor_expr_suffix(actor: &str) -> String {
    if let Some(field) = actor.strip_prefix("self.")
        && is_identifier(field)
    {
        return to_snake(field);
    }
    if is_identifier(actor) {
        return hidden_actor_suffix(actor);
    }
    to_snake(&compact_expr(actor).replace(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_', "_"))
}

pub(super) fn hidden_observed_actor_prefix_name(spec: &ObservedActorWitnessSpec) -> String {
    if let Some(source) = &spec.source {
        return hidden_actor_type_source_prefix_name(source);
    }
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_prefix", spec.observe, observed_actor_spec_suffix(spec))
}

pub(super) fn hidden_observed_actor_suffix_name(spec: &ObservedActorWitnessSpec) -> String {
    if let Some(source) = &spec.source {
        return hidden_actor_type_source_suffix_name(source);
    }
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_suffix", spec.observe, observed_actor_spec_suffix(spec))
}

pub(super) fn hidden_observed_actor_prefix_len_name(spec: &ObservedActorWitnessSpec) -> String {
    if let Some(source) = &spec.source {
        return hidden_actor_type_source_prefix_len_name(source);
    }
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_prefix_len", spec.observe, observed_actor_spec_suffix(spec))
}

pub(super) fn hidden_observed_actor_suffix_len_name(spec: &ObservedActorWitnessSpec) -> String {
    if let Some(source) = &spec.source {
        return hidden_actor_type_source_suffix_len_name(source);
    }
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_suffix_len", spec.observe, observed_actor_spec_suffix(spec))
}

pub(super) fn hidden_observed_actor_template_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_template", spec.observe, observed_actor_spec_suffix(spec))
}

pub(super) fn hidden_imported_template_name(spec: &ImportedTemplateSpec) -> String {
    hidden_template_name(&spec.actor_reference())
}

fn hidden_imported_template_const_name(spec: &ImportedTemplateSpec) -> String {
    format!("{}_const", hidden_imported_template_name(spec))
}

pub(super) fn hidden_spawn_actor_prefix_name(spec: &SpawnActorWitnessSpec) -> String {
    spec.source.as_ref().map_or_else(
        || format!("{RESERVED_GENERATED_PREFIX}spawn_{}_prefix", spawn_actor_spec_suffix(spec)),
        hidden_actor_type_source_prefix_name,
    )
}

pub(super) fn hidden_spawn_actor_suffix_name(spec: &SpawnActorWitnessSpec) -> String {
    spec.source.as_ref().map_or_else(
        || format!("{RESERVED_GENERATED_PREFIX}spawn_{}_suffix", spawn_actor_spec_suffix(spec)),
        hidden_actor_type_source_suffix_name,
    )
}

fn spawn_actor_spec_suffix(spec: &SpawnActorWitnessSpec) -> String {
    spec.source.as_ref().map_or_else(|| actor_expr_suffix(&spec.actor), clause_actor_type_witness_suffix)
}

fn hidden_actor_type_source_prefix_name(source: &ClauseActorTypeRef) -> String {
    format!("{RESERVED_GENERATED_PREFIX}actor_type_{}_prefix", clause_actor_type_witness_suffix(source))
}

fn hidden_actor_type_source_suffix_name(source: &ClauseActorTypeRef) -> String {
    format!("{RESERVED_GENERATED_PREFIX}actor_type_{}_suffix", clause_actor_type_witness_suffix(source))
}

fn hidden_actor_type_source_prefix_len_name(source: &ClauseActorTypeRef) -> String {
    format!("{RESERVED_GENERATED_PREFIX}actor_type_{}_prefix_len", clause_actor_type_witness_suffix(source))
}

fn hidden_actor_type_source_suffix_len_name(source: &ClauseActorTypeRef) -> String {
    format!("{RESERVED_GENERATED_PREFIX}actor_type_{}_suffix_len", clause_actor_type_witness_suffix(source))
}

fn clause_actor_type_witness_suffix(source: &ClauseActorTypeRef) -> String {
    match source {
        ClauseActorTypeRef::StateField { field, .. } => format!("self_{field}"),
        ClauseActorTypeRef::EntryArgument { name, .. } => format!("arg_{name}"),
    }
}

fn hidden_state_expansion_preimage_name(spec: &StateExpansionWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_preimage", to_snake(&spec.field), to_snake(&spec.memory_state))
}

pub(super) fn hidden_state_expansion_field_name(spec: &StateExpansionWitnessSpec, field: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}", to_snake(&spec.field), to_snake(field))
}

pub(super) fn hidden_observed_output_field_name(spec: &ObservedOutputFieldWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_next_{}", spec.observe, spec.handle, to_snake(&spec.field))
}

fn hidden_observe_cov_id_name(observe: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_cov_id")
}

pub(super) fn hidden_observed_input_idx_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_input_idx")
}

pub(super) fn hidden_observed_output_idx_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_output_idx")
}

pub(super) fn hidden_spawn_output_idx_name(spawn: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{spawn}_{handle}_output_idx")
}

fn hidden_spawn_preimage_name(spawn: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{spawn}_genesis_preimage")
}

pub(super) fn hidden_observed_input_state_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_state")
}

pub(super) fn hidden_consumed_input_state_name(handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{handle}_state")
}

pub(super) fn hidden_consumed_input_authored_cache_name(handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{handle}_authored_states")
}

pub(super) fn hidden_consumed_input_field_cache_name(handle: &str, field: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{handle}_{field}_values")
}

fn observed_actor_side_label(side: ObservedActorSideArtifact) -> &'static str {
    match side {
        ObservedActorSideArtifact::Input => "input",
        ObservedActorSideArtifact::Output => "output",
    }
}

pub(super) fn hidden_cov_id_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}cov_id")
}

pub(super) fn hidden_input_idx_name(input: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{input}_input_idx")
}

pub(super) fn hidden_input_count_name(input: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{input}_count")
}

fn hidden_input_position_name(input: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{input}_position")
}

pub(super) fn hidden_output_idx_name(output: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{output}_output_idx")
}

pub(super) fn hidden_output_count_name(output: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{output}_output_count")
}

pub(super) fn hidden_output_position_name(output: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{output}_output_position")
}

pub(super) fn hidden_checked_range_index_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}checked_range_index")
}

fn hidden_range_index_arg_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}range_index")
}

fn hidden_range_count_arg_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}range_count")
}

fn compact_expr(input: &str) -> String {
    let without_comments =
        input.lines().map(|line| line.split_once("//").map(|(code, _)| code).unwrap_or(line)).collect::<Vec<_>>().join(" ");
    let compact = without_comments.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars = compact.chars();
    let prefix = chars.by_ref().take(96).collect::<String>();
    if chars.next().is_some() { format!("{prefix}...") } else { compact }
}

fn indent_block_body(body: &str, spaces: usize) -> String {
    let indent = " ".repeat(spaces);
    // Normalize CRLF to LF first. `body` may originate from a CRLF-checked-out
    // source file (e.g. on Windows with core.autocrlf=true); without this,
    // trim_matches('\n') only strips bare '\n' from the very edges, leaving a
    // stray '\r' attached to the first/last line and producing output that
    // differs byte-for-byte from the same source checked out with LF endings.
    let normalized = body.replace("\r\n", "\n");
    let trimmed = normalized.trim_end().trim_start_matches('\n');
    if trimmed.trim().is_empty() {
        return String::new();
    }

    let common_indent = trimmed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.chars().take_while(|ch| *ch == ' ' || *ch == '\t').count())
        .min()
        .unwrap_or(0);

    let mut out = String::new();
    for line in trimmed.lines() {
        if line.trim().is_empty() {
            out.push('\n');
        } else {
            out.push_str(&indent);
            out.push_str(line.get(common_indent..).unwrap_or_else(|| line.trim_start()));
            out.push('\n');
        }
    }
    out
}

fn json_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t")
}
