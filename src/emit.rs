use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::artifact::*;
use crate::ast::*;
use crate::codec::encode_hex;
use crate::error::{ArgentError, Result};
use crate::language::word;
use crate::lexer::{RESERVED_GENERATED_PREFIX, Token, TokenKind, lex};
use silverscript_lang::ast::Expr as SilExpr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract};

pub fn emit_build(program: &Program, out_dir: impl AsRef<Path>) -> Result<()> {
    emit_build_selected(program, None, out_dir)
}

pub fn emit_build_app(program: &Program, app_name: &str, out_dir: impl AsRef<Path>) -> Result<()> {
    emit_build_selected(program, Some(app_name), out_dir)
}

fn emit_build_selected(program: &Program, app_name: Option<&str>, out_dir: impl AsRef<Path>) -> Result<()> {
    let out_dir = out_dir.as_ref();
    let sil_dir = out_dir.join("sil");

    let model = match app_name {
        Some(app_name) => Model::from_program_app(program, app_name)?,
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

#[derive(Debug)]
struct Model<'a> {
    app_name: String,
    template_actors: Vec<String>,
    route_families: Vec<RouteFamily>,
    consts: Vec<&'a ConstDecl>,
    functions: Vec<&'a FunctionDecl>,
    states: BTreeMap<String, &'a StateDecl>,
    actors_by_name: BTreeMap<String, &'a ActorDecl>,
    actor_enums: BTreeMap<String, ActorEnumInfo>,
    actors: Vec<&'a ActorDecl>,
    /// Delegate entries that establish each actor as a leader actor.
    leader_for: BTreeMap<String, Vec<EntryRefArtifact>>,
    state_route_leaves: BTreeMap<String, Vec<RouteRootLeaf>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActorEnumInfo {
    name: String,
    state: String,
    variants: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TemplateSelector {
    name: String,
    actor_enum: String,
    state: String,
    variants: Vec<String>,
    selector_expr: String,
    fixed_actor: Option<String>,
}

impl TemplateSelector {
    fn route_actors(&self) -> Vec<String> {
        self.fixed_actor.as_ref().map_or_else(|| self.variants.clone(), |actor| vec![actor.clone()])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteFamily {
    id: String,
    state: String,
    actors: Vec<String>,
    entry_actors: Vec<String>,
    direct_template_actors: Vec<String>,
    table_actors: Vec<String>,
}

impl RouteFamily {
    fn anchor_actor(&self) -> &str {
        self.direct_template_actors.first().map(String::as_str).expect("route families contain at least one direct template actor")
    }

    fn direct_template_actors(&self) -> &[String] {
        &self.direct_template_actors
    }

    fn table_actors(&self) -> &[String] {
        &self.table_actors
    }

    fn table_byte_len(&self) -> usize {
        self.table_actors().len() * 32
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RouteRootLeaf {
    Actor(String),
    Family(String),
}

fn compute_leader_for(actors: &[&ActorDecl]) -> BTreeMap<String, Vec<EntryRefArtifact>> {
    let mut leader_for = BTreeMap::<String, Vec<EntryRefArtifact>>::new();
    for actor in actors {
        for entry in &actor.entries {
            if entry.kind != EntryKind::Delegate {
                continue;
            }
            let Some(leader) = entry.consumes.first() else {
                continue;
            };
            leader_for
                .entry(leader.actor.clone())
                .or_default()
                .push(EntryRefArtifact { actor: actor.name.clone(), entry: entry.name.clone() });
        }
    }
    leader_for
}

impl<'a> Model<'a> {
    fn from_program(program: &'a Program) -> Result<Self> {
        Self::from_program_selected(program, None)
    }

    fn from_program_app(program: &'a Program, app_name: &str) -> Result<Self> {
        Self::from_program_selected(program, Some(app_name))
    }

    fn from_program_selected(program: &'a Program, app_name: Option<&str>) -> Result<Self> {
        validate_unique_apps(program)?;
        let consts = collect_consts(program)?;
        let functions = collect_functions(program)?;
        let states = collect_states(program)?;
        let all_actors = collect_actors(program)?;
        let actor_enum_decls = collect_actor_enums(program)?;

        let app = select_root_app(program, app_name)?;
        let (app_name, template_actors) = if let Some(app) = app {
            (app.name.clone(), app.actors.clone())
        } else {
            ("ArgentApp".to_string(), all_actors.keys().cloned().collect())
        };

        let mut actors = Vec::new();
        for name in &template_actors {
            let actor =
                all_actors.get(name).copied().ok_or_else(|| ArgentError::new(format!("app references unknown actor `{name}`")))?;
            if !states.contains_key(&actor.state) {
                return Err(ArgentError::new(format!("actor `{}` owns unknown state `{}`", actor.name, actor.state)));
            }
            actors.push(actor);
        }

        let actor_enums = build_actor_enums(&actor_enum_decls, &all_actors, &states, &template_actors)?;
        let layout_actors = all_actors.values().copied().collect::<Vec<_>>();
        let mut layout_template_actors = template_actors.clone();
        for actor in all_actors.keys() {
            if !layout_template_actors.contains(actor) {
                layout_template_actors.push(actor.clone());
            }
        }
        let state_template_deps = compute_state_template_deps(&layout_actors, &all_actors, &layout_template_actors, &actor_enums)?;
        let direct_state_template_deps =
            compute_direct_state_template_deps(&layout_actors, &all_actors, &layout_template_actors, &actor_enums)?;
        let route_families = infer_direct_route_families(&actors, &all_actors, &template_actors, &actor_enums)?;
        let leader_for = compute_leader_for(&actors);
        let state_route_leaves = compute_state_route_leaves(&state_template_deps, &direct_state_template_deps, &route_families);
        let model = Self {
            app_name,
            template_actors,
            route_families,
            consts,
            functions,
            states,
            actors_by_name: all_actors,
            actor_enums,
            actors,
            leader_for,
            state_route_leaves,
        };
        model.validate()?;
        Ok(model)
    }

    fn state(&self, name: &str) -> Result<&StateDecl> {
        self.states.get(name).copied().ok_or_else(|| ArgentError::new(format!("unknown state `{name}`")))
    }

    fn storage_state_name(&self, name: &str) -> Result<String> {
        let state = self.state(name)?;
        Ok(state.expansion.as_ref().map_or_else(|| name.to_string(), |expansion| expansion.base.clone()))
    }

    fn storage_state(&self, name: &str) -> Result<&StateDecl> {
        self.state(&self.storage_state_name(name)?)
    }

    fn actor(&self, name: &str) -> Result<&ActorDecl> {
        self.actors_by_name.get(name).copied().ok_or_else(|| ArgentError::new(format!("unknown actor `{name}`")))
    }

    fn actor_state(&self, name: &str) -> Result<&StateDecl> {
        let actor = self.actor(name)?;
        self.storage_state(&actor.state)
    }

    fn route_leaves_for_state(&self, state: &str) -> &[RouteRootLeaf] {
        self.state_route_leaves.get(state).map(Vec::as_slice).unwrap_or(&[])
    }

    fn route_family_for_actor(&self, actor: &str) -> Option<&RouteFamily> {
        self.route_families.iter().find(|family| family.actors.iter().any(|member| member == actor))
    }

    fn route_families_for_state(&self, state: &str) -> Vec<&RouteFamily> {
        self.route_families.iter().filter(|family| family.state == state).collect()
    }

    fn leader_for(&self, actor: &str) -> &[EntryRefArtifact] {
        self.leader_for.get(actor).map(Vec::as_slice).unwrap_or(&[])
    }

    fn is_leader_actor(&self, actor: &str) -> bool {
        !self.leader_for(actor).is_empty()
    }

    fn template_selectors_for_entry(&self, actor: &ActorDecl, entry: &EntryDecl) -> Result<BTreeMap<String, TemplateSelector>> {
        template_selectors_for_entry(actor, entry, &self.actor_enums)
    }

    fn is_actor_enum_type(&self, ty: &TypeRef) -> bool {
        ty.array.is_none() && self.actor_enums.contains_key(&ty.name)
    }

    fn expand_actor_refs(&self, refs: &[String]) -> Vec<String> {
        refs.iter()
            .flat_map(|actor| {
                self.actor_enums.get(actor).map_or_else(|| vec![actor.clone()], |actor_enum| actor_enum.variants.clone())
            })
            .collect()
    }

    fn route_targets(&self, actor: &ActorDecl, entry: &EntryDecl, route: &RouteCall) -> Result<Vec<String>> {
        let selectors = self.template_selectors_for_entry(actor, entry)?;
        Ok(selectors.get(&route.actor).map_or_else(|| vec![route.actor.clone()], TemplateSelector::route_actors))
    }

    fn validate(&self) -> Result<()> {
        self.validate_reserved_identifiers()?;
        self.validate_state_expansions()?;
        self.validate_generated_actor_suffixes()?;

        let template_actor_set = self.template_actors.iter().cloned().collect::<BTreeSet<_>>();
        for actor in &self.actors {
            for entry in &actor.entries {
                self.validate_entry(actor, entry, &template_actor_set)?;
            }
        }
        self.validate_observed_template_state_fields()?;
        Ok(())
    }

    fn validate_state_expansions(&self) -> Result<()> {
        for state in self.states.values() {
            for field in &state.fields {
                if field.virtual_slot && (field.ty.name != "byte" || field.ty.array != Some(32) || field.ty.actor_state.is_some()) {
                    return Err(ArgentError::new(format!(
                        "state `{}` field `{}` is virtual, but virtual slots must be byte[32]",
                        state.name, field.name
                    )));
                }
            }
        }

        for state in self.states.values() {
            let Some(expansion) = &state.expansion else {
                continue;
            };
            if !state.fields.is_empty() {
                return Err(ArgentError::new(format!(
                    "state `{}` expands `{}` and cannot declare ordinary fields",
                    state.name, expansion.base
                )));
            }
            if expansion.digests.is_empty() {
                return Err(ArgentError::new(format!(
                    "state `{}` expands `{}` but declares no digest expansions",
                    state.name, expansion.base
                )));
            }
            let base = self
                .state(&expansion.base)
                .map_err(|_| ArgentError::new(format!("state `{}` expands unknown base state `{}`", state.name, expansion.base)))?;
            if base.expansion.is_some() {
                return Err(ArgentError::new(format!(
                    "state `{}` expands `{}`, but expanded states cannot currently be used as bases",
                    state.name, expansion.base
                )));
            }
            let mut seen = BTreeSet::new();
            for digest in &expansion.digests {
                if !seen.insert(digest.field.as_str()) {
                    return Err(ArgentError::new(format!(
                        "state `{}` binds virtual slot `{}` more than once",
                        state.name, digest.field
                    )));
                }
                let field = base.fields.iter().find(|field| field.name == digest.field).ok_or_else(|| {
                    ArgentError::new(format!(
                        "state `{}` expands `{}` field `{}`, but `{}` has no such field",
                        state.name, expansion.base, digest.field, expansion.base
                    ))
                })?;
                if !field.virtual_slot || field.ty.name != "byte" || field.ty.array != Some(32) || field.ty.actor_state.is_some() {
                    return Err(ArgentError::new(format!(
                        "state `{}` binds `{}` slot `{}`, but expanded slots must be virtual",
                        state.name, expansion.base, digest.field
                    )));
                }
                let memory_state = self.state(&digest.state).map_err(|_| {
                    ArgentError::new(format!(
                        "state `{}` expands `{}` field `{}` as unknown memory state `{}`",
                        state.name, expansion.base, digest.field, digest.state
                    ))
                })?;
                if memory_state.fields.is_empty() {
                    return Err(ArgentError::new(format!(
                        "state `{}` expands `{}` field `{}` as `{}`, but memory states must have at least one field",
                        state.name, expansion.base, digest.field, digest.state
                    )));
                }
                for memory_field in &memory_state.fields {
                    packed_field_len(&memory_field.ty).map_err(|err| {
                        ArgentError::new(format!(
                            "state `{}` slot `{}` as `{}` field `{}` cannot be packed: {err}",
                            state.name, digest.field, digest.state, memory_field.name
                        ))
                    })?;
                }
            }
        }
        Ok(())
    }

    fn validate_reserved_identifiers(&self) -> Result<()> {
        reject_reserved_identifier(word::APP, &self.app_name)?;
        for konst in &self.consts {
            reject_reserved_identifier("constant", &konst.name)?;
        }
        for function in &self.functions {
            reject_reserved_identifier("function", &function.name)?;
            for param in &function.params {
                reject_reserved_identifier(&format!("function `{}` parameter", function.name), &param.name)?;
            }
        }
        for state in self.states.values() {
            reject_reserved_identifier(word::STATE, &state.name)?;
            for field in &state.fields {
                reject_reserved_identifier(&format!("state `{}` field", state.name), &field.name)?;
            }
            if let Some(expansion) = &state.expansion {
                for digest in &expansion.digests {
                    reject_reserved_identifier(&format!("state `{}` expanded digest field", state.name), &digest.field)?;
                }
            }
        }
        for actor_enum in self.actor_enums.values() {
            reject_reserved_identifier("actor enum", &actor_enum.name)?;
        }
        for actor in self.actors_by_name.values() {
            reject_reserved_identifier(word::ACTOR, &actor.name)?;
            for entry in &actor.entries {
                reject_reserved_identifier(&format!("entry `{}::{}`", actor.name, entry.name), &entry.name)?;
                for param in &entry.params {
                    reject_reserved_identifier(&format!("entry `{}::{}` parameter", actor.name, entry.name), &param.name)?;
                }
                for consume in &entry.consumes {
                    reject_reserved_identifier(&format!("entry `{}::{}` consume handle", actor.name, entry.name), &consume.name)?;
                }
                for observe in &entry.observes {
                    reject_reserved_identifier(&format!("entry `{}::{}` observe handle", actor.name, entry.name), &observe.name)?;
                    for observed in &observe.inputs {
                        reject_reserved_identifier(
                            &format!("entry `{}::{}` observe `{}` input handle", actor.name, entry.name, observe.name),
                            &observed.name,
                        )?;
                    }
                    for observed in &observe.outputs {
                        reject_reserved_identifier(
                            &format!("entry `{}::{}` observe `{}` output handle", actor.name, entry.name, observe.name),
                            &observed.name,
                        )?;
                    }
                }
                for spawn in &entry.spawns {
                    reject_reserved_identifier(&format!("entry `{}::{}` spawn handle", actor.name, entry.name), &spawn.name)?;
                    reject_reserved_identifier(
                        &format!("entry `{}::{}` spawn covenant binding", actor.name, entry.name),
                        &spawn.covenant,
                    )?;
                    for output in &spawn.outputs {
                        reject_reserved_identifier(
                            &format!("entry `{}::{}` spawn `{}` output handle", actor.name, entry.name, spawn.name),
                            &output.name,
                        )?;
                    }
                }
                if let EmitSpec::Outputs(outputs) = &entry.emits {
                    for output in outputs {
                        reject_reserved_identifier(&format!("entry `{}::{}` output handle", actor.name, entry.name), &output.name)?;
                    }
                }
                for route in &entry.routes {
                    if let Some(output) = &route.output {
                        reject_reserved_identifier(&format!("entry `{}::{}` route output handle", actor.name, entry.name), output)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_generated_actor_suffixes(&self) -> Result<()> {
        let mut seen = BTreeMap::new();
        for actor in &self.template_actors {
            let suffix = to_snake(actor);
            if let Some(previous) = seen.insert(suffix.clone(), actor.as_str()) {
                return Err(ArgentError::new(format!(
                    "template actors `{previous}` and `{actor}` both map to generated suffix `{suffix}`"
                )));
            }
        }
        Ok(())
    }

    fn validate_entry(&self, actor: &ActorDecl, entry: &EntryDecl, template_actor_set: &BTreeSet<String>) -> Result<()> {
        self.validate_observes(actor, entry)?;
        self.validate_spawns(actor, entry)?;

        if entry.kind == EntryKind::Delegate && entry.consumes.is_empty() {
            return Err(ArgentError::new(format!(
                "delegate `{}::{}` must declare its leader as the first `consumes` actor",
                actor.name, entry.name
            )));
        }

        for consume in &entry.consumes {
            self.require_template_actor(
                &consume.actor,
                template_actor_set,
                format!("entry `{}::{}` consumes unknown actor `{}`", actor.name, entry.name, consume.actor),
            )?;
        }

        match &entry.emits {
            EmitSpec::None => {}
            EmitSpec::One { actors } => {
                for target in self.expand_actor_refs(actors) {
                    self.require_template_actor(
                        &target,
                        template_actor_set,
                        format!("entry `{}::{}` emits unknown actor `{target}`", actor.name, entry.name),
                    )?;
                }
            }
            EmitSpec::Outputs(outputs) => {
                let mut names = BTreeSet::new();
                let mut auth_indices = BTreeSet::new();
                for output in outputs {
                    if !names.insert(output.name.clone()) {
                        return Err(ArgentError::new(format!(
                            "entry `{}::{}` declares output `{}` more than once",
                            actor.name, entry.name, output.name
                        )));
                    }
                    if output.auth_index >= outputs.len() {
                        return Err(ArgentError::new(format!(
                            "entry `{}::{}` output `{}` uses auth[{}], but only {} outputs are emitted",
                            actor.name,
                            entry.name,
                            output.name,
                            output.auth_index,
                            outputs.len()
                        )));
                    }
                    if !auth_indices.insert(output.auth_index) {
                        return Err(ArgentError::new(format!(
                            "entry `{}::{}` maps multiple outputs to auth[{}]",
                            actor.name, entry.name, output.auth_index
                        )));
                    }
                    for target in self.expand_actor_refs(&output.actors) {
                        self.require_template_actor(
                            &target,
                            template_actor_set,
                            format!("entry `{}::{}` output `{}` emits unknown actor `{target}`", actor.name, entry.name, output.name),
                        )?;
                    }
                }
            }
        }

        if entry.kind == EntryKind::Delegate && !entry.routes.is_empty() {
            return Err(ArgentError::new(format!(
                "delegate `{}::{}` cannot use `become`; delegates verify coordinated transitions but emit no outputs",
                actor.name, entry.name
            )));
        }

        for route in &entry.routes {
            if route.state.trim().is_empty() {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` has an empty `become` state for actor `{}`",
                    actor.name, entry.name, route.actor
                )));
            }
            for target in self.route_targets(actor, entry, route)? {
                self.require_template_actor(
                    &target,
                    template_actor_set,
                    format!("entry `{}::{}` routes to unknown actor `{target}`", actor.name, entry.name),
                )?;
                self.actor_state(&target)?;
            }
            self.validate_route_allowed(actor, entry, route)?;
        }
        self.validate_route_coverage(actor, entry)?;
        Ok(())
    }

    fn validate_spawns(&self, actor: &ActorDecl, entry: &EntryDecl) -> Result<()> {
        if entry.kind == EntryKind::Delegate && !entry.spawns.is_empty() {
            return Err(ArgentError::new(format!("delegate `{}::{}` cannot spawn covenant outputs", actor.name, entry.name)));
        }

        let observe_names = entry.observes.iter().map(|observe| observe.name.as_str()).collect::<BTreeSet<_>>();
        let mut source_names = self
            .storage_state(&actor.state)?
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .chain(entry.params.iter().map(|param| param.name.as_str()))
            .chain(entry.consumes.iter().map(|consume| consume.name.as_str()))
            .collect::<BTreeSet<_>>();
        for observe in &entry.observes {
            source_names.extend(observed_open_bindings(observe).into_keys());
        }

        let mut names = BTreeSet::new();
        let mut covenant_bindings = BTreeSet::new();
        for spawn in &entry.spawns {
            if !names.insert(spawn.name.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` declares spawn `{}` more than once",
                    actor.name, entry.name, spawn.name
                )));
            }
            if observe_names.contains(spawn.name.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` uses `{}` as both an observe and a spawn",
                    actor.name, entry.name, spawn.name
                )));
            }
            if !covenant_bindings.insert(spawn.covenant.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` uses spawn covenant binding `{}` more than once",
                    actor.name, entry.name, spawn.covenant
                )));
            }
            if !source_names.insert(spawn.covenant.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` spawn covenant binding `{}` collides with a source value",
                    actor.name, entry.name, spawn.covenant
                )));
            }
            if spawn.outputs.is_empty() {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` spawn `{}` must declare at least one output",
                    actor.name, entry.name, spawn.name
                )));
            }

            let mut output_names = BTreeSet::new();
            for output in &spawn.outputs {
                if !output_names.insert(output.name.as_str()) {
                    return Err(ArgentError::new(format!(
                        "entry `{}::{}` spawn `{}` declares output `{}` more than once",
                        actor.name, entry.name, spawn.name, output.name
                    )));
                }
                if source_actor_type_state_for_expr(&output.actor, actor, entry, self)?.is_none() {
                    return Err(ArgentError::new(format!(
                        "entry `{}::{}` spawn `{}.{}` target `{}` must be an actor_type value",
                        actor.name, entry.name, spawn.name, output.name, output.actor
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_observes(&self, actor: &ActorDecl, entry: &EntryDecl) -> Result<()> {
        let mut observe_names = BTreeSet::new();
        for observe in &entry.observes {
            if !observe_names.insert(observe.name.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` declares observe `{}` more than once",
                    actor.name, entry.name, observe.name
                )));
            }
            if observe.covenant_expr.trim().is_empty() {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` has an empty covenant expression",
                    actor.name, entry.name, observe.name
                )));
            }
            observe_covenant_id_source(actor, entry, self, observe)?;
            self.validate_observed_open_bindings(actor, entry, observe)?;
            self.validate_observed_actor_types(actor, entry, observe, "input", &observe.inputs)?;
            self.validate_observed_actor_types(actor, entry, observe, "output", &observe.outputs)?;
        }
        Ok(())
    }

    fn validate_observed_open_bindings(&self, actor: &ActorDecl, entry: &EntryDecl, observe: &ObserveDecl) -> Result<()> {
        let mut bindings = BTreeMap::new();
        let mut source_names =
            self.storage_state(&actor.state)?.fields.iter().map(|field| field.name.as_str()).collect::<BTreeSet<_>>();
        source_names.extend(entry.params.iter().map(|param| param.name.as_str()));
        source_names.extend(entry.consumes.iter().map(|consume| consume.name.as_str()));
        for input in &observe.inputs {
            let Some(state) = input.open_state.as_deref() else {
                continue;
            };
            reject_reserved_identifier(
                &format!("entry `{}::{}` observe `{}` open actor binding", actor.name, entry.name, observe.name),
                &input.actor,
            )?;
            if source_names.contains(input.actor.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` open observed actor binding `{}` collides with a source value",
                    actor.name, entry.name, observe.name, input.actor
                )));
            }
            self.state(state)?;
            if let Some(previous_state) = bindings.insert(input.actor.as_str(), state) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` declares open observed actor binding `{}` for both `{previous_state}` and `{state}`",
                    actor.name, entry.name, observe.name, input.actor
                )));
            }
            if !observe.outputs.iter().any(|output| output.actor == input.actor) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` open observed actor binding `{}` must be used by an output",
                    actor.name, entry.name, observe.name, input.actor
                )));
            }
        }
        Ok(())
    }

    fn validate_observed_actor_types(
        &self,
        actor: &ActorDecl,
        entry: &EntryDecl,
        observe: &ObserveDecl,
        section: &str,
        observed_actors: &[ObservedActorDecl],
    ) -> Result<()> {
        let mut names = BTreeSet::new();
        for observed in observed_actors {
            if !names.insert(observed.name.as_str()) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` declares {section} `{}` more than once",
                    actor.name, entry.name, observe.name, observed.name
                )));
            }
            if let Some(state) = observed_open_state_for_decl(actor, entry, observe, observed, self)? {
                self.state(&state).map_err(|_| {
                    ArgentError::new(format!(
                        "entry `{}::{}` observe `{}` {section} `{}` references unknown state `{state}`",
                        actor.name, entry.name, observe.name, observed.name
                    ))
                })?;
                continue;
            }
            self.actor_state(&observed.actor).map_err(|_| {
                ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` {section} `{}` references unknown actor `{}`",
                    actor.name, entry.name, observe.name, observed.name, observed.actor
                ))
            })?;
        }
        Ok(())
    }

    fn validate_observed_template_state_fields(&self) -> Result<()> {
        let mut seen = BTreeMap::new();
        for actor in &self.actors {
            for entry in &actor.entries {
                for observe in &entry.observes {
                    for spec in observed_actor_template_specs(actor, entry, observe, self)? {
                        let field = hidden_observed_actor_template_name(&spec);
                        let key = (actor.state.as_str(), field.clone());
                        if let Some(previous) = seen.insert(key, (actor.name.as_str(), entry.name.as_str(), spec.clone()))
                            && previous.2 != spec
                        {
                            return Err(ArgentError::new(format!(
                                "observed input template field `{field}` for state `{}` is used by both `{}::{}` and `{}::{}` with different actors",
                                actor.state, previous.0, previous.1, actor.name, entry.name
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn require_template_actor(&self, actor: &str, template_actor_set: &BTreeSet<String>, message: String) -> Result<()> {
        if !template_actor_set.contains(actor) {
            return Err(ArgentError::new(message));
        }
        self.actor_state(actor)?;
        Ok(())
    }

    fn validate_route_allowed(&self, actor: &ActorDecl, entry: &EntryDecl, route: &RouteCall) -> Result<()> {
        match &entry.emits {
            EmitSpec::None => Err(ArgentError::new(format!(
                "entry `{}::{}` has a `become` route to `{}`, but declares `emits none`",
                actor.name, entry.name, route.actor
            ))),
            EmitSpec::One { actors } => {
                if let Some(output) = &route.output {
                    return Err(ArgentError::new(format!(
                        "entry `{}::{}` names output `{output}`, but `emits one` uses an unnamed output",
                        actor.name, entry.name
                    )));
                }
                let allowed = self.expand_actor_refs(actors);
                let targets = self.route_targets(actor, entry, route)?;
                if targets.iter().all(|target| allowed.iter().any(|allowed| allowed == target)) {
                    Ok(())
                } else {
                    Err(ArgentError::new(format!(
                        "entry `{}::{}` routes to `{}`, but `emits one` allows only {}",
                        actor.name,
                        entry.name,
                        route.actor,
                        actors.join(" | ")
                    )))
                }
            }
            EmitSpec::Outputs(outputs) => {
                let output_name = route.output.as_ref().ok_or_else(|| {
                    ArgentError::new(format!(
                        "entry `{}::{}` routes to `{}` without an output handle, but declares named outputs",
                        actor.name, entry.name, route.actor
                    ))
                })?;
                let output = outputs.iter().find(|output| &output.name == output_name).ok_or_else(|| {
                    ArgentError::new(format!("entry `{}::{}` routes through unknown output `{output_name}`", actor.name, entry.name))
                })?;
                let allowed = self.expand_actor_refs(&output.actors);
                let targets = self.route_targets(actor, entry, route)?;
                if targets.iter().all(|target| allowed.iter().any(|allowed| allowed == target)) {
                    Ok(())
                } else {
                    Err(ArgentError::new(format!(
                        "entry `{}::{}` routes output `{}` to `{}`, but that output allows only {}",
                        actor.name,
                        entry.name,
                        output.name,
                        route.actor,
                        output.actors.join(" | ")
                    )))
                }
            }
        }
    }

    fn validate_route_coverage(&self, actor: &ActorDecl, entry: &EntryDecl) -> Result<()> {
        match &entry.emits {
            EmitSpec::None => Ok(()),
            EmitSpec::One { .. } => self.validate_single_output_coverage(actor, entry),
            EmitSpec::Outputs(outputs) => self.validate_named_output_coverage(actor, entry, outputs),
        }
    }

    fn validate_single_output_coverage(&self, actor: &ActorDecl, entry: &EntryDecl) -> Result<()> {
        if entry.terminal_route_sets.is_empty() {
            return Err(ArgentError::new(format!(
                "entry `{}::{}` declares `emits one` but has no terminal `become` route",
                actor.name, entry.name
            )));
        }

        for (path_idx, routes) in entry.terminal_route_sets.iter().enumerate() {
            if routes.len() != 1 || routes[0].output.is_some() {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` terminal path {} must validate exactly one unnamed output for `emits one`",
                    actor.name, entry.name, path_idx
                )));
            }
        }
        Ok(())
    }

    fn validate_named_output_coverage(&self, actor: &ActorDecl, entry: &EntryDecl, outputs: &[EmitOutput]) -> Result<()> {
        if outputs.is_empty() {
            return Ok(());
        }
        if entry.terminal_route_sets.is_empty() {
            return Err(ArgentError::new(format!(
                "entry `{}::{}` declares {} outputs but has no terminal `become` route",
                actor.name,
                entry.name,
                outputs.len()
            )));
        }

        let declared = outputs.iter().map(|output| output.name.as_str()).collect::<BTreeSet<_>>();
        for (path_idx, routes) in entry.terminal_route_sets.iter().enumerate() {
            let mut seen = BTreeSet::new();
            for route in routes {
                let output = route.output.as_deref().ok_or_else(|| {
                    ArgentError::new(format!(
                        "entry `{}::{}` terminal path {} has an unnamed route but declares named outputs",
                        actor.name, entry.name, path_idx
                    ))
                })?;
                if !declared.contains(output) {
                    continue;
                }
                if !seen.insert(output) {
                    return Err(ArgentError::new(format!(
                        "entry `{}::{}` terminal path {} validates output `{}` more than once",
                        actor.name, entry.name, path_idx, output
                    )));
                }
            }

            for output in outputs {
                if !seen.contains(output.name.as_str()) {
                    return Err(ArgentError::new(format!(
                        "entry `{}::{}` terminal path {} does not validate output `{}`",
                        actor.name, entry.name, path_idx, output.name
                    )));
                }
            }
        }
        Ok(())
    }
}

fn collect_consts(program: &Program) -> Result<Vec<&ConstDecl>> {
    let mut seen = BTreeMap::new();
    let mut consts = Vec::new();
    for module in &program.modules {
        for konst in &module.consts {
            reject_duplicate_top_level(word::CONST, &konst.name, &module.path, &mut seen)?;
            consts.push(konst);
        }
    }
    Ok(consts)
}

fn collect_functions(program: &Program) -> Result<Vec<&FunctionDecl>> {
    let mut seen = BTreeMap::new();
    let mut functions = Vec::new();
    for module in &program.modules {
        for function in &module.functions {
            reject_duplicate_top_level(word::FN, &function.name, &module.path, &mut seen)?;
            functions.push(function);
        }
    }
    Ok(functions)
}

fn collect_states(program: &Program) -> Result<BTreeMap<String, &StateDecl>> {
    let mut seen = BTreeMap::new();
    let mut states = BTreeMap::new();
    for module in &program.modules {
        for state in &module.states {
            reject_duplicate_top_level(word::STATE, &state.name, &module.path, &mut seen)?;
            states.insert(state.name.clone(), state);
        }
    }
    Ok(states)
}

fn collect_actors(program: &Program) -> Result<BTreeMap<String, &ActorDecl>> {
    let mut seen = BTreeMap::new();
    let mut actors = BTreeMap::new();
    for module in &program.modules {
        for actor in &module.actors {
            reject_duplicate_top_level(word::ACTOR, &actor.name, &module.path, &mut seen)?;
            actors.insert(actor.name.clone(), actor);
        }
    }
    Ok(actors)
}

fn collect_actor_enums(program: &Program) -> Result<BTreeMap<String, &ActorEnumDecl>> {
    let mut seen = BTreeMap::new();
    let mut actor_enums = BTreeMap::new();
    for module in &program.modules {
        for actor_enum in &module.actor_enums {
            reject_duplicate_top_level("actor enum", &actor_enum.name, &module.path, &mut seen)?;
            actor_enums.insert(actor_enum.name.clone(), actor_enum);
        }
    }
    Ok(actor_enums)
}

fn build_actor_enums(
    actor_enum_decls: &BTreeMap<String, &ActorEnumDecl>,
    actors_by_name: &BTreeMap<String, &ActorDecl>,
    states: &BTreeMap<String, &StateDecl>,
    template_actors: &[String],
) -> Result<BTreeMap<String, ActorEnumInfo>> {
    let template_actor_set = template_actors.iter().cloned().collect::<BTreeSet<_>>();
    let mut out = BTreeMap::new();
    for actor_enum in actor_enum_decls.values() {
        if !actor_enum.variants.iter().any(|variant| template_actor_set.contains(variant)) {
            continue;
        }
        if actors_by_name.contains_key(&actor_enum.name) || states.contains_key(&actor_enum.name) {
            return Err(ArgentError::new(format!("actor enum `{}` conflicts with an actor or state declaration", actor_enum.name)));
        }
        if actor_enum.variants.len() < 2 {
            return Err(ArgentError::new(format!("actor enum `{}` must contain at least two variants", actor_enum.name)));
        }
        let mut seen = BTreeSet::new();
        let mut state = None::<String>;
        for variant in &actor_enum.variants {
            if !seen.insert(variant.as_str()) {
                return Err(ArgentError::new(format!("actor enum `{}` repeats variant `{variant}`", actor_enum.name)));
            }
            if !template_actor_set.contains(variant) {
                return Err(ArgentError::new(format!(
                    "actor enum `{}` references actor `{variant}` outside the app",
                    actor_enum.name
                )));
            }
            let actor = actors_by_name
                .get(variant)
                .copied()
                .ok_or_else(|| ArgentError::new(format!("actor enum `{}` references unknown actor `{variant}`", actor_enum.name)))?;
            if let Some(expected) = &state {
                if expected != &actor.state {
                    return Err(ArgentError::new(format!(
                        "actor enum `{}` variant `{variant}` owns state `{}`, expected `{expected}`",
                        actor_enum.name, actor.state
                    )));
                }
            } else {
                state = Some(actor.state.clone());
            }
        }
        out.insert(
            actor_enum.name.clone(),
            ActorEnumInfo {
                name: actor_enum.name.clone(),
                state: state.expect("non-empty actor enum has a state"),
                variants: actor_enum.variants.clone(),
            },
        );
    }
    Ok(out)
}

fn template_selectors_for_entry(
    actor: &ActorDecl,
    entry: &EntryDecl,
    actor_enums: &BTreeMap<String, ActorEnumInfo>,
) -> Result<BTreeMap<String, TemplateSelector>> {
    let ctx = TemplateSelectorContext { actor, entry, actor_enums };
    let mut selectors = BTreeMap::new();
    for param in &entry.params {
        if param.ty.array.is_some() || !actor_enums.contains_key(&param.ty.name) {
            continue;
        }
        let selector = template_selector_from_actor_enum_value(
            &ctx,
            TemplateSelectorRequest {
                name: &param.name,
                actor_enum_name: &param.ty.name,
                selector_expr: &param.name,
                fixed_actor: None,
                expected_state: None,
                expected_actor_enum: Some(&param.ty.name),
            },
        )?;
        insert_template_selector(actor, entry, &mut selectors, selector)?;
    }

    let tokens = lex(&entry.body)
        .map_err(|err| ArgentError::new(format!("failed to lex body for `{}::{}`: {}", actor.name, entry.name, err.message)))?;
    let mut pos = 0usize;
    while pos + 3 < tokens.len() {
        let is_actor_type = matches!(&tokens[pos].kind, TokenKind::Ident(name) if name == word::ACTOR_TYPE)
            && matches!(tokens[pos + 1].kind, TokenKind::Symbol('<'))
            && matches!(tokens[pos + 3].kind, TokenKind::Symbol('>'))
            && matches!(tokens.get(pos + 4).map(|token| &token.kind), Some(TokenKind::Ident(_)))
            && matches!(tokens.get(pos + 5).map(|token| &token.kind), Some(TokenKind::Symbol('=')));
        if is_actor_type {
            let state = match &tokens[pos + 2].kind {
                TokenKind::Ident(state) => state.clone(),
                _ => {
                    pos += 1;
                    continue;
                }
            };
            let name = match &tokens[pos + 4].kind {
                TokenKind::Ident(name) => name.clone(),
                _ => {
                    pos += 1;
                    continue;
                }
            };
            let (expr, end_pos) = take_expr_until_semicolon(&entry.body, &tokens, pos + 6, actor, entry)?;
            let selector = template_selector_from_initializer(&ctx, &name, Some(&state), None, &expr)?;
            insert_template_selector(actor, entry, &mut selectors, selector)?;
            pos = end_pos + 1;
            continue;
        }

        let is_actor_enum_local = matches!(&tokens[pos].kind, TokenKind::Ident(source_ty) if actor_enums.contains_key(source_ty))
            && matches!(tokens.get(pos + 1).map(|token| &token.kind), Some(TokenKind::Ident(_)))
            && matches!(tokens.get(pos + 2).map(|token| &token.kind), Some(TokenKind::Symbol('=')));
        if is_actor_enum_local {
            let actor_enum_name = match &tokens[pos].kind {
                TokenKind::Ident(actor_enum_name) => actor_enum_name.clone(),
                _ => unreachable!("checked actor enum local type"),
            };
            let name = match &tokens[pos + 1].kind {
                TokenKind::Ident(name) => name.clone(),
                _ => unreachable!("checked actor enum local name"),
            };
            let (expr, end_pos) = take_expr_until_semicolon(&entry.body, &tokens, pos + 3, actor, entry)?;
            let mut selector = template_selector_from_initializer(&ctx, &name, None, Some(&actor_enum_name), &expr)?;
            selector.selector_expr = name.clone();
            insert_template_selector(actor, entry, &mut selectors, selector)?;
            pos = end_pos + 1;
            continue;
        }

        pos += 1;
    }
    Ok(selectors)
}

fn take_expr_until_semicolon(
    body: &str,
    tokens: &[Token],
    start_pos: usize,
    actor: &ActorDecl,
    entry: &EntryDecl,
) -> Result<(String, usize)> {
    let start = tokens
        .get(start_pos)
        .ok_or_else(|| ArgentError::new(format!("entry `{}::{}` has an incomplete actor enum selector", actor.name, entry.name)))?
        .span
        .start;
    let mut depth = 0usize;
    let mut scan = start_pos;
    while scan < tokens.len() {
        match tokens[scan].kind {
            TokenKind::Symbol('{') | TokenKind::Symbol('(') | TokenKind::Symbol('[') => depth += 1,
            TokenKind::Symbol('}') | TokenKind::Symbol(')') | TokenKind::Symbol(']') => depth = depth.saturating_sub(1),
            TokenKind::Symbol(';') if depth == 0 => {
                return Ok((body[start..tokens[scan].span.start].trim().to_string(), scan));
            }
            TokenKind::Eof => break,
            _ => {}
        }
        scan += 1;
    }
    Err(ArgentError::new(format!("entry `{}::{}` has an unterminated actor enum selector", actor.name, entry.name)))
}

fn insert_template_selector(
    actor: &ActorDecl,
    entry: &EntryDecl,
    selectors: &mut BTreeMap<String, TemplateSelector>,
    selector: TemplateSelector,
) -> Result<()> {
    let name = selector.name.clone();
    if selectors.insert(name.clone(), selector).is_some() {
        return Err(ArgentError::new(format!("entry `{}::{}` declares actor handle `{name}` more than once", actor.name, entry.name)));
    }
    Ok(())
}

struct TemplateSelectorContext<'a> {
    actor: &'a ActorDecl,
    entry: &'a EntryDecl,
    actor_enums: &'a BTreeMap<String, ActorEnumInfo>,
}

struct TemplateSelectorRequest<'a> {
    name: &'a str,
    actor_enum_name: &'a str,
    selector_expr: &'a str,
    fixed_actor: Option<&'a str>,
    expected_state: Option<&'a str>,
    expected_actor_enum: Option<&'a str>,
}

fn template_selector_from_initializer(
    ctx: &TemplateSelectorContext<'_>,
    name: &str,
    expected_state: Option<&str>,
    expected_actor_enum: Option<&str>,
    expr: &str,
) -> Result<TemplateSelector> {
    if let Some((actor_enum, selector_expr)) = parse_actor_enum_selector(expr) {
        return template_selector_from_actor_enum_value(
            ctx,
            TemplateSelectorRequest {
                name,
                actor_enum_name: actor_enum,
                selector_expr,
                fixed_actor: None,
                expected_state,
                expected_actor_enum,
            },
        );
    }
    if let Some((actor_enum, variant)) = parse_actor_enum_variant(expr) {
        return template_selector_from_actor_enum_value(
            ctx,
            TemplateSelectorRequest {
                name,
                actor_enum_name: &actor_enum,
                selector_expr: "",
                fixed_actor: Some(&variant),
                expected_state,
                expected_actor_enum,
            },
        );
    }
    if let Some(actor_enum) = expected_actor_enum {
        return template_selector_from_actor_enum_value(
            ctx,
            TemplateSelectorRequest {
                name,
                actor_enum_name: actor_enum,
                selector_expr: expr,
                fixed_actor: None,
                expected_state,
                expected_actor_enum,
            },
        );
    }
    Err(ArgentError::new(format!(
        "entry `{}::{}` declares actor handle `{name}` without an actor enum initializer",
        ctx.actor.name, ctx.entry.name
    )))
}

fn template_selector_from_actor_enum_value(
    ctx: &TemplateSelectorContext<'_>,
    request: TemplateSelectorRequest<'_>,
) -> Result<TemplateSelector> {
    if let Some(expected_actor_enum) = request.expected_actor_enum
        && request.actor_enum_name != expected_actor_enum
    {
        return Err(ArgentError::new(format!(
            "entry `{}::{}` declares actor enum value `{name}` as `{expected_actor_enum}`, but initializes it from `{actor_enum_name}`",
            ctx.actor.name,
            ctx.entry.name,
            name = request.name,
            actor_enum_name = request.actor_enum_name
        )));
    }
    let actor_enum = ctx.actor_enums.get(request.actor_enum_name).ok_or_else(|| {
        ArgentError::new(format!(
            "entry `{}::{}` declares actor handle `{name}` from unknown actor enum `{actor_enum_name}`",
            ctx.actor.name,
            ctx.entry.name,
            name = request.name,
            actor_enum_name = request.actor_enum_name
        ))
    })?;
    if let Some(expected_state) = request.expected_state
        && actor_enum.state != expected_state
    {
        return Err(ArgentError::new(format!(
            "entry `{}::{}` declares actor handle `{name}` as {actor_type}<{expected_state}>, but `{actor_enum_name}` contains {actor_type}<{}>",
            ctx.actor.name,
            ctx.entry.name,
            actor_enum.state,
            actor_type = word::ACTOR_TYPE,
            name = request.name,
            actor_enum_name = request.actor_enum_name
        )));
    }
    if ctx.actor.state != actor_enum.state {
        return Err(ArgentError::new(format!(
            "entry `{}::{}` uses actor enum `{actor_enum_name}` for state `{}`, but the entry actor owns `{}`; selector values currently require the same state",
            ctx.actor.name,
            ctx.entry.name,
            actor_enum.state,
            ctx.actor.state,
            actor_enum_name = request.actor_enum_name
        )));
    }
    let fixed_actor = request.fixed_actor.map(str::to_string);
    let selector_expr = if let Some(fixed_actor) = &fixed_actor {
        actor_enum_variant_const_expr(actor_enum, fixed_actor).ok_or_else(|| {
            ArgentError::new(format!(
                "actor enum `{actor_enum_name}` has no variant `{fixed_actor}` in `{}::{}`",
                ctx.actor.name,
                ctx.entry.name,
                actor_enum_name = request.actor_enum_name
            ))
        })?
    } else {
        request.selector_expr.trim().to_string()
    };
    if selector_expr.is_empty() {
        return Err(ArgentError::new(format!(
            "entry `{}::{}` declares actor enum value `{name}` with an empty selector",
            ctx.actor.name,
            ctx.entry.name,
            name = request.name
        )));
    }
    Ok(TemplateSelector {
        name: request.name.to_string(),
        actor_enum: actor_enum.name.clone(),
        state: actor_enum.state.clone(),
        variants: actor_enum.variants.clone(),
        selector_expr,
        fixed_actor,
    })
}

fn expand_entry_template_routes(
    actor: &ActorDecl,
    entry: &EntryDecl,
    actor_enums: &BTreeMap<String, ActorEnumInfo>,
) -> Result<Vec<RouteCall>> {
    let selectors = template_selectors_for_entry(actor, entry, actor_enums)?;
    Ok(expand_route_set_for_template_deps(&entry.routes, &selectors))
}

fn expand_route_set(routes: &[RouteCall], selectors: &BTreeMap<String, TemplateSelector>) -> Vec<RouteCall> {
    let mut out = Vec::new();
    for route in routes {
        if let Some(selector) = selectors.get(&route.actor) {
            out.extend(selector.route_actors().into_iter().map(|variant| RouteCall {
                output: route.output.clone(),
                actor: variant,
                state: route.state.clone(),
            }));
        } else {
            out.push(route.clone());
        }
    }
    out
}

fn expand_route_set_for_template_deps(routes: &[RouteCall], selectors: &BTreeMap<String, TemplateSelector>) -> Vec<RouteCall> {
    let mut out = Vec::new();
    for route in routes {
        if let Some(selector) = selectors.get(&route.actor) {
            out.extend(selector.variants.iter().cloned().map(|variant| RouteCall {
                output: route.output.clone(),
                actor: variant,
                state: route.state.clone(),
            }));
        } else {
            out.push(route.clone());
        }
    }
    out
}

fn validate_unique_apps(program: &Program) -> Result<()> {
    let mut seen = BTreeMap::new();
    for module in &program.modules {
        for app in &module.apps {
            reject_duplicate_top_level(word::APP, &app.name, &module.path, &mut seen)?;
        }
    }
    Ok(())
}

fn select_root_app<'a>(program: &'a Program, app_name: Option<&str>) -> Result<Option<&'a AppDecl>> {
    let root = program
        .modules
        .iter()
        .find(|module| module.path == program.root)
        .ok_or_else(|| ArgentError::at(&program.root, "root module is missing from the loaded program"))?;

    if let Some(app_name) = app_name {
        return root
            .apps
            .iter()
            .find(|app| app.name == app_name)
            .map(Some)
            .ok_or_else(|| ArgentError::at(&program.root, format!("root module has no app named `{app_name}`")));
    }

    match root.apps.as_slice() {
        [] => Ok(None),
        [app] => Ok(Some(app)),
        apps => Err(ArgentError::at(
            &program.root,
            format!(
                "root module declares multiple apps ({}); select one with `--app <name>`",
                apps.iter().map(|app| app.name.as_str()).collect::<Vec<_>>().join(", ")
            ),
        )),
    }
}

fn compute_state_template_deps<'a>(
    actors: &[&'a ActorDecl],
    actors_by_name: &BTreeMap<String, &'a ActorDecl>,
    template_actors: &[String],
    actor_enums: &BTreeMap<String, ActorEnumInfo>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let template_actor_set = template_actors.iter().cloned().collect::<BTreeSet<_>>();
    let mut deps = BTreeMap::<String, BTreeSet<String>>::new();
    let mut routes = BTreeMap::<String, BTreeSet<String>>::new();

    for actor in actors {
        deps.entry(actor.state.clone()).or_default();
        routes.entry(actor.state.clone()).or_default();

        for entry in &actor.entries {
            for consume in &entry.consumes {
                if template_actor_set.contains(&consume.actor) {
                    deps.entry(actor.state.clone()).or_default().insert(consume.actor.clone());
                }
            }

            for route in expand_entry_template_routes(actor, entry, actor_enums)? {
                let target = actors_by_name.get(&route.actor).copied().ok_or_else(|| {
                    ArgentError::new(format!("entry `{}::{}` routes to unknown actor `{}`", actor.name, entry.name, route.actor))
                })?;
                routes.entry(actor.state.clone()).or_default().insert(target.state.clone());
                routes.entry(target.state.clone()).or_default();
                deps.entry(target.state.clone()).or_default();

                if template_actor_set.contains(&route.actor)
                    && route_validation_kind(actor, &route) == RouteValidationKind::ForeignTemplate
                {
                    deps.entry(actor.state.clone()).or_default().insert(route.actor.clone());
                }
            }
        }
    }

    // A source state must also carry the templates needed to construct any
    // successor state. Propagate those requirements backward to a fixed point;
    // this preserves route cycles without leaking them into terminal states.
    loop {
        let mut changed = false;
        for (state, targets) in &routes {
            let inherited = targets.iter().flat_map(|target| deps.get(target).into_iter().flatten()).cloned().collect::<BTreeSet<_>>();
            let state_deps = deps.get_mut(state).expect("route source state has dependency storage");
            for actor in inherited {
                changed |= state_deps.insert(actor);
            }
        }
        if !changed {
            break;
        }
    }

    Ok(deps
        .into_iter()
        .map(|(state, deps)| {
            let ordered = template_actors.iter().filter(|actor| deps.contains(*actor)).cloned().collect::<Vec<_>>();
            (state, ordered)
        })
        .collect())
}

fn compute_direct_state_template_deps<'a>(
    actors: &[&'a ActorDecl],
    actors_by_name: &BTreeMap<String, &'a ActorDecl>,
    template_actors: &[String],
    actor_enums: &BTreeMap<String, ActorEnumInfo>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let template_actor_set = template_actors.iter().cloned().collect::<BTreeSet<_>>();
    let mut direct = BTreeMap::<String, BTreeSet<String>>::new();
    for actor in actors {
        direct.entry(actor.state.clone()).or_default();
        for entry in &actor.entries {
            for consume in &entry.consumes {
                if template_actor_set.contains(&consume.actor) {
                    direct.entry(actor.state.clone()).or_default().insert(consume.actor.clone());
                }
            }
            for route in expand_entry_template_routes(actor, entry, actor_enums)? {
                let target = actors_by_name.get(&route.actor).copied().ok_or_else(|| {
                    ArgentError::new(format!("entry `{}::{}` routes to unknown actor `{}`", actor.name, entry.name, route.actor))
                })?;
                if template_actor_set.contains(&target.name)
                    && route_validation_kind(actor, &route) == RouteValidationKind::ForeignTemplate
                {
                    direct.entry(actor.state.clone()).or_default().insert(target.name.clone());
                }
            }
        }
    }
    Ok(direct)
}

fn compute_state_route_leaves(
    state_template_deps: &BTreeMap<String, Vec<String>>,
    direct_state_template_deps: &BTreeMap<String, BTreeSet<String>>,
    route_families: &[RouteFamily],
) -> BTreeMap<String, Vec<RouteRootLeaf>> {
    let family_actor_sets = route_families
        .iter()
        .map(|family| (family.id.as_str(), family.actors.iter().map(String::as_str).collect::<BTreeSet<_>>()))
        .collect::<BTreeMap<_, _>>();
    let mut out = BTreeMap::new();
    for (state, deps) in state_template_deps {
        let mut leaves = Vec::new();
        let mut emitted_families = BTreeSet::new();
        let direct = direct_state_template_deps.get(state);
        for actor in deps {
            let family = route_families.iter().find(|family| family_actor_sets[family.id.as_str()].contains(actor.as_str()));
            if let Some(family) = family {
                if family.direct_template_actors().contains(actor)
                    || family.state == *state
                    || direct.is_some_and(|direct| direct.contains(actor))
                {
                    leaves.push(RouteRootLeaf::Actor(actor.clone()));
                }
                if emitted_families.insert(family.id.as_str()) {
                    leaves.push(RouteRootLeaf::Family(family.id.clone()));
                }
            } else {
                leaves.push(RouteRootLeaf::Actor(actor.clone()));
            }
        }
        out.insert(state.clone(), leaves);
    }
    out
}

fn infer_direct_route_families<'a>(
    actors: &[&'a ActorDecl],
    actors_by_name: &BTreeMap<String, &'a ActorDecl>,
    template_actors: &[String],
    actor_enums: &BTreeMap<String, ActorEnumInfo>,
) -> Result<Vec<RouteFamily>> {
    let template_actor_set = template_actors.iter().cloned().collect::<BTreeSet<_>>();
    let mut edges_by_state = BTreeMap::<String, BTreeMap<String, BTreeSet<String>>>::new();
    let mut directed_routes = Vec::<(String, String)>::new();
    let mut selectors_by_actor = BTreeMap::<String, Vec<TemplateSelector>>::new();

    for actor in actors {
        for entry in &actor.entries {
            let selectors = template_selectors_for_entry(actor, entry, actor_enums)?;
            selectors_by_actor.entry(actor.name.clone()).or_default().extend(selectors.values().cloned());
            for route in expand_entry_template_routes(actor, entry, actor_enums)? {
                let target = actors_by_name.get(&route.actor).copied().ok_or_else(|| {
                    ArgentError::new(format!("entry `{}::{}` routes to unknown actor `{}`", actor.name, entry.name, route.actor))
                })?;
                if !template_actor_set.contains(&actor.name) || !template_actor_set.contains(&target.name) {
                    continue;
                }
                if actor.name != target.name {
                    directed_routes.push((actor.name.clone(), target.name.clone()));
                }
                if actor.name == target.name || actor.state != target.state {
                    continue;
                }
                edges_by_state
                    .entry(actor.state.clone())
                    .or_default()
                    .entry(actor.name.clone())
                    .or_default()
                    .insert(target.name.clone());
                edges_by_state
                    .entry(actor.state.clone())
                    .or_default()
                    .entry(target.name.clone())
                    .or_default()
                    .insert(actor.name.clone());
            }
        }
    }

    let mut families = Vec::new();
    for (state, edges) in edges_by_state {
        let mut visited = BTreeSet::new();
        for actor in edges.keys() {
            if visited.contains(actor) {
                continue;
            }
            let mut stack = vec![actor.clone()];
            let mut component = BTreeSet::new();
            while let Some(next) = stack.pop() {
                if !visited.insert(next.clone()) {
                    continue;
                }
                component.insert(next.clone());
                if let Some(neighbors) = edges.get(&next) {
                    stack.extend(neighbors.iter().filter(|neighbor| !visited.contains(*neighbor)).cloned());
                }
            }
            // A two-actor component needs two template hashes either way;
            // direct fields avoid the extra table hash and slice operations.
            if component.len() < 3 {
                continue;
            }
            let actors = template_actors.iter().filter(|actor| component.contains(*actor)).cloned().collect::<Vec<_>>();
            let entry_actors = template_actors
                .iter()
                .filter(|actor| {
                    component.contains(*actor)
                        && directed_routes.iter().any(|(source, target)| target == *actor && !component.contains(source))
                })
                .cloned()
                .collect::<Vec<_>>();
            let anchor_actor = entry_actors.first().or_else(|| actors.first()).expect("component has at least two actors");
            let direct_template_actors = if entry_actors.is_empty() { vec![anchor_actor.clone()] } else { entry_actors.clone() };
            let direct_template_actor_set = direct_template_actors.iter().cloned().collect::<BTreeSet<_>>();
            let default_table_actors =
                actors.iter().filter(|actor| !direct_template_actor_set.contains(*actor)).cloned().collect::<Vec<_>>();
            let table_actors =
                route_family_table_actors_from_selector_order(&state, &actors, &default_table_actors, &selectors_by_actor)?;
            // Multiple direct entry actors can leave only one table entry even
            // in a larger component. Such a table has no storage benefit.
            if table_actors.len() < 2 {
                continue;
            }
            families.push(RouteFamily {
                id: route_template_family_receipt_id(&state, anchor_actor),
                state: state.clone(),
                actors,
                entry_actors,
                direct_template_actors,
                table_actors,
            });
        }
    }

    Ok(families)
}

fn route_family_table_actors_from_selector_order(
    state: &str,
    component_actors: &[String],
    default_table_actors: &[String],
    selectors_by_actor: &BTreeMap<String, Vec<TemplateSelector>>,
) -> Result<Vec<String>> {
    let table_actor_set = default_table_actors.iter().cloned().collect::<BTreeSet<_>>();
    let mut selected_order = None::<(&str, Vec<String>)>;

    for actor in component_actors {
        let Some(selectors) = selectors_by_actor.get(actor) else {
            continue;
        };
        for selector in selectors.iter().filter(|selector| selector.state == state) {
            let selector_actor_set = selector.variants.iter().cloned().collect::<BTreeSet<_>>();
            if selector_actor_set != table_actor_set {
                return Err(ArgentError::new(format!(
                    "actor enum `{}` variants must exactly match the route table actors for state `{state}`; expected {:?}, found {:?}",
                    selector.actor_enum, table_actor_set, selector_actor_set
                )));
            }

            if let Some((source_actor_enum, order)) = &selected_order {
                if order != &selector.variants {
                    return Err(ArgentError::new(format!(
                        "actor enum `{}` uses a different selector order than actor enum `{source_actor_enum}` for state `{state}`",
                        selector.actor_enum
                    )));
                }
            } else {
                selected_order = Some((&selector.actor_enum, selector.variants.clone()));
            }
        }
    }

    Ok(selected_order.map_or_else(|| default_table_actors.to_vec(), |(_, order)| order))
}

fn reject_duplicate_top_level<'a>(kind: &str, name: &str, path: &'a Path, seen: &mut BTreeMap<String, &'a Path>) -> Result<()> {
    if let Some(first_path) = seen.insert(name.to_string(), path) {
        return Err(ArgentError::new(format!(
            "duplicate top-level {kind} `{name}` in `{}`; first declared in `{}`",
            path.display(),
            first_path.display()
        )));
    }
    Ok(())
}

fn emit_actor(actor: &ActorDecl, model: &Model<'_>) -> Result<String> {
    let state = model.storage_state(&actor.state)?;
    let mut out = String::new();
    out.push_str("pragma silverscript ^0.1.0;\n\n");
    out.push_str("// Generated by argentc. Do not edit by hand.\n\n");

    out.push_str(&format!("contract {}(\n", actor.name));
    let mut args = Vec::new();
    args.extend(hidden_template_init_args_for_state(&actor.state, model).into_iter().map(|arg| format!("    {arg}")));
    for field in &state.fields {
        args.push(format!("    {} init_{}", lower_type_ref(&field.ty, model), field.name));
    }
    out.push_str(&args.join(",\n"));
    out.push_str("\n) {\n");

    emit_shared_constants(&mut out, model)?;
    emit_state_layouts(&mut out, actor, model)?;
    emit_shared_functions(&mut out, model);

    emit_section_header(&mut out, "Route templates");
    emit_route_template_table(&mut out, &actor.state, model);
    out.push('\n');

    emit_section_header_raw(&mut out, &format!("state fields: {}", actor.name));
    for field in &state.fields {
        out.push_str(&format!("    {} {} = init_{};\n", lower_type_ref(&field.ty, model), field.name, field.name));
    }
    out.push('\n');

    emit_section_header(&mut out, "Entrypoints");
    for entry in &actor.entries {
        emit_entry(&mut out, actor, entry, model)?;
        out.push('\n');
    }

    out.push_str("}\n");
    Ok(out)
}

fn emit_section_header(out: &mut String, title: &str) {
    out.push_str(&format!("    // :: {}\n", title.to_ascii_lowercase()));
}

fn emit_section_header_raw(out: &mut String, title: &str) {
    out.push_str(&format!("    // :: {title}\n"));
}

fn emit_shared_constants(out: &mut String, model: &Model<'_>) -> Result<()> {
    if !model.consts.is_empty() {
        emit_section_header(out, "Shared constants");
        for konst in &model.consts {
            out.push_str(&format!(
                "    {} constant {} = {};\n",
                lower_type_ref(&konst.ty, model),
                konst.name,
                lower_actor_enum_literals(&konst.value, model)?
            ));
        }
        out.push('\n');
    }
    Ok(())
}

fn emit_state_layouts(out: &mut String, current_actor: &ActorDecl, model: &Model<'_>) -> Result<()> {
    emit_section_header(out, "State layouts");
    let mut emitted = BTreeSet::new();
    let mut state_names = model.actors.iter().map(|actor| actor.state.clone()).collect::<Vec<_>>();
    for entry in &current_actor.entries {
        for observe in &entry.observes {
            for observed in observe.inputs.iter().chain(observe.outputs.iter()) {
                if let Some(state) = observed_open_state_for_decl(current_actor, entry, observe, observed, model)? {
                    state_names.push(state.to_string());
                } else {
                    state_names.push(model.actor(&observed.actor)?.state.clone());
                }
            }
        }
        for spawn in &entry.spawns {
            for output in &spawn.outputs {
                let state = source_actor_type_state_for_expr(&output.actor, current_actor, entry, model)?
                    .expect("spawn target actor_type checked during model validation");
                state_names.push(state);
            }
        }
    }

    for state_name in state_names {
        if state_name == current_actor.state {
            continue;
        }
        if !emitted.insert(state_name.clone()) {
            continue;
        }
        let state = model.storage_state(&state_name)?;
        out.push_str(&format!("    struct {state_name} {{\n"));
        out.push_str("        // :: generated fields\n");
        emit_hidden_template_fields(out, state_name.as_str(), model, 8);
        out.push_str("\n        // :: user declared fields\n");
        for field in &state.fields {
            out.push_str(&format!("        {} {};\n", lower_type_ref(&field.ty, model), field.name));
        }
        out.push_str("    }\n");
    }
    out.push('\n');
    Ok(())
}

fn emit_shared_functions(out: &mut String, model: &Model<'_>) {
    if !model.functions.is_empty() {
        emit_section_header(out, "Shared helper functions");
        for function in &model.functions {
            let params = function
                .params
                .iter()
                .map(|param| format!("{} {}", lower_type_ref(&param.ty, model), param.name))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("    function {}({}) : {} {{\n", function.name, params, lower_type_ref(&function.return_ty, model)));
            out.push_str(&indent_block_body(&function.body, 8));
            out.push_str("    }\n");
        }
        out.push('\n');
    }
}

fn emit_entry(out: &mut String, actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<()> {
    let witness_specs = entry_witness_specs(actor, entry, model)?;
    let sil_params = lower_entry_params(actor, entry, &witness_specs, model);
    push_entry_signature(out, &entry.name, &sil_params);

    let has_byte_witnesses =
        witness_specs.templates.iter().any(|spec| spec.form == TemplateWitnessForm::Bytes) || !witness_specs.selectors.is_empty();
    if has_byte_witnesses {
        out.push_str("        // :: witness lens\n");
        for spec in &witness_specs.templates {
            if spec.form != TemplateWitnessForm::Bytes {
                continue;
            }
            let prefix = hidden_witness_prefix_name(&spec.actor);
            let suffix = hidden_witness_suffix_name(&spec.actor);
            let prefix_len = hidden_witness_prefix_len_name(&spec.actor);
            let suffix_len = hidden_witness_suffix_len_name(&spec.actor);
            out.push_str(&format!("        int {prefix_len} = {prefix}.length;\n"));
            out.push_str(&format!("        int {suffix_len} = {suffix}.length;\n"));
        }
        for spec in &witness_specs.selectors {
            let prefix = hidden_template_selector_prefix_name(&spec.name);
            let suffix = hidden_template_selector_suffix_name(&spec.name);
            let prefix_len = hidden_template_selector_prefix_len_name(&spec.name);
            let suffix_len = hidden_template_selector_suffix_len_name(&spec.name);
            out.push_str(&format!("        int {prefix_len} = {prefix}.length;\n"));
            out.push_str(&format!("        int {suffix_len} = {suffix}.length;\n"));
        }
        out.push('\n');
    }

    if emit_entry_template_locals(out, actor, &witness_specs, model) {
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
        match entry.kind {
            EntryKind::Leader => {
                let count = entry.consumes.len() + 1;
                out.push_str(&format!("        require(OpCovInputCount({cov_id}) == {count});\n"));
                // If count == 1, the assertion below follows from the preceding
                // OpCovInputCount check: cov_id is the active input's ID, so the
                // only matching input at cov[0] must be this.activeInputIndex.
                if count > 1 {
                    out.push_str(&format!("        require(OpCovInputIdx({cov_id}, 0) == this.activeInputIndex);\n"));
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
        for (idx, consume) in entry.consumes.iter().enumerate() {
            let cov_index = slot_offset + idx;
            let input_idx = hidden_input_idx_name(&consume.name);
            let prefix_len = hidden_witness_prefix_len_name(&consume.actor);
            let suffix_len = hidden_witness_suffix_len_name(&consume.actor);
            let template = hidden_template_name(&consume.actor);
            let state_struct = contract_state_type_for_actor(&consume.actor, actor, model)?;
            let _state = model.actor_state(&consume.actor)?;
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {input_idx} = OpCovInputIdx({cov_id}, {cov_index})"),
                &format!("input {} at cov[{}]", consume.actor, cov_index),
            );
            push_generated_call(
                out,
                8,
                &format!("{state_struct} {} = ", consume.name),
                "readInputStateWithTemplate",
                &[input_idx, prefix_len, suffix_len, template],
            );
        }
        out.push('\n');
    }

    if !entry.observes.is_empty() {
        emit_observed_inputs(out, actor, entry, model)?;
    }

    emit_state_expansion_prelude(out, actor, model)?;

    out.push_str("        // :: auth outputs\n");
    let auth_output_count = emitted_auth_output_count(&entry.emits);
    out.push_str(&format!("        require(OpAuthOutputCount(this.activeInputIndex) == {auth_output_count});\n"));
    match &entry.emits {
        EmitSpec::None => {}
        EmitSpec::One { actors } => {
            let output_idx = hidden_next_output_idx_name();
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {output_idx} = OpAuthOutputIdx(this.activeInputIndex, 0)"),
                &format!("emits one {}", actors.join(" | ")),
            );
        }
        EmitSpec::Outputs(outputs) => {
            for output in outputs {
                let output_idx = hidden_output_idx_name(&output.name);
                push_generated_statement_with_comment(
                    out,
                    8,
                    &format!("int {output_idx} = OpAuthOutputIdx(this.activeInputIndex, {})", output.auth_index),
                    &format!("output {}: {}", output.name, output.actors.join(" | ")),
                );
            }
        }
    }
    out.push('\n');
    emit_spawn_prelude(out, entry)?;
    out.push_str(&lower_entry_body(actor, entry, model)?);
    out.push_str("    }\n");
    Ok(())
}

fn emitted_auth_output_count(emits: &EmitSpec) -> usize {
    match emits {
        EmitSpec::None => 0,
        EmitSpec::One { .. } => 1,
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
        out.push_str("            + bytes(OpOutpointIndex(this.activeInputIndex), 8).slice(0, 4)\n");
        out.push_str(&format!("            + bytes({}, 8)\n", spawn.outputs.len()));
        for (output_position, output) in spawn.outputs.iter().enumerate() {
            let output_idx = hidden_spawn_output_idx_name(&spawn.name, &output.name);
            out.push_str(&format!("            + bytes({output_idx}, 8).slice(0, 4)\n"));
            out.push_str(&format!("            + bytes(tx.outputs[{output_idx}].value, 8)\n"));
            out.push_str(&format!("            + 0x{:02x}{:02x}\n", P2SH_SPK_VERSION[0], P2SH_SPK_VERSION[1]));
            out.push_str(&format!("            + bytes({P2SH_SCRIPT_LEN}, 8)\n"));
            let terminator = if output_position + 1 == spawn.outputs.len() { ";" } else { "" };
            out.push_str(&format!(
                "            + OpTxOutputSpkSubstr({output_idx}, {SPK_VERSION_LEN}, {}){terminator}\n",
                SPK_VERSION_LEN + P2SH_SCRIPT_LEN
            ));
        }
        out.push_str(&format!("        byte[32] {} = blake2bWithKey({preimage}, bytes(\"CovenantID\"));\n", spawn.covenant));
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
        let digest = format!("blake2b({hidden})");
        push_generated_binary_require(out, 8, &digest, "==", &spec.field);
        let mut offset = 0usize;
        for field in &model.state(&spec.memory_state)?.fields {
            let len = packed_field_len(&field.ty)?;
            let end = offset + len;
            let slice = format!("{hidden}.slice({offset}, {end})");
            let expr = unpack_packed_field_expr(&field.ty, &slice)?;
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

fn emit_observed_inputs(out: &mut String, actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<()> {
    out.push_str("        // :: observed covenants\n");
    for observe in &entry.observes {
        let cov_id = hidden_observe_cov_id_name(&observe.name);
        let cov_expr = lower_entry_expr(actor, entry, model, &observe.covenant_expr, Some("byte[32]"))?;
        out.push_str(&format!("        byte[32] {cov_id} = {cov_expr}; // observe {}\n", observe.name));
        out.push_str(&format!("        require(OpCovInputCount({cov_id}) == {});\n", observe.inputs.len()));
        out.push_str(&format!("        require(OpCovOutputCount({cov_id}) == {});\n", observe.outputs.len()));
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
        for (idx, input) in observe.inputs.iter().enumerate() {
            let input_spec = observed_input_spec(actor, entry, observe, input, model)?;
            let input_idx = hidden_observed_input_idx_name(&observe.name, &input.name);
            let state_name = hidden_observed_input_state_name(&observe.name, &input.name);
            let state_struct = contract_state_type_for_observed_actor(actor, entry, observe, input, model)?;
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {input_idx} = OpCovInputIdx({cov_id}, {idx})"),
                &format!("observed input {}.{}: {}", observe.name, input.name, input.actor),
            );
            push_generated_call(
                out,
                8,
                &format!("{state_struct} {state_name} = "),
                "readInputStateWithTemplate",
                &[
                    input_idx,
                    hidden_observed_actor_prefix_len_name(&input_spec),
                    hidden_observed_actor_suffix_len_name(&input_spec),
                    observed_actor_template_expr_for_entry(actor, entry, model, observe, input, &input_spec)?,
                ],
            );
        }
        for (idx, output) in observe.outputs.iter().enumerate() {
            let output_idx = hidden_observed_output_idx_name(&observe.name, &output.name);
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {output_idx} = OpCovOutputIdx({cov_id}, {idx})"),
                &format!("observed output {}.{}: {}", observe.name, output.name, output.actor),
            );
        }
    }
    out.push('\n');
    Ok(())
}

fn lower_entry_expr(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>, expr: &str, expected_ty: Option<&str>) -> Result<String> {
    BodyLowerer::new(actor, entry, model)?.lower_expr(expr, expected_ty, 8)
}

fn state_payload_digest_expr(state_name: &str, value_expr: &str, model: &Model<'_>) -> Result<String> {
    Ok(format!("blake2b({})", state_payload_bytes_expr(state_name, value_expr, model)?))
}

fn state_payload_bytes_expr(state_name: &str, value_expr: &str, model: &Model<'_>) -> Result<String> {
    state_packed_bytes_expr(state_name, model, |field, _, _| packed_field_expr(&field.ty, &format!("{value_expr}.{}", field.name)))
}

fn state_packed_bytes_expr<F>(state_name: &str, model: &Model<'_>, mut field_expr: F) -> Result<String>
where
    F: FnMut(&FieldDecl, usize, usize) -> Result<String>,
{
    let state = model.state(state_name)?;
    let mut offset = 0usize;
    let mut parts = Vec::with_capacity(state.fields.len());
    for field in &state.fields {
        let len = packed_field_len(&field.ty)?;
        parts.push(field_expr(field, offset, len)?);
        offset += len;
    }
    Ok(parts.join(" + "))
}

fn state_packed_len(state_name: &str, model: &Model<'_>) -> Result<usize> {
    model.state(state_name)?.fields.iter().try_fold(0usize, |sum, field| packed_field_len(&field.ty).map(|len| sum + len))
}

fn packed_field_expr(ty: &TypeRef, expr: &str) -> Result<String> {
    if ty.is_actor_type() {
        return Ok(format!("byte[]({expr})"));
    }
    match (ty.name.as_str(), ty.array) {
        ("int", None) => Ok(format!("byte[8]({expr})")),
        ("bool", None) | ("byte", None) => Ok(format!("byte[1]({expr})")),
        ("byte", Some(_)) | ("pubkey", None) | (word::COVENANT_ID, None) | ("sig", None) | ("datasig", None) => {
            Ok(format!("byte[]({expr})"))
        }
        ("bytes", None) | ("string", None) | (_, Some(_)) => {
            Err(ArgentError::new(format!("cannot pack field `{expr}` with unsupported variable or array type")))
        }
        (name, None) => Err(ArgentError::new(format!("cannot digest field `{expr}` of unsupported type `{name}`"))),
    }
}

fn unpack_packed_field_expr(ty: &TypeRef, slice_expr: &str) -> Result<String> {
    if ty.is_actor_type() {
        return Ok(format!("byte[32]({slice_expr})"));
    }
    match (ty.name.as_str(), ty.array) {
        ("int", None) => Ok(format!("OpBin2Num({slice_expr})")),
        ("bool", None) => Ok(format!("OpBin2Num({slice_expr}) != 0")),
        ("byte", None) => Ok(format!("byte({slice_expr})")),
        ("byte", Some(len)) => Ok(format!("byte[{len}]({slice_expr})")),
        ("pubkey", None) | (word::COVENANT_ID, None) => Ok(format!("byte[32]({slice_expr})")),
        ("sig", None) => Ok(format!("byte[65]({slice_expr})")),
        ("datasig", None) => Ok(format!("byte[64]({slice_expr})")),
        ("bytes", None) | ("string", None) | (_, Some(_)) => {
            Err(ArgentError::new(format!("cannot unpack unsupported variable or array field from `{slice_expr}`")))
        }
        (name, None) => Err(ArgentError::new(format!("cannot unpack unsupported type `{name}` from `{slice_expr}`"))),
    }
}

fn packed_field_len(ty: &TypeRef) -> Result<usize> {
    if ty.is_actor_type() {
        return Ok(32);
    }
    match (ty.name.as_str(), ty.array) {
        ("int", None) => Ok(8),
        ("bool", None) | ("byte", None) => Ok(1),
        ("byte", Some(len)) => Ok(len),
        ("pubkey", None) | (word::COVENANT_ID, None) => Ok(32),
        ("sig", None) => Ok(65),
        ("datasig", None) => Ok(64),
        ("bytes", None) | ("string", None) | (_, Some(_)) => Err(ArgentError::new("only fixed-width scalar fields are supported")),
        (name, None) => Err(ArgentError::new(format!("unsupported type `{name}`"))),
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
        out.push_str(&format!("        require(blake2b({table}) == {commitment});\n"));
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

fn lower_entry_body(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<String> {
    BodyLowerer::new(actor, entry, model)?.lower()
}

struct BodyLowerer<'a, 'm> {
    body: &'a str,
    tokens: Vec<Token>,
    pos: usize,
    actor: &'a ActorDecl,
    entry: &'a EntryDecl,
    model: &'m Model<'a>,
    types: BTreeMap<String, String>,
    source_types: BTreeMap<String, String>,
    selectors: BTreeMap<String, TemplateSelector>,
    materialized_selectors: BTreeSet<String>,
    input_names: BTreeSet<String>,
    output_names: BTreeSet<String>,
    observed_input_state_refs: Vec<(String, String)>,
    observed_output_fields: Vec<ObservedOutputFieldWitnessSpec>,
    validated_spawns: BTreeSet<String>,
    conditional_depth: usize,
}

impl<'a, 'm> BodyLowerer<'a, 'm> {
    fn new(actor: &'a ActorDecl, entry: &'a EntryDecl, model: &'m Model<'a>) -> Result<Self> {
        let tokens = lex(&entry.body)
            .map_err(|err| ArgentError::new(format!("failed to lex body for `{}::{}`: {}", actor.name, entry.name, err.message)))?;

        let mut types = BTreeMap::new();
        let mut source_types = BTreeMap::new();
        let expanded_digest_fields = state_expansion_digest_fields_for_state(&actor.state, model);
        for field in &model.storage_state(&actor.state)?.fields {
            if expanded_digest_fields.contains(field.name.as_str()) {
                continue;
            }
            types.insert(field.name.clone(), lower_type_ref(&field.ty, model));
            source_types.insert(field.name.clone(), source_type_ref(&field.ty));
        }
        if let Some(expansion) = model.state(&actor.state)?.expansion.as_ref() {
            for digest in &expansion.digests {
                source_types.insert(digest.field.clone(), digest.state.clone());
            }
        }
        for param in &entry.params {
            types.insert(param.name.clone(), lower_entry_param_type(actor, &param.ty, model));
            source_types.insert(param.name.clone(), source_type_ref(&param.ty));
        }
        for observe in &entry.observes {
            for (binding, state) in observed_open_bindings(observe) {
                types.insert(binding.to_string(), "byte[32]".to_string());
                source_types.insert(binding.to_string(), format!("{}<{state}>", word::ACTOR_TYPE));
            }
        }
        for spawn in &entry.spawns {
            types.insert(spawn.covenant.clone(), "byte[32]".to_string());
            source_types.insert(spawn.covenant.clone(), word::COVENANT_ID.to_string());
        }

        let mut input_names = BTreeSet::new();
        for consume in &entry.consumes {
            input_names.insert(consume.name.clone());
            types.insert(consume.name.clone(), contract_state_type_for_actor(&consume.actor, actor, model)?);
        }

        let mut output_names = BTreeSet::new();
        match &entry.emits {
            EmitSpec::None => {}
            EmitSpec::One { .. } => {
                output_names.insert("next".to_string());
            }
            EmitSpec::Outputs(outputs) => {
                output_names.extend(outputs.iter().map(|output| output.name.clone()));
            }
        }

        let observed_input_state_refs = entry
            .observes
            .iter()
            .flat_map(|observe| {
                observe.inputs.iter().map(|input| {
                    (
                        format!("{}.inputs.{}.state", observe.name, input.name),
                        hidden_observed_input_state_name(&observe.name, &input.name),
                    )
                })
            })
            .collect();

        let selectors = model.template_selectors_for_entry(actor, entry)?;
        let observed_output_fields = observed_output_field_witness_specs(actor, entry, model);

        Ok(Self {
            body: &entry.body,
            tokens,
            pos: 0,
            actor,
            entry,
            model,
            types,
            source_types,
            selectors,
            materialized_selectors: BTreeSet::new(),
            input_names,
            output_names,
            observed_input_state_refs,
            observed_output_fields,
            validated_spawns: BTreeSet::new(),
            conditional_depth: 0,
        })
    }

    fn lower(mut self) -> Result<String> {
        let mut out = String::new();
        self.lower_statements(&mut out, 8, None)?;
        if out.trim().is_empty() {
            out.push_str("        require(1 == 1);\n");
        }
        for spawn in &self.entry.spawns {
            if !self.validated_spawns.contains(&spawn.name) {
                return Err(
                    self.error(format!("spawn `{}` must be validated with `require {}.outputs become`", spawn.name, spawn.name))
                );
            }
        }
        Ok(out)
    }

    fn lower_statements(&mut self, out: &mut String, indent: usize, end: Option<char>) -> Result<()> {
        while !self.is_eof() && !end.is_some_and(|symbol| self.check_symbol(symbol)) {
            if self.consume_ident(word::IF) {
                self.lower_if(out, indent)?;
            } else if self.consume_ident(word::BECOME) {
                self.lower_become(out, indent)?;
            } else if self.check_outputs_become_start() {
                self.lower_outputs_become(out, indent)?;
            } else if self.check_symbol(';') {
                self.advance();
            } else {
                self.lower_plain_statement(out, indent)?;
            }
        }
        Ok(())
    }

    fn lower_if(&mut self, out: &mut String, indent: usize) -> Result<()> {
        self.lower_if_inner(out, indent, true)
    }

    fn lower_if_inner(&mut self, out: &mut String, indent: usize, push_leading_indent: bool) -> Result<()> {
        self.expect_symbol('(')?;
        let condition = self.take_balanced_expr('(', ')')?;
        self.expect_symbol('{')?;

        if push_leading_indent {
            push_indent(out, indent);
        }
        out.push_str(&format!("if ({}) {{\n", self.lower_expr(&condition, None, indent)?));
        self.conditional_depth += 1;
        self.lower_statements(out, indent + 4, Some('}'))?;
        self.conditional_depth -= 1;
        self.expect_symbol('}')?;
        push_indent(out, indent);
        out.push('}');

        if self.consume_ident(word::ELSE) {
            if self.consume_ident(word::IF) {
                out.push_str(" else ");
                self.lower_if_inner(out, indent, false)?;
                return Ok(());
            }
            self.expect_symbol('{')?;
            out.push_str(" else {\n");
            self.conditional_depth += 1;
            self.lower_statements(out, indent + 4, Some('}'))?;
            self.conditional_depth -= 1;
            self.expect_symbol('}')?;
            push_indent(out, indent);
            out.push('}');
        }
        out.push('\n');
        Ok(())
    }

    fn lower_plain_statement(&mut self, out: &mut String, indent: usize) -> Result<()> {
        let statement = self.take_until_semicolon()?;
        if let Some((source_ty, name, expr)) = parse_typed_local_statement(&statement) {
            if let Some(state) = parse_actor_type(source_ty) {
                self.lower_actor_type_statement(out, indent, state, name, expr)?;
                return Ok(());
            }
            let ty = self.lower_local_type(source_ty);
            let lowered = self.lower_typed_local_initializer(source_ty, &ty, expr, indent)?;
            self.types.insert(name.to_string(), ty.clone());
            self.source_types.insert(name.to_string(), source_ty.to_string());

            push_indent(out, indent);
            out.push_str(&format!("{ty} {name} = {lowered};\n"));
            return Ok(());
        }

        if let Some(require_expr) = parse_require_statement(&statement) {
            for covenant_id in co_spent_covenant_ids(require_expr, &self.source_types)? {
                push_indent(out, indent);
                out.push_str(&format!("// :: co-spent with {}\n", covenant_id.trim()));
            }
        }

        push_indent(out, indent);
        out.push_str(&self.lower_expr(&statement, None, indent)?);
        out.push_str(";\n");
        Ok(())
    }

    fn lower_actor_type_statement(&mut self, out: &mut String, indent: usize, state: &str, name: &str, expr: &str) -> Result<()> {
        let selector = self
            .selectors
            .get(name)
            .ok_or_else(|| ArgentError::new(format!("actor handle `{name}` must be initialized as `ActorEnum[selector]`")))?
            .clone();
        if selector.state != state {
            return Err(ArgentError::new(format!(
                "actor handle `{name}` is declared as {actor_type}<{state}>, but `{}` contains {actor_type}<{}>",
                selector.actor_enum,
                selector.state,
                actor_type = word::ACTOR_TYPE,
            )));
        }
        self.validate_actor_type_initializer(name, expr, &selector)?;
        self.ensure_selector_template(out, indent, name)?;
        Ok(())
    }

    fn validate_actor_type_initializer(&self, name: &str, expr: &str, selector: &TemplateSelector) -> Result<()> {
        if let Some((actor_enum, _)) = parse_actor_enum_selector(expr) {
            if actor_enum != selector.actor_enum {
                return Err(ArgentError::new(format!(
                    "actor handle `{name}` was analyzed as `{}`, but lowers from `{actor_enum}`",
                    selector.actor_enum
                )));
            }
            return Ok(());
        }
        if let Some((actor_enum, _)) = parse_actor_enum_variant(expr) {
            if actor_enum != selector.actor_enum {
                return Err(ArgentError::new(format!(
                    "actor handle `{name}` was analyzed as `{}`, but lowers from `{actor_enum}`",
                    selector.actor_enum
                )));
            }
            return Ok(());
        }
        Err(ArgentError::new(format!("actor handle `{name}` must be initialized as `ActorEnum[selector]` or `ActorEnum::Variant`")))
    }

    fn ensure_selector_template(&mut self, out: &mut String, indent: usize, selector_name: &str) -> Result<String> {
        let template_var = hidden_template_selector_template_name(selector_name);
        if !self.materialized_selectors.insert(selector_name.to_string()) {
            return Ok(template_var);
        }
        let selector = self
            .selectors
            .get(selector_name)
            .ok_or_else(|| ArgentError::new(format!("unknown actor handle `{selector_name}`")))?
            .clone();
        let family = self.selector_family(&selector)?;
        if family.table_actors() != selector.variants.as_slice() {
            return Err(ArgentError::new(format!(
                "actor enum `{}` order must match route family `{}` table order for selector lowering",
                selector.actor_enum, family.id
            )));
        }

        let selector_var = hidden_template_selector_index_name(selector_name);
        let selector_expr = self.lower_expr(&selector.selector_expr, None, indent)?;
        let table = hidden_route_family_table_name(family);
        push_indent(out, indent);
        out.push_str(&format!("int {selector_var} = {selector_expr};\n"));
        push_indent(out, indent);
        out.push_str(&format!("require({selector_var} >= 0);\n"));
        push_indent(out, indent);
        out.push_str(&format!("require({selector_var} < {});\n", selector.variants.len()));
        push_generated_call(
            out,
            indent,
            &format!("byte[32] {template_var} = "),
            "byte[32]",
            &[format!("{table}.slice({selector_var} * 32, {selector_var} * 32 + 32)")],
        );
        Ok(template_var)
    }

    fn lower_become(&mut self, out: &mut String, indent: usize) -> Result<()> {
        let routes = self.parse_become_routes()?;
        for route in routes {
            self.lower_route(out, indent, route)?;
        }
        Ok(())
    }

    fn parse_become_routes(&mut self) -> Result<Vec<RouteCall>> {
        if self.consume_symbol('{') {
            let mut routes = Vec::new();
            while !self.check_symbol('}') && !self.is_eof() {
                routes.push(self.parse_become_route()?);
                self.consume_symbol(';');
            }
            self.expect_symbol('}')?;
            self.consume_symbol(';');
            return Ok(routes);
        }

        let route = self.parse_become_route()?;
        self.consume_symbol(';');
        Ok(vec![route])
    }

    fn parse_become_route(&mut self) -> Result<RouteCall> {
        let start = self.current().span.start;
        let first = self.expect_any_ident()?;
        let (output, actor) = if self.consume_left_arrow() {
            (Some(first), self.take_route_actor_expr()?)
        } else {
            (None, self.take_route_actor_expr_from(start)?)
        };
        self.expect_symbol('(')?;
        let state = self.take_balanced_expr('(', ')')?;
        Ok(RouteCall { output, actor, state })
    }

    fn take_route_actor_expr(&mut self) -> Result<String> {
        let start = self.current().span.start;
        self.take_route_actor_expr_from(start)
    }

    fn take_route_actor_expr_from(&mut self, start: usize) -> Result<String> {
        let mut depth = 0usize;
        while !self.is_eof() {
            let token = self.current().clone();
            match token.kind {
                TokenKind::Symbol('(') if depth == 0 => {
                    let expr = self.body[start..token.span.start].trim().to_string();
                    if expr.is_empty() {
                        return Err(self.error("become target is empty"));
                    }
                    return Ok(expr);
                }
                TokenKind::Symbol('{') | TokenKind::Symbol('[') | TokenKind::Symbol('<') => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol('}') | TokenKind::Symbol(']') | TokenKind::Symbol('>') => {
                    depth = depth.saturating_sub(1);
                    self.advance();
                }
                _ => self.advance(),
            }
        }
        Err(self.error("unterminated become target"))
    }

    fn lower_outputs_become(&mut self, out: &mut String, indent: usize) -> Result<()> {
        self.expect_ident(word::REQUIRE)?;
        let observe_name = self.expect_any_ident()?;
        self.expect_symbol('.')?;
        self.expect_ident(word::OUTPUTS)?;
        self.expect_ident(word::BECOME)?;
        let routes = self.parse_become_routes()?;

        if let Some(spawn) = self.entry.spawns.iter().find(|spawn| spawn.name == observe_name) {
            if self.conditional_depth != 0 {
                return Err(self.error(format!("spawn `{observe_name}` output validation must be unconditional")));
            }
            if !self.validated_spawns.insert(observe_name.clone()) {
                return Err(self.error(format!("spawn `{observe_name}` outputs are validated more than once")));
            }
            return self.lower_spawn_outputs_become(out, indent, spawn, routes);
        }

        let observe = self
            .entry
            .observes
            .iter()
            .find(|observe| observe.name == observe_name)
            .ok_or_else(|| self.error(format!("unknown observe `{observe_name}`")))?;
        let outputs_by_name = observe.outputs.iter().map(|output| (output.name.as_str(), output)).collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();

        for route in routes {
            let Some(handle) = route.output.as_deref() else {
                return Err(self.error(format!("observed output route to `{}` is missing an output handle", route.actor)));
            };
            let Some(observed_output) = outputs_by_name.get(handle).copied() else {
                return Err(self.error(format!("observe `{observe_name}` has no output `{handle}`")));
            };
            if !seen.insert(handle.to_string()) {
                return Err(self.error(format!("observe `{observe_name}` validates output `{handle}` more than once")));
            }
            if route.actor != observed_output.actor {
                return Err(self.error(format!(
                    "observe `{observe_name}` output `{handle}` expects `{}`, but route uses `{}`",
                    observed_output.actor, route.actor
                )));
            }
            self.lower_observed_output_route(out, indent, &observe_name, observed_output, route)?;
        }

        for observed_output in &observe.outputs {
            if !seen.contains(&observed_output.name) {
                return Err(self.error(format!("observe `{observe_name}` does not validate output `{}`", observed_output.name)));
            }
        }
        Ok(())
    }

    fn lower_spawn_outputs_become(
        &mut self,
        out: &mut String,
        indent: usize,
        spawn: &SpawnDecl,
        routes: Vec<RouteCall>,
    ) -> Result<()> {
        let outputs_by_name = spawn.outputs.iter().map(|output| (output.name.as_str(), output)).collect::<BTreeMap<_, _>>();
        let mut seen = BTreeSet::new();

        for route in routes {
            let Some(handle) = route.output.as_deref() else {
                return Err(self.error(format!("spawned output route to `{}` is missing an output handle", route.actor)));
            };
            let Some(spawned_output) = outputs_by_name.get(handle).copied() else {
                return Err(self.error(format!("spawn `{}` has no output `{handle}`", spawn.name)));
            };
            if !seen.insert(handle.to_string()) {
                return Err(self.error(format!("spawn `{}` validates output `{handle}` more than once", spawn.name)));
            }
            if route.actor != spawned_output.actor {
                return Err(self.error(format!(
                    "spawn `{}` output `{handle}` expects `{}`, but route uses `{}`",
                    spawn.name, spawned_output.actor, route.actor
                )));
            }
            self.lower_spawn_output_route(out, indent, spawn, spawned_output, route)?;
        }

        for output in &spawn.outputs {
            if !seen.contains(&output.name) {
                return Err(self.error(format!("spawn `{}` does not validate output `{}`", spawn.name, output.name)));
            }
        }
        Ok(())
    }

    fn lower_spawn_output_route(
        &mut self,
        out: &mut String,
        indent: usize,
        spawn: &SpawnDecl,
        output: &SpawnOutputDecl,
        route: RouteCall,
    ) -> Result<()> {
        let state_name = source_actor_type_state_for_expr(&output.actor, self.actor, self.entry, self.model)?
            .expect("spawn target actor_type checked during model validation");
        let state_ty = if state_name == self.actor.state { "State".to_string() } else { state_name };
        let state_expr = route.state.trim();
        let state_arg = if self.types.get(state_expr).is_some_and(|ty| ty == &state_ty) {
            self.lower_expr(state_expr, Some(&state_ty), indent)?
        } else {
            let name = generated_state_name(&route, &state_ty);
            let lowered = self.lower_expr(state_expr, Some(&state_ty), indent)?;
            push_indent(out, indent);
            out.push_str(&format!("{state_ty} {name} = {lowered};\n"));
            name
        };
        let source = clause_actor_type_ref(&output.actor, self.actor, self.entry, self.model)?
            .expect("spawn target actor_type checked during model validation");
        let spec =
            SpawnActorWitnessSpec { spawn: spawn.name.clone(), handle: output.name.clone(), actor: output.actor.clone(), source };
        let template = self.lower_expr(&output.actor, Some("byte[32]"), indent)?;

        push_indent(out, indent);
        out.push_str(&format!("// :: spawned become {}.{} -> {}\n", spawn.name, output.name, output.actor));
        push_generated_call(
            out,
            indent,
            "",
            "validateOutputStateWithTemplate",
            &[
                hidden_spawn_output_idx_name(&spawn.name, &output.name),
                state_arg,
                hidden_spawn_actor_prefix_name(&spec),
                hidden_spawn_actor_suffix_name(&spec),
                template,
            ],
        );
        Ok(())
    }

    fn lower_observed_output_route(
        &mut self,
        out: &mut String,
        indent: usize,
        observe_name: &str,
        observed_output: &ObservedActorDecl,
        route: RouteCall,
    ) -> Result<()> {
        let observe = self.entry.observes.iter().find(|observe| observe.name == observe_name).expect("observe checked by caller");
        let state_ty = contract_state_type_for_observed_actor(self.actor, self.entry, observe, observed_output, self.model)?;
        let state_expr = route.state.trim();
        let state_arg = if self.types.get(state_expr).is_some_and(|ty| ty == &state_ty) {
            self.lower_expr(state_expr, Some(&state_ty), indent)?
        } else {
            let name = generated_state_name(&route, &state_ty);
            let lowered = self.lower_expr(state_expr, Some(&state_ty), indent)?;
            push_indent(out, indent);
            out.push_str(&format!("{state_ty} {name} = {lowered};\n"));
            name
        };

        let spec = observed_output_spec(self.actor, self.entry, observe, observed_output, self.model)?;
        let output_idx = hidden_observed_output_idx_name(observe_name, &observed_output.name);

        push_indent(out, indent);
        out.push_str(&format!("// :: observed become {}.{} -> {}\n", observe_name, observed_output.name, observed_output.actor));
        if observed_reuses_input_template(observe, observed_output) {
            let input = first_observed_input_for_actor(observe, &observed_output.actor)
                .expect("input-template reuse requires a matching observed input");
            let input_spec = observed_input_spec(self.actor, self.entry, observe, input, self.model)?;
            push_generated_call(
                out,
                indent,
                "",
                "validateOutputStateWithInputTemplate",
                &[
                    output_idx,
                    state_arg,
                    hidden_observed_input_idx_name(observe_name, &input.name),
                    hidden_observed_actor_prefix_len_name(&input_spec),
                    hidden_observed_actor_suffix_len_name(&input_spec),
                    self.observed_actor_template_expr(observe, observed_output, &spec, indent)?,
                ],
            );
        } else {
            push_generated_call(
                out,
                indent,
                "",
                "validateOutputStateWithTemplate",
                &[
                    output_idx,
                    state_arg,
                    hidden_observed_actor_prefix_name(&spec),
                    hidden_observed_actor_suffix_name(&spec),
                    self.observed_actor_template_expr(observe, observed_output, &spec, indent)?,
                ],
            );
        }
        Ok(())
    }

    fn observed_actor_template_expr(
        &self,
        observe: &ObserveDecl,
        observed: &ObservedActorDecl,
        spec: &ObservedActorWitnessSpec,
        indent: usize,
    ) -> Result<String> {
        if observed_is_dynamic_binding(observe, observed) {
            return Ok(observed.actor.clone());
        }
        if observed_is_source_actor_type(self.actor, self.entry, observed, self.model)? {
            return self.lower_expr(&observed.actor, Some("byte[32]"), indent);
        }
        Ok(hidden_observed_actor_template_name(spec))
    }

    fn lower_route(&mut self, out: &mut String, indent: usize, route: RouteCall) -> Result<()> {
        if self.selectors.contains_key(&route.actor) {
            return self.lower_selector_route(out, indent, route);
        }
        self.model.actor_state(&route.actor)?;
        let output_idx = route.output.as_ref().map_or_else(hidden_next_output_idx_name, |output| hidden_output_idx_name(output));
        let validation = route_validation_kind(self.actor, &route);

        if validation == RouteValidationKind::ExactScriptPublicKey {
            push_indent(out, indent);
            out.push_str(&format!("// :: become {}\n", route.actor));
            push_generated_binary_require(
                out,
                indent,
                &format!("tx.outputs[{output_idx}].scriptPubKey"),
                "==",
                "tx.inputs[this.activeInputIndex].scriptPubKey",
            );
            return Ok(());
        }

        let state_ty = contract_state_type_for_actor(&route.actor, self.actor, self.model)?;
        let state_expr = route.state.trim();
        let state_arg = if self.types.get(state_expr).is_some_and(|ty| ty == &state_ty) {
            self.lower_expr(state_expr, Some(&state_ty), indent)?
        } else {
            let name = generated_state_name(&route, &state_ty);
            let lowered = self.lower_expr(state_expr, Some(&state_ty), indent)?;
            push_indent(out, indent);
            out.push_str(&format!("{state_ty} {name} = {lowered};\n"));
            name
        };

        push_indent(out, indent);
        out.push_str(&format!("// :: become {}\n", route.actor));
        match validation {
            RouteValidationKind::ExactScriptPublicKey => unreachable!("exact continuation returned before state lowering"),
            RouteValidationKind::SameTemplate => {
                push_generated_call(out, indent, "", "validateOutputState", &[output_idx, state_arg]);
            }
            RouteValidationKind::ForeignTemplate => {
                let template = hidden_template_name(&route.actor);
                if let Some(input) = self.entry.consumes.iter().find(|input| input.actor == route.actor) {
                    push_generated_call(
                        out,
                        indent,
                        "",
                        "validateOutputStateWithInputTemplate",
                        &[
                            output_idx,
                            state_arg,
                            hidden_input_idx_name(&input.name),
                            hidden_witness_prefix_len_name(&route.actor),
                            hidden_witness_suffix_len_name(&route.actor),
                            template,
                        ],
                    );
                } else {
                    push_generated_call(
                        out,
                        indent,
                        "",
                        "validateOutputStateWithTemplate",
                        &[
                            output_idx,
                            state_arg,
                            hidden_witness_prefix_name(&route.actor),
                            hidden_witness_suffix_name(&route.actor),
                            template,
                        ],
                    );
                }
            }
        }
        Ok(())
    }

    fn lower_selector_route(&mut self, out: &mut String, indent: usize, route: RouteCall) -> Result<()> {
        let selector = self
            .selectors
            .get(&route.actor)
            .ok_or_else(|| ArgentError::new(format!("unknown actor handle `{}`", route.actor)))?
            .clone();
        let output_idx = route.output.as_ref().map_or_else(hidden_next_output_idx_name, |output| hidden_output_idx_name(output));
        let state_ty = if selector.state == self.actor.state { "State".to_string() } else { selector.state.clone() };
        let state_expr = route.state.trim();
        let state_arg = if self.types.get(state_expr).is_some_and(|ty| ty == &state_ty) {
            self.lower_expr(state_expr, Some(&state_ty), indent)?
        } else {
            let name = generated_state_name(&route, &state_ty);
            let lowered = self.lower_expr(state_expr, Some(&state_ty), indent)?;
            push_indent(out, indent);
            out.push_str(&format!("{state_ty} {name} = {lowered};\n"));
            name
        };

        let template = self.ensure_selector_template(out, indent, &route.actor)?;
        push_indent(out, indent);
        out.push_str(&format!("// :: become {}\n", route.actor));
        push_generated_call(
            out,
            indent,
            "",
            "validateOutputStateWithTemplate",
            &[
                output_idx,
                state_arg,
                hidden_template_selector_prefix_name(&route.actor),
                hidden_template_selector_suffix_name(&route.actor),
                template,
            ],
        );
        Ok(())
    }

    fn selector_family(&self, selector: &TemplateSelector) -> Result<&RouteFamily> {
        self.model
            .route_families_for_state(&selector.state)
            .into_iter()
            .find(|family| selector.variants.iter().all(|variant| family.table_actors().contains(variant)))
            .ok_or_else(|| {
                ArgentError::new(format!(
                    "actor enum `{}` variants are not available as a selector table for state `{}`",
                    selector.actor_enum, selector.state
                ))
            })
    }

    fn lower_expr(&self, expr: &str, expected_ty: Option<&str>, indent: usize) -> Result<String> {
        let expr = expr.trim();
        if let Some(domain) = parse_unique_self_outpoint(expr) {
            return Ok(format!(
                "blake2b(bytes(\"{domain}\") + OpOutpointTxId(this.activeInputIndex) + byte[4](OpOutpointIndex(this.activeInputIndex)))"
            ));
        }
        if expr == "self.state" {
            let ty = expected_ty.ok_or_else(|| ArgentError::new("`self.state` requires a target state type during lowering"))?;
            return self.lower_self_state_expr(ty, indent);
        }
        if let Some(value) = parse_digest_call(expr) {
            return self.lower_digest_expr(value);
        }
        if let Some((state_name, body)) = split_state_constructor(expr) {
            return self.lower_state_constructor(state_name, body, indent);
        }
        self.lower_refs(expr)
    }

    fn lower_self_state_expr(&self, ty: &str, indent: usize) -> Result<String> {
        let state_name = if ty == "State" { &self.actor.state } else { ty };
        let fields = self
            .model
            .storage_state(state_name)?
            .fields
            .iter()
            .map(|field| (field.name.clone(), field.name.clone()))
            .collect::<Vec<_>>();
        self.render_state_object_for_state(state_name, &fields, indent)
    }

    fn lower_state_constructor(&self, state_name: &str, body: &str, indent: usize) -> Result<String> {
        self.model.state(state_name)?;
        self.lower_state_object_for_state(state_name, body, indent)
    }

    fn lower_digest_expr(&self, value: &str) -> Result<String> {
        let value = value.trim();
        let state_name = self.source_types.get(value).ok_or_else(|| {
            ArgentError::new(format!("`digest(...)` requires a named state value, but `{value}` has no known source type"))
        })?;
        self.model.state(state_name)?;
        state_payload_digest_expr(state_name, value, self.model)
    }

    fn lower_typed_local_initializer(&self, source_ty: &str, lowered_ty: &str, expr: &str, indent: usize) -> Result<String> {
        if self.model.actor_enums.contains_key(source_ty) {
            return self.lower_actor_enum_initializer(source_ty, expr, indent);
        }
        if let Some(state_name) = self.source_state_for_local_type(source_ty)
            && let Some(body) = split_state_object_literal(expr)
        {
            return self.lower_state_object_for_state(&state_name, body, indent);
        }
        self.lower_expr(expr, Some(lowered_ty), indent)
    }

    fn lower_actor_enum_initializer(&self, actor_enum_name: &str, expr: &str, indent: usize) -> Result<String> {
        if let Some((source_actor_enum, selector_expr)) = parse_actor_enum_selector(expr) {
            if source_actor_enum != actor_enum_name {
                return Err(ArgentError::new(format!(
                    "actor enum value `{actor_enum_name}` cannot be initialized from `{source_actor_enum}`"
                )));
            }
            return self.lower_expr(selector_expr, Some("int"), indent);
        }
        if let Some((source_actor_enum, variant)) = parse_actor_enum_variant(expr) {
            if source_actor_enum != actor_enum_name {
                return Err(ArgentError::new(format!(
                    "actor enum value `{actor_enum_name}` cannot be initialized from `{source_actor_enum}`"
                )));
            }
            let actor_enum = self
                .model
                .actor_enums
                .get(actor_enum_name)
                .ok_or_else(|| ArgentError::new(format!("unknown actor enum `{actor_enum_name}`")))?;
            let value = actor_enum_variant_const_expr(actor_enum, &variant)
                .ok_or_else(|| ArgentError::new(format!("actor enum `{actor_enum_name}` has no variant `{variant}`")))?;
            return Ok(value);
        }
        self.lower_expr(expr, Some("int"), indent)
    }

    fn lower_state_object_for_state(&self, state_name: &str, body: &str, indent: usize) -> Result<String> {
        self.model.state(state_name)?;
        let raw_fields = parse_state_fields(body);
        if self.model.state(state_name)?.expansion.is_some() {
            return self.render_expanded_state_object_for_state(state_name, &raw_fields, indent);
        }
        let fields = raw_fields
            .into_iter()
            .map(|(name, expr)| self.lower_expr(&expr, None, indent + 4).map(|lowered| (name, lowered)))
            .collect::<Result<Vec<_>>>()?;
        self.render_state_object_for_state(state_name, &fields, indent)
    }

    fn lower_local_type(&self, source_ty: &str) -> String {
        if self.model.actor_enums.contains_key(source_ty) {
            return "int".to_string();
        }
        if source_ty == word::COVENANT_ID {
            return "byte[32]".to_string();
        }
        let same_storage = match (self.model.storage_state_name(&self.actor.state), self.model.storage_state_name(source_ty)) {
            (Ok(current_storage), Ok(source_storage)) => current_storage == source_storage,
            _ => false,
        };
        if source_ty == self.actor.state || same_storage { "State".to_string() } else { source_ty.to_string() }
    }

    fn source_state_for_local_type(&self, source_ty: &str) -> Option<String> {
        if source_ty == "State" {
            Some(self.actor.state.clone())
        } else if self.model.states.contains_key(source_ty) {
            Some(source_ty.to_string())
        } else {
            None
        }
    }

    fn render_state_object_for_state(&self, state_name: &str, fields: &[(String, String)], indent: usize) -> Result<String> {
        if self.model.state(state_name)?.expansion.is_some() {
            return self.render_expanded_state_object_for_state(state_name, fields, indent);
        }

        let field_indent = " ".repeat(indent + 4);
        let close_indent = " ".repeat(indent);
        let mut pending = fields.iter().cloned().collect::<BTreeMap<_, _>>();
        if pending.len() != fields.len() {
            return Err(ArgentError::new(format!("state `{state_name}` constructor contains duplicate fields")));
        }
        let mut out = String::new();
        out.push_str("{\n");
        let generated_fields = hidden_template_object_fields_for_state(&self.actor.state, state_name, self.model);
        out.push_str(&format!("{field_indent}// :: generated fields\n"));
        for (field, expr) in generated_fields {
            out.push_str(&format!("{field_indent}{field}: {expr},\n"));
        }
        out.push_str(&format!("\n{field_indent}// :: user declared fields\n"));
        for field in &self.model.storage_state(state_name)?.fields {
            let expr = if let Some(expr) = pending.remove(&field.name) {
                expr
            } else if field.virtual_slot {
                self.observed_output_field_expr(state_name, &field.name)?
            } else {
                return Err(ArgentError::new(format!("state `{state_name}` constructor is missing field `{}`", field.name)));
            };
            out.push_str(&format!("{field_indent}{}: {expr},\n", field.name));
        }
        if let Some(extra) = pending.keys().next() {
            return Err(ArgentError::new(format!("state `{state_name}` constructor has unknown field `{extra}`")));
        }
        out.push_str(&close_indent);
        out.push('}');
        Ok(out)
    }

    fn observed_output_field_expr(&self, state_name: &str, field_name: &str) -> Result<String> {
        let matches =
            self.observed_output_fields.iter().filter(|spec| spec.state == state_name && spec.field == field_name).collect::<Vec<_>>();
        match matches.as_slice() {
            [spec] => Ok(hidden_observed_output_field_name(spec)),
            [] => Err(ArgentError::new(format!(
                "state `{state_name}` constructor is missing virtual slot `{field_name}`, but this entry has no observed output that can provide it"
            ))),
            _ => Err(ArgentError::new(format!(
                "state `{state_name}` constructor is missing virtual slot `{field_name}`, but multiple observed outputs could provide it"
            ))),
        }
    }

    fn render_expanded_state_object_for_state(&self, state_name: &str, fields: &[(String, String)], indent: usize) -> Result<String> {
        let state = self.model.state(state_name)?;
        let expansion = state.expansion.as_ref().ok_or_else(|| ArgentError::new(format!("state `{state_name}` is not expanded")))?;
        let storage_state = self.model.storage_state(state_name)?;
        let mut pending = fields.iter().cloned().collect::<BTreeMap<_, _>>();
        if pending.len() != fields.len() {
            return Err(ArgentError::new(format!("state `{state_name}` constructor contains duplicate fields")));
        }
        let field_indent = " ".repeat(indent + 4);
        let close_indent = " ".repeat(indent);
        let mut out = String::new();
        out.push_str("{\n");
        let generated_fields = hidden_template_object_fields_for_state(&self.actor.state, state_name, self.model);
        out.push_str(&format!("{field_indent}// :: generated fields\n"));
        for (field, expr) in generated_fields {
            out.push_str(&format!("{field_indent}{field}: {expr},\n"));
        }
        out.push_str(&format!("\n{field_indent}// :: user declared fields\n"));

        for field in &storage_state.fields {
            if let Some(digest) = expansion.digests.iter().find(|digest| digest.field == field.name) {
                let expr = pending.remove(&digest.field).ok_or_else(|| {
                    ArgentError::new(format!("state `{state_name}` constructor is missing expanded slot `{}`", digest.field))
                })?;
                if expr.trim() == digest.field {
                    out.push_str(&format!("{field_indent}{}: {},\n", field.name, digest.field));
                    continue;
                }
                let (slot_state, slot_body) = split_state_constructor(&expr).ok_or_else(|| {
                    ArgentError::new(format!(
                        "state `{state_name}` constructor slot `{}` must use `{} {{ ... }}`",
                        digest.field, digest.state
                    ))
                })?;
                if slot_state != digest.state {
                    return Err(ArgentError::new(format!(
                        "state `{state_name}` constructor slot `{}` expects `{}`, got `{slot_state}`",
                        digest.field, digest.state
                    )));
                }
                let mut slot_fields = parse_state_fields(slot_body).into_iter().collect::<BTreeMap<_, _>>();
                let payload = state_packed_bytes_expr(&digest.state, self.model, |memory_field, _, _| {
                    let expr = slot_fields.remove(&memory_field.name).ok_or_else(|| {
                        ArgentError::new(format!(
                            "state `{state_name}` constructor slot `{}` is missing field `{}`",
                            digest.field, memory_field.name
                        ))
                    })?;
                    let lowered = self.lower_expr(&expr, None, indent + 4)?;
                    packed_field_expr(&memory_field.ty, &lowered)
                })?;
                if let Some(extra) = slot_fields.keys().next() {
                    return Err(ArgentError::new(format!(
                        "state `{state_name}` constructor slot `{}` has unknown field `{extra}`",
                        digest.field
                    )));
                }
                out.push_str(&format!("{field_indent}{}: blake2b({payload}),\n", field.name));
            } else if field.virtual_slot {
                let raw_expr = pending.remove(&field.name).unwrap_or_else(|| field.name.clone());
                let expr = self.lower_expr(&raw_expr, None, indent + 4)?;
                out.push_str(&format!("{field_indent}{}: {expr},\n", field.name));
            } else {
                let raw_expr = pending
                    .remove(&field.name)
                    .ok_or_else(|| ArgentError::new(format!("state `{state_name}` constructor is missing field `{}`", field.name)))?;
                let expr = self.lower_expr(&raw_expr, None, indent + 4)?;
                out.push_str(&format!("{field_indent}{}: {expr},\n", field.name));
            }
        }
        if let Some(extra) = pending.keys().next() {
            return Err(ArgentError::new(format!("state `{state_name}` constructor has unknown field `{extra}`")));
        }
        out.push_str(&close_indent);
        out.push('}');
        Ok(out)
    }

    fn lower_refs(&self, expr: &str) -> Result<String> {
        let mut out = expr.replace("self.value", "tx.inputs[this.activeInputIndex].value");
        out = out.replace("self.covenant_id", "OpInputCovenantId(this.activeInputIndex)");
        for spec in state_expansion_witness_specs_for_actor(self.actor, self.model) {
            for field in &self.model.state(&spec.memory_state)?.fields {
                let local = hidden_state_expansion_field_name(&spec, &field.name);
                out = out.replace(&format!("self.{}.{}", spec.field, field.name), &local);
                out = out.replace(&format!("{}.{}", spec.field, field.name), &local);
            }
        }
        for field in &self.model.storage_state(&self.actor.state)?.fields {
            out = out.replace(&format!("self.{}", field.name), &field.name);
        }
        out = lower_co_spent_calls(&out, &self.source_types)?;
        for (source, lowered) in &self.observed_input_state_refs {
            out = out.replace(source, lowered);
        }
        for name in &self.input_names {
            out = out.replace(&format!("{name}.value"), &format!("tx.inputs[{}].value", hidden_input_idx_name(name)));
        }
        for name in &self.output_names {
            out = out.replace(&format!("{name}.value"), &format!("tx.outputs[{}].value", hidden_output_idx_name(name)));
        }
        lower_actor_enum_literals(&out, self.model)
    }

    fn take_until_semicolon(&mut self) -> Result<String> {
        let start = self.current().span.start;
        let mut depth = 0usize;
        while !self.is_eof() {
            let token = self.current().clone();
            match token.kind {
                TokenKind::Symbol('{') | TokenKind::Symbol('(') | TokenKind::Symbol('[') => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol('}') | TokenKind::Symbol(')') | TokenKind::Symbol(']') => {
                    depth = depth.saturating_sub(1);
                    self.advance();
                }
                TokenKind::Symbol(';') if depth == 0 => {
                    let text = self.body[start..token.span.start].trim().to_string();
                    self.advance();
                    return Ok(text);
                }
                _ => self.advance(),
            }
        }
        Err(self.error("unterminated statement"))
    }

    fn take_balanced_expr(&mut self, open: char, close: char) -> Result<String> {
        let start = self.current().span.start;
        let mut depth = 1usize;
        while !self.is_eof() {
            let token = self.current().clone();
            match token.kind {
                TokenKind::Symbol(symbol) if symbol == open => {
                    depth += 1;
                    self.advance();
                }
                TokenKind::Symbol(symbol) if symbol == close => {
                    depth -= 1;
                    if depth == 0 {
                        let text = self.body[start..token.span.start].trim().to_string();
                        self.advance();
                        return Ok(text);
                    }
                    self.advance();
                }
                _ => self.advance(),
            }
        }
        Err(self.error(format!("unterminated `{open}` group")))
    }

    fn expect_any_ident(&mut self) -> Result<String> {
        match self.current().kind.clone() {
            TokenKind::Ident(name) => {
                self.advance();
                Ok(name)
            }
            _ => Err(self.error("expected identifier")),
        }
    }

    fn expect_ident(&mut self, expected: &str) -> Result<()> {
        match &self.current().kind {
            TokenKind::Ident(actual) if actual == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `{expected}`"))),
        }
    }

    fn expect_symbol(&mut self, expected: char) -> Result<()> {
        match self.current().kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance();
                Ok(())
            }
            _ => Err(self.error(format!("expected `{expected}`"))),
        }
    }

    fn consume_ident(&mut self, expected: &str) -> bool {
        match &self.current().kind {
            TokenKind::Ident(actual) if actual == expected => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn consume_symbol(&mut self, expected: char) -> bool {
        match self.current().kind {
            TokenKind::Symbol(actual) if actual == expected => {
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn consume_left_arrow(&mut self) -> bool {
        match self.current().kind {
            TokenKind::LeftArrow => {
                self.advance();
                true
            }
            TokenKind::Symbol('<') if matches!(self.peek_kind(1), Some(TokenKind::Symbol('-'))) => {
                self.advance();
                self.advance();
                true
            }
            _ => false,
        }
    }

    fn check_symbol(&self, expected: char) -> bool {
        matches!(self.current().kind, TokenKind::Symbol(actual) if actual == expected)
    }

    fn check_outputs_become_start(&self) -> bool {
        matches!(&self.current().kind, TokenKind::Ident(actual) if actual == word::REQUIRE)
            && matches!(self.peek_kind(1), Some(TokenKind::Ident(_)))
            && matches!(self.peek_kind(2), Some(TokenKind::Symbol('.')))
            && matches!(self.peek_kind(3), Some(TokenKind::Ident(actual)) if actual == word::OUTPUTS)
            && matches!(self.peek_kind(4), Some(TokenKind::Ident(actual)) if actual == word::BECOME)
    }

    fn current(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn peek_kind(&self, offset: usize) -> Option<&TokenKind> {
        self.tokens.get(self.pos + offset).map(|token| &token.kind)
    }

    fn advance(&mut self) {
        if !self.is_eof() {
            self.pos += 1;
        }
    }

    fn is_eof(&self) -> bool {
        matches!(self.current().kind, TokenKind::Eof)
    }

    fn error(&self, message: impl Into<String>) -> ArgentError {
        ArgentError::new(format!(
            "{} in `{}::{}` at body byte {}",
            message.into(),
            self.actor.name,
            self.entry.name,
            self.current().span.start
        ))
    }
}

const GENERATED_SIL_LINE_LIMIT: usize = 100;

fn push_indent(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
}

fn push_entry_signature(out: &mut String, name: &str, params: &[String]) {
    let single = format!("    entrypoint function {name}({}) {{", params.join(", "));
    if single.len() <= GENERATED_SIL_LINE_LIMIT {
        out.push_str(&single);
        out.push('\n');
        return;
    }

    out.push_str(&format!("    entrypoint function {name}(\n"));
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

fn push_generated_call(out: &mut String, indent: usize, prefix: &str, function: &str, args: &[String]) {
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

fn push_generated_binary_require(out: &mut String, indent: usize, lhs: &str, op: &str, rhs: &str) {
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

fn generated_state_name(route: &RouteCall, state_ty: &str) -> String {
    let base = route.output.as_deref().unwrap_or(route.actor.as_str());
    format!("{RESERVED_GENERATED_PREFIX}state_{}_{}", to_snake(base), to_snake(state_ty))
}

fn parse_unique_self_outpoint(expr: &str) -> Option<String> {
    let expr = expr.trim();
    let rest = expr.strip_prefix("unique(")?.strip_suffix(')')?;
    let (domain, outpoint) = rest.split_once(',')?;
    if outpoint.trim() != "self.outpoint" {
        return None;
    }
    let domain = domain.trim();
    Some(domain.strip_prefix('"')?.strip_suffix('"')?.to_string())
}

fn split_state_constructor(expr: &str) -> Option<(&str, &str)> {
    let expr = expr.trim();
    let brace_idx = expr.find('{')?;
    let state_name = expr[..brace_idx].trim();
    if state_name.is_empty() || !state_name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        return None;
    }
    let body = expr[brace_idx + 1..].trim();
    let body = body.strip_suffix('}')?.trim();
    Some((state_name, body))
}

fn split_state_object_literal(expr: &str) -> Option<&str> {
    let expr = expr.trim();
    if !expr.starts_with('{') {
        return None;
    }
    expr.strip_prefix('{')?.strip_suffix('}').map(str::trim)
}

fn parse_digest_call(expr: &str) -> Option<&str> {
    let expr = expr.trim();
    expr.strip_prefix("digest(")?.strip_suffix(')').map(str::trim)
}

fn parse_typed_local_statement(statement: &str) -> Option<(&str, &str, &str)> {
    let (left, expr) = split_top_level_assignment(statement)?;
    let left = left.trim();
    let split_idx = left.char_indices().rev().find_map(|(idx, ch)| ch.is_whitespace().then_some(idx))?;
    let source_ty = left[..split_idx].trim();
    let name = left[split_idx..].trim();
    if source_ty.is_empty() || !is_identifier(name) {
        return None;
    }
    Some((source_ty, name, expr.trim()))
}

fn parse_actor_type(ty: &str) -> Option<&str> {
    let ty = ty.trim();
    ty.strip_prefix(word::ACTOR_TYPE)?.strip_prefix('<')?.strip_suffix('>').map(str::trim).filter(|state| is_identifier(state))
}

fn parse_actor_enum_selector(expr: &str) -> Option<(&str, &str)> {
    let expr = expr.trim();
    let (actor_enum, rest) = expr.split_once('[')?;
    let actor_enum = actor_enum.trim();
    if !is_identifier(actor_enum) {
        return None;
    }
    let selector = rest.strip_suffix(']')?.trim();
    if selector.is_empty() {
        return None;
    }
    Some((actor_enum, selector))
}

fn parse_actor_enum_variant(expr: &str) -> Option<(String, String)> {
    let expr = expr.trim();
    let (actor_enum, variant) = expr.split_once("::")?;
    let actor_enum = actor_enum.trim();
    let variant = variant.trim();
    if !is_identifier(actor_enum) || !is_identifier(variant) {
        return None;
    }
    Some((actor_enum.to_string(), variant.to_string()))
}

fn split_top_level_assignment(input: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                let prev = input[..idx].chars().next_back();
                let next = input[idx + ch.len_utf8()..].chars().next();
                if matches!(prev, Some('=' | '!' | '<' | '>')) || matches!(next, Some('=')) {
                    continue;
                }
                let left = input[..idx].trim();
                let right = input[idx + ch.len_utf8()..].trim();
                if !left.is_empty() && !right.is_empty() {
                    return Some((left, right));
                }
            }
            _ => {}
        }
    }
    None
}

fn is_identifier(input: &str) -> bool {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_') && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn parse_state_fields(body: &str) -> Vec<(String, String)> {
    split_top_level_commas(body)
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (name, expr) = split_top_level_colon(entry)?;
            Some((name.trim().to_string(), expr.trim().to_string()))
        })
        .collect()
}

fn split_top_level_colon(input: &str) -> Option<(&str, &str)> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => return Some((&input[..idx], &input[idx + 1..])),
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&input[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&input[start..]);
    parts
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
struct ObservedActorWitnessSpec {
    observe: String,
    side: ObservedActorSideArtifact,
    handle: String,
    actor: String,
    source: Option<ClauseActorTypeRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SpawnActorWitnessSpec {
    spawn: String,
    handle: String,
    actor: String,
    source: ClauseActorTypeRef,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StateExpansionWitnessSpec {
    state: String,
    field: String,
    memory_state: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObservedOutputFieldWitnessSpec {
    observe: String,
    handle: String,
    state: String,
    field: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryWitnessSpecs {
    templates: Vec<TemplateWitnessSpec>,
    families: Vec<RouteFamilyWitnessSpec>,
    selectors: Vec<TemplateSelectorWitnessSpec>,
    observed_actors: Vec<ObservedActorWitnessSpec>,
    spawn_outputs: Vec<SpawnActorWitnessSpec>,
    spawn_templates: Vec<SpawnActorWitnessSpec>,
    state_expansions: Vec<StateExpansionWitnessSpec>,
    observed_output_fields: Vec<ObservedOutputFieldWitnessSpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteValidationKind {
    ExactScriptPublicKey,
    SameTemplate,
    ForeignTemplate,
}

fn route_validation_kind(actor: &ActorDecl, route: &RouteCall) -> RouteValidationKind {
    if route.actor == actor.name && compact_expr(&route.state) == "self.state" {
        return RouteValidationKind::ExactScriptPublicKey;
    }

    // Concrete actor names denote one compiled template in the current Argent
    // model, so peer coordination does not by itself require a foreign-template
    // witness. Future generic/observed actor handles need their own identity
    // classifier instead of flowing through this named-actor shortcut.
    if route.actor == actor.name {
        return RouteValidationKind::SameTemplate;
    }

    RouteValidationKind::ForeignTemplate
}

fn lower_entry_params(actor: &ActorDecl, entry: &EntryDecl, witness_specs: &EntryWitnessSpecs, model: &Model<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for param in &entry.params {
        out.push(format!("{} {}", lower_entry_param_type(actor, &param.ty, model), param.name));
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
    for spec in &witness_specs.spawn_templates {
        out.push(format!("byte[] {}", hidden_spawn_actor_prefix_name(spec)));
        out.push(format!("byte[] {}", hidden_spawn_actor_suffix_name(spec)));
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
    let read_actors = entry.consumes.iter().map(|consume| consume.actor.clone()).collect::<BTreeSet<_>>();
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
    let write_actors = entry
        .routes
        .iter()
        .filter(|route| !selectors.contains_key(&route.actor))
        .filter(|route| route_validation_kind(actor, route) == RouteValidationKind::ForeignTemplate)
        .map(|route| route.actor.clone())
        .collect::<BTreeSet<_>>();
    let mut specs = template_witness_specs_for_actor(actor, model, read_actors, write_actors);
    specs.selectors = selector_specs;
    specs.observed_actors = observed_actor_witness_specs(actor, entry, model)?;
    specs.spawn_outputs = spawn_output_witness_specs(actor, entry, model)?;
    specs.spawn_templates = spawn_template_witness_specs(&specs.spawn_outputs);
    specs.state_expansions = state_expansion_witness_specs_for_actor(actor, model);
    specs.observed_output_fields = observed_output_field_witness_specs(actor, entry, model);
    Ok(specs)
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
    for spawn in &entry.spawns {
        for output in &spawn.outputs {
            let source = clause_actor_type_ref(&output.actor, actor, entry, model)?
                .expect("spawn target actor_type checked during model validation");
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

fn spawn_template_witness_specs(outputs: &[SpawnActorWitnessSpec]) -> Vec<SpawnActorWitnessSpec> {
    let mut seen = BTreeSet::new();
    outputs.iter().filter(|spec| seen.insert(spec.source.clone())).cloned().collect()
}

fn observed_output_field_witness_specs(
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
    let mut specs = template_witness_specs(model, read_actors, write_actors);
    let mut family_specs = BTreeMap::<String, RouteFamilyWitnessSpec>::new();
    for spec in &mut specs {
        spec.source = template_source_for_actor(&actor.state, &spec.actor, model);
        if let Some(family) = model.route_family_for_actor(&spec.actor)
            && actor.state != family.state
            && route_leaves_contain_family(model.route_leaves_for_state(&actor.state), &family.id)
        {
            family_specs
                .entry(family.id.clone())
                .or_insert(RouteFamilyWitnessSpec { family_id: family.id.clone(), byte_len: family.table_byte_len() });
        }
    }
    EntryWitnessSpecs {
        templates: specs,
        families: family_specs.into_values().collect(),
        selectors: Vec::new(),
        observed_actors: Vec::new(),
        spawn_outputs: Vec::new(),
        spawn_templates: Vec::new(),
        state_expansions: Vec::new(),
        observed_output_fields: Vec::new(),
    }
}

fn state_expansion_witness_specs_for_actor(actor: &ActorDecl, model: &Model<'_>) -> Vec<StateExpansionWitnessSpec> {
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

fn state_expansion_digest_fields_for_state(state_name: &str, model: &Model<'_>) -> BTreeSet<String> {
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
    for actor in &model.template_actors {
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

fn observed_template_specs_for_state(state: &str, model: &Model<'_>) -> Vec<ObservedActorWitnessSpec> {
    let mut seen = BTreeSet::new();
    let mut specs = Vec::new();
    for actor in &model.actors {
        if actor.state != state {
            continue;
        }
        for entry in &actor.entries {
            for observe in &entry.observes {
                for spec in observed_actor_template_specs(actor, entry, observe, model)
                    .expect("observed actor template specs are valid after model validation")
                {
                    if seen.insert(spec.clone()) {
                        specs.push(spec);
                    }
                }
            }
        }
    }
    specs
}

fn observed_actor_template_specs(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    model: &Model<'_>,
) -> Result<Vec<ObservedActorWitnessSpec>> {
    observed_actor_specs_for_observe(actor, entry, observe, model)?
        .into_iter()
        .filter_map(|spec| {
            let observed = observed_decl_for_spec(observe, &spec)?;
            match observed_open_state_for_decl(actor, entry, observe, observed, model) {
                Ok(Some(_)) => None,
                Ok(None) => Some(Ok(spec)),
                Err(err) => Some(Err(err)),
            }
        })
        .collect()
}

fn observed_actor_witness_specs_for_observe(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    model: &Model<'_>,
) -> Result<Vec<ObservedActorWitnessSpec>> {
    observed_actor_specs_for_observe(actor, entry, observe, model)
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

fn observed_open_bindings(observe: &ObserveDecl) -> BTreeMap<&str, &str> {
    observe.inputs.iter().filter_map(|input| input.open_state.as_deref().map(|state| (input.actor.as_str(), state))).collect()
}

fn observed_dynamic_binding_state<'a>(observe: &'a ObserveDecl, observed: &'a ObservedActorDecl) -> Option<&'a str> {
    observed.open_state.as_deref().or_else(|| observed_open_bindings(observe).get(observed.actor.as_str()).copied())
}

fn observed_open_state_for_decl(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<Option<String>> {
    if let Some(state) = observed_dynamic_binding_state(observe, observed) {
        model.state(state)?;
        return Ok(Some(state.to_string()));
    }
    source_actor_type_state_for_expr(&observed.actor, actor, entry, model)
}

fn observed_is_dynamic_binding(observe: &ObserveDecl, observed: &ObservedActorDecl) -> bool {
    observed_dynamic_binding_state(observe, observed).is_some()
}

fn observed_is_source_actor_type(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<bool> {
    Ok(source_actor_type_state_for_expr(&observed.actor, actor, entry, model)?.is_some())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ClauseReference {
    StateField(String),
    Bare(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ClauseActorTypeRef {
    StateField { field: String, state: String },
    EntryArgument { name: String, state: String },
}

impl ClauseActorTypeRef {
    fn state(&self) -> &str {
        match self {
            Self::StateField { state, .. } | Self::EntryArgument { state, .. } => state,
        }
    }

    fn witness_suffix(&self) -> String {
        match self {
            Self::StateField { field, .. } => format!("self_{field}"),
            Self::EntryArgument { name, .. } => format!("arg_{name}"),
        }
    }
}

fn clause_reference(expr: &str) -> Result<Option<ClauseReference>> {
    let tokens = lex(expr).map_err(|err| ArgentError::new(format!("failed to lex clause reference `{expr}`: {}", err.message)))?;
    match tokens.as_slice() {
        [
            Token { kind: TokenKind::Ident(self_name), .. },
            Token { kind: TokenKind::Symbol('.'), .. },
            Token { kind: TokenKind::Ident(field), .. },
            Token { kind: TokenKind::Eof, .. },
        ] if self_name == word::SELF => Ok(Some(ClauseReference::StateField(field.clone()))),
        [Token { kind: TokenKind::Ident(name), .. }, Token { kind: TokenKind::Eof, .. }] => {
            Ok(Some(ClauseReference::Bare(name.clone())))
        }
        _ => Ok(None),
    }
}

fn clause_actor_type_ref(expr: &str, actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<Option<ClauseActorTypeRef>> {
    let state = model.storage_state(&actor.state)?;
    let (source, ty) = match clause_reference(expr)? {
        Some(ClauseReference::StateField(field_name)) => {
            let field = state.fields.iter().find(|field| field.name == field_name).ok_or_else(|| {
                ArgentError::new(format!(
                    "entry `{}::{}` references unknown state field `{}.{field_name}`",
                    actor.name,
                    entry.name,
                    word::SELF
                ))
            })?;
            (ClauseReference::StateField(field_name), &field.ty)
        }
        Some(ClauseReference::Bare(name)) => {
            if let Some(param) = entry.params.iter().find(|param| param.name == name) {
                (ClauseReference::Bare(name), &param.ty)
            } else if state.fields.iter().any(|field| field.name == name) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` state field `{name}` must be referenced as `{}.{name}` in entry clauses",
                    actor.name,
                    entry.name,
                    word::SELF
                )));
            } else {
                return Ok(None);
            }
        }
        None => return Ok(None),
    };

    let Some(actor_state) = ty.actor_state.as_ref() else {
        return Err(ArgentError::new(format!(
            "entry `{}::{}` clause reference `{}` has type `{}`; expected `{}<State>`",
            actor.name,
            entry.name,
            expr.trim(),
            source_type_ref(ty),
            word::ACTOR_TYPE
        )));
    };
    model.state(actor_state)?;
    Ok(Some(match source {
        ClauseReference::StateField(field) => ClauseActorTypeRef::StateField { field, state: actor_state.clone() },
        ClauseReference::Bare(name) => ClauseActorTypeRef::EntryArgument { name, state: actor_state.clone() },
    }))
}

fn source_actor_type_state_for_expr(expr: &str, actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<Option<String>> {
    Ok(clause_actor_type_ref(expr, actor, entry, model)?.map(|source| source.state().to_string()))
}

fn observed_actor_template_expr_for_entry(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    spec: &ObservedActorWitnessSpec,
) -> Result<String> {
    if observed_is_dynamic_binding(observe, observed) {
        return Ok(observed.actor.clone());
    }
    if observed_is_source_actor_type(actor, entry, observed, model)? {
        return lower_entry_expr(actor, entry, model, &observed.actor, Some("byte[32]"));
    }
    Ok(hidden_observed_actor_template_name(spec))
}

fn observed_input_spec(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    input: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<ObservedActorWitnessSpec> {
    observed_actor_spec(actor, entry, observe, ObservedActorSideArtifact::Input, input, model)
}

fn observed_output_spec(
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

fn observed_reuses_input_template(observe: &ObserveDecl, output: &ObservedActorDecl) -> bool {
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

fn first_observed_input_for_actor<'a>(observe: &'a ObserveDecl, actor: &str) -> Option<&'a ObservedActorDecl> {
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
    for (idx, actor) in model.template_actors.iter().enumerate() {
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
            out.push_str("          \"emits\": ");
            emit_emit_spec_json(&mut out, &entry.emits);
            out.push_str(",\n");
            out.push_str("          \"consumes\": [");
            for (consume_idx, consume) in entry.consumes.iter().enumerate() {
                if consume_idx > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!(
                    "{{ \"name\": \"{}\", \"actor\": \"{}\" }}",
                    json_escape(&consume.name),
                    json_escape(&consume.actor)
                ));
            }
            out.push_str("],\n");
            out.push_str("          \"routes\": [");
            for (route_idx, route) in entry.routes.iter().enumerate() {
                if route_idx > 0 {
                    out.push_str(", ");
                }
                let output =
                    route.output.as_ref().map(|output| format!("\"{}\"", json_escape(output))).unwrap_or_else(|| "null".to_string());
                out.push_str(&format!(
                    "{{ \"output\": {}, \"actor\": \"{}\", \"state\": \"{}\" }}",
                    output,
                    json_escape(&route.actor),
                    json_escape(&compact_expr(&route.state))
                ));
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
    let mut json = serde_json::to_string_pretty(&artifact).map_err(|err| ArgentError::new(err.to_string()))?;
    json.push('\n');
    Ok(json)
}

fn emit_artifact(program: &Program, model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<Artifact> {
    let templates = model.template_actors.iter().map(|actor| template_ref_artifact(actor)).collect::<Vec<_>>();

    let states: Vec<StateArtifact> = model
        .states
        .values()
        .map(|state| StateArtifact {
            name: state.name.clone(),
            fields: model
                .storage_state(&state.name)
                .expect("state expansions are valid after model validation")
                .fields
                .iter()
                .map(|field| FieldArtifact { name: field.name.clone(), ty: type_artifact(&field.ty, model) })
                .collect(),
        })
        .collect();
    let state_expansions = model
        .states
        .values()
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

    let sil_contracts = model.actors.iter().map(|actor| sil_contract_artifact(actor, model, actor_sil)).collect::<Result<Vec<_>>>()?;
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
    let template_plan = template_plan_artifact(model, &templates, &argent_actors, &sil_contracts, actor_sil)?;
    let interfaces = interface_set_artifact(model)?;

    let mut artifact = Artifact {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        id: String::new(),
        generator: GeneratorArtifact { name: "argentc".to_string(), version: env!("CARGO_PKG_VERSION").to_string() },
        app: model.app_name.clone(),
        root: manifest_path(&program.root),
        modules: program.modules.iter().map(|module| manifest_path(&module.path)).collect(),
        argent: ArgentArtifact {
            templates,
            template_plan,
            interfaces,
            states: states.clone(),
            state_expansions,
            actor_enums,
            actors: argent_actors,
        },
        sil_abi: SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION, states, contracts: sil_contracts },
    };
    artifact.verify_template_plan().map_err(|err| ArgentError::new(format!("invalid template plan receipt: {err}")))?;
    artifact.id = artifact.computed_id_hex().map_err(|err| ArgentError::new(format!("failed to compute artifact id: {err}")))?;
    Ok(artifact)
}

fn interface_set_artifact(model: &Model<'_>) -> Result<InterfaceSetArtifact> {
    let exports = model.template_actors.iter().map(|actor| actor_interface_artifact(actor, model)).collect::<Result<Vec<_>>>()?;

    let mut imported_actors = BTreeSet::new();
    let template_actor_set = model.template_actors.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for actor in &model.actors {
        for entry in &actor.entries {
            for observe in &entry.observes {
                for observed in observe.inputs.iter().chain(observe.outputs.iter()) {
                    if observed_open_state_for_decl(actor, entry, observe, observed, model)?.is_some() {
                        continue;
                    }
                    if !template_actor_set.contains(observed.actor.as_str()) {
                        imported_actors.insert(observed.actor.clone());
                    }
                }
            }
        }
    }
    let imports = imported_actors.iter().map(|actor| actor_interface_artifact(actor, model)).collect::<Result<Vec<_>>>()?;

    Ok(InterfaceSetArtifact { exports, imports })
}

fn actor_interface_artifact(actor_name: &str, model: &Model<'_>) -> Result<ActorInterfaceArtifact> {
    let actor = model.actor(actor_name)?;
    let runtime_fields = runtime_state_fields_for_source(&actor.state, model)?;
    let fingerprint_hex = actor_interface_fingerprint_hex(&actor.name, &actor.state, &runtime_fields)
        .map_err(|err| ArgentError::new(format!("failed to compute actor interface fingerprint for `{}`: {err}", actor.name)))?;
    Ok(ActorInterfaceArtifact {
        id: actor_interface_id(&actor.name),
        actor: actor.name.clone(),
        state: actor.state.clone(),
        fingerprint_hex,
    })
}

fn template_ref_artifact(actor: &str) -> TemplateRefArtifact {
    TemplateRefArtifact { id: template_receipt_id(actor), actor: actor.to_string(), symbol: hidden_template_name(actor) }
}

fn template_plan_artifact(
    model: &Model<'_>,
    templates: &[TemplateRefArtifact],
    actors: &[ActorArtifact],
    sil_contracts: &[SilContractArtifact],
    actor_sil: &BTreeMap<String, String>,
) -> Result<TemplatePlanArtifact> {
    let sil_by_name = sil_contracts.iter().map(|contract| (contract.name.as_str(), contract)).collect::<BTreeMap<_, _>>();
    let templates = templates
        .iter()
        .map(|template| {
            let contract = sil_by_name
                .get(template.actor.as_str())
                .ok_or_else(|| ArgentError::new(format!("missing Sil ABI contract for template actor `{}`", template.actor)))?;
            Ok(TemplatePlanTemplateArtifact {
                id: template.id.clone(),
                actor: template.actor.clone(),
                contract: contract.name.clone(),
                symbol: template.symbol.clone(),
                canonical_template_hash: contract.compiled.template.hash_hex.clone(),
                actor_type_handle: None,
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
    let route_proofs = route_template_proofs_artifact(&route_tables, &templates)?;
    let route_families = route_template_families_artifact(model);

    let mut seen = BTreeSet::new();
    let mut witness_recipes = Vec::new();
    for actor in actors {
        for entry in &actor.entries {
            for param in &entry.hidden_params {
                if seen.insert(param.recipe_id.clone()) {
                    witness_recipes.push(TemplateWitnessRecipeArtifact {
                        id: param.recipe_id.clone(),
                        template_id: match &param.subject {
                            HiddenParamSubjectArtifact::Actor { actor } => Some(template_receipt_id(actor)),
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

    let mut plan = TemplatePlanArtifact { templates, runtime_states, route_tables, route_proofs, route_families, witness_recipes };
    let handles = plan
        .templates
        .iter()
        .map(|template| actor_type_handle_artifact(template, &plan, model, actor_sil))
        .collect::<Result<Vec<_>>>()?;
    for (template, handle) in plan.templates.iter_mut().zip(handles) {
        template.actor_type_handle = handle;
    }
    Ok(plan)
}

fn actor_type_handle_artifact(
    template: &TemplatePlanTemplateArtifact,
    plan: &TemplatePlanArtifact,
    model: &Model<'_>,
    actor_sil: &BTreeMap<String, String>,
) -> Result<Option<ActorTypeHandleArtifact>> {
    let actor = model.actor(&template.actor)?;
    let Some(expansion) = &model.state(&actor.state)?.expansion else {
        return Ok(None);
    };
    let runtime_plan = plan.runtime_states.iter().find(|runtime_state| runtime_state.contract == actor.name);
    let context_fields = runtime_plan
        .map(|runtime_state| runtime_state.field_roles.iter().map(|field| field.name.clone()).collect::<Vec<_>>())
        .unwrap_or_default();
    let context_values = runtime_plan
        .map(|runtime_state| {
            runtime_state
                .field_roles
                .iter()
                .map(|field| {
                    fixed_runtime_context_value(plan, runtime_state, field)
                        .map_err(|err| ArgentError::new(format!("cannot derive fixed capsule context: {err}")))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let runtime_fields = runtime_state_fields_for_source(&actor.state, model)?;
    let context_state = RuntimeStateArtifact {
        source: expansion.base.clone(),
        fields: runtime_fields.iter().take(context_fields.len()).cloned().collect(),
    };
    let context_state_values =
        context_fields.iter().cloned().zip(context_values.iter().cloned().map(ArtifactValue::Bytes)).collect::<BTreeMap<_, _>>();
    let context_script = crate::codec::encode_runtime_state_script(&context_state, &context_state_values)
        .map_err(|err| ArgentError::new(format!("cannot encode actor_type<{}> context: {err}", expansion.base)))?;

    let mut args = context_values.into_iter().map(SilExpr::from).collect::<Vec<_>>();
    for field in &model.storage_state(&actor.state)?.fields {
        args.push(placeholder_expr_for_type(&field.ty).map_err(|err| {
            ArgentError::new(format!(
                "cannot build actor_type<{}> placeholder for actor `{}` field `{}`: {err}",
                expansion.base, actor.name, field.name
            ))
        })?);
    }

    let sil = actor_sil
        .get(&actor.name)
        .ok_or_else(|| ArgentError::new(format!("missing generated Silverscript for actor `{}`", actor.name)))?;
    let compiled = compile_contract(sil, &args, CompileOptions::default()).map_err(|err| {
        ArgentError::new(format!("generated Silverscript for actor `{}` failed to compile its capsule cut: {err}", actor.name))
    })?;
    if encode_hex(&compiled.template_hash()) != template.canonical_template_hash {
        return Err(ArgentError::new(format!(
            "actor `{}` canonical template changed while resolving its capsule context",
            actor.name
        )));
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
    if compiled.script.get(state_start..context_end) != Some(context_script.as_slice()) {
        return Err(ArgentError::new(format!("actor `{}` compiled capsule context does not match its runtime state ABI", actor.name)));
    }
    let prefix = &compiled.script[..context_end];
    let suffix = &compiled.script[state_end..];
    let hash = silverscript_lang::template::template_hash(prefix, suffix);
    Ok(Some(ActorTypeHandleArtifact {
        state: expansion.base.clone(),
        context_fields,
        template: CompiledTemplateArtifact {
            prefix_hex: encode_hex(prefix),
            suffix_hex: encode_hex(suffix),
            hash_hex: encode_hex(&hash),
        },
    }))
}

fn route_template_families_artifact(model: &Model<'_>) -> Vec<RouteTemplateFamilyArtifact> {
    model
        .route_families
        .iter()
        .map(|family| RouteTemplateFamilyArtifact {
            id: family.id.clone(),
            state: family.state.clone(),
            anchor_actor: family.anchor_actor().to_string(),
            entry_actors: family.entry_actors.clone(),
            table_id: route_template_table_receipt_id(&family.state, &hidden_route_family_table_name(family)),
            actors: family.actors.clone(),
        })
        .collect()
}

fn route_template_tables_artifact(
    runtime_states: &[RuntimeStatePlanArtifact],
    sil_contracts: &[SilContractArtifact],
) -> Result<Vec<RouteTemplateTableArtifact>> {
    let mut tables = BTreeMap::<String, RouteTemplateTableArtifact>::new();
    let sil_by_name = sil_contracts.iter().map(|contract| (contract.name.as_str(), contract)).collect::<BTreeMap<_, _>>();
    for runtime_state in runtime_states {
        let contract = sil_by_name
            .get(runtime_state.contract.as_str())
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
                RuntimeFieldRoleArtifact::ObservedTemplate { .. } => continue,
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
    templates: &[TemplatePlanTemplateArtifact],
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
        abi: ActorAbiRefArtifact { actor: actor.name.clone() },
        leader_for,
        entries,
    })
}

fn sil_contract_artifact(actor: &ActorDecl, model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<SilContractArtifact> {
    let entries = actor.entries.iter().enumerate().map(|(idx, entry)| sil_entry_artifact(actor, idx, entry, model)).collect();
    let sil = actor_sil
        .get(&actor.name)
        .ok_or_else(|| ArgentError::new(format!("missing generated Silverscript for actor `{}`", actor.name)))?;

    Ok(SilContractArtifact {
        name: actor.name.clone(),
        source_path: format!("sil/{}.sil", actor.name),
        runtime_state: RuntimeStateArtifact {
            source: actor.state.clone(),
            fields: runtime_state_fields_for_source(&actor.state, model)?,
        },
        entries,
        compiled: compile_contract_artifact(sil, actor, model)?,
    })
}

fn compile_contract_artifact<'i>(sil: &'i str, actor: &ActorDecl, model: &Model<'_>) -> Result<CompiledContractArtifact> {
    let args: Vec<SilExpr<'i>> = constructor_args_for_actor(actor, model)?;
    let compiled = compile_contract(sil, &args, CompileOptions::default())
        .map_err(|err| ArgentError::new(format!("generated Silverscript for actor `{}` failed to compile: {err}", actor.name)))?;
    compiled_contract_artifact(&compiled)
}

fn constructor_args_for_actor<'i>(actor: &ActorDecl, model: &Model<'_>) -> Result<Vec<SilExpr<'i>>> {
    let state = model.storage_state(&actor.state)?;
    let hidden_args = hidden_template_init_args_for_state(&actor.state, model);
    let mut args = Vec::with_capacity(hidden_args.len() + state.fields.len());

    // These placeholders are valid because Argent-generated constructor
    // arguments are state initializers: hidden template commitments and source
    // state fields. If a constructor argument affects code shape outside the
    // compiled state span, the template hash changes and the contract must be
    // recompiled for that value.
    match route_field_kind(&actor.state, model) {
        RouteFieldKind::None => {}
        RouteFieldKind::Direct { actor_templates, family_commitments } => {
            args.extend(actor_templates.into_iter().map(|_| zero_byte_array_expr(32)));
            args.extend(family_commitments.into_iter().map(|_| zero_byte_array_expr(32)));
        }
        RouteFieldKind::FamilyTables { families } => {
            for family in families {
                args.extend(family.direct_template_actors().iter().map(|_| zero_byte_array_expr(32)));
                args.push(zero_byte_array_expr(family.table_byte_len()));
            }
        }
    }
    args.extend(observed_template_specs_for_state(&actor.state, model).iter().map(|_| zero_byte_array_expr(32)));
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
        ("byte", Some(len)) => Ok(zero_byte_array_expr(len)),
        (_, Some(len)) => {
            let item = TypeRef::new(ty.name.clone());
            let values = (0..len).map(|_| placeholder_expr_for_type(&item)).collect::<Result<Vec<_>>>()?;
            Ok(values.into())
        }
        ("int", None) => Ok(SilExpr::int(0)),
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
    (0..len).map(|_| SilExpr::byte(0)).collect::<Vec<_>>().into()
}

fn compiled_contract_artifact(compiled: &CompiledContract<'_>) -> Result<CompiledContractArtifact> {
    let layout = compiled.state_layout;
    let suffix_start = layout.start + layout.len;
    if layout.start > compiled.script.len() || suffix_start > compiled.script.len() {
        return Err(ArgentError::new(format!(
            "compiled contract `{}` reported invalid state span start={} len={} for script len={}",
            compiled.contract_name,
            layout.start,
            layout.len,
            compiled.script.len()
        )));
    }

    let prefix = &compiled.script[..layout.start];
    let suffix = &compiled.script[suffix_start..];
    let template_hash = compiled.template_hash();

    Ok(CompiledContractArtifact {
        script_hex: encode_hex(&compiled.script),
        template: CompiledTemplateArtifact {
            prefix_hex: encode_hex(prefix),
            suffix_hex: encode_hex(suffix),
            hash_hex: encode_hex(&template_hash),
        },
        state_span: StateSpanArtifact { offset: layout.start, len: layout.len },
    })
}

fn runtime_state_field_defs_for_source(
    source_state: &str,
    model: &Model<'_>,
) -> Result<Vec<(String, TypeArtifact, Option<RuntimeFieldRoleArtifact>)>> {
    let state = model.storage_state(source_state)?;
    let mut fields = Vec::new();
    match route_field_kind(source_state, model) {
        RouteFieldKind::None => {}
        RouteFieldKind::Direct { actor_templates, family_commitments } => {
            for actor in actor_templates {
                fields.push((
                    hidden_template_name(actor),
                    TypeArtifact::from_parts("byte", Some(32)),
                    Some(RuntimeFieldRoleArtifact::Template { contract: actor.to_string() }),
                ));
            }
            for family in family_commitments {
                fields.push((
                    hidden_route_family_commitment_name(family),
                    TypeArtifact::from_parts("byte", Some(32)),
                    Some(RuntimeFieldRoleArtifact::TemplateDigest { id: family.id.clone() }),
                ));
            }
        }
        RouteFieldKind::FamilyTables { families } => {
            for family in families {
                for actor in family.direct_template_actors() {
                    fields.push((
                        hidden_template_name(actor),
                        TypeArtifact::from_parts("byte", Some(32)),
                        Some(RuntimeFieldRoleArtifact::Template { contract: actor.to_string() }),
                    ));
                }
                fields.push((
                    hidden_route_family_table_name(family),
                    TypeArtifact::from_parts("byte", Some(family.table_byte_len())),
                    Some(RuntimeFieldRoleArtifact::TemplateTable { contracts: family.table_actors().to_vec() }),
                ));
            }
        }
    }
    for spec in observed_template_specs_for_state(source_state, model) {
        fields.push((
            hidden_observed_actor_template_name(&spec),
            TypeArtifact::from_parts("byte", Some(32)),
            Some(RuntimeFieldRoleArtifact::ObservedTemplate {
                observe: spec.observe,
                side: spec.side,
                handle: spec.handle,
                contract: spec.actor,
            }),
        ));
    }
    for field in &state.fields {
        fields.push((field.name.clone(), type_artifact(&field.ty, model), None));
    }
    Ok(fields)
}

fn runtime_state_fields_for_source(source_state: &str, model: &Model<'_>) -> Result<Vec<RuntimeFieldArtifact>> {
    Ok(runtime_state_field_defs_for_source(source_state, model)?
        .into_iter()
        .map(|(name, ty, _role)| RuntimeFieldArtifact { name, ty })
        .collect())
}

fn runtime_state_plan_artifact(actor: &ActorDecl, model: &Model<'_>) -> Result<Option<RuntimeStatePlanArtifact>> {
    let field_roles = runtime_state_field_defs_for_source(&actor.state, model)?
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
    for spec in &witness_specs.spawn_templates {
        let subject = HiddenParamSubjectArtifact::SpawnActor {
            spawn: spec.spawn.clone(),
            handle: spec.handle.clone(),
            actor: spec.actor.clone(),
        };
        hidden_params.push(HiddenParamArtifact {
            recipe_id: spawn_actor_witness_recipe_id(actor, entry, spec, HiddenParamPurposeArtifact::TemplatePrefixBytes),
            name: hidden_spawn_actor_prefix_name(spec),
            ty: TypeArtifact::Bytes,
            subject: subject.clone(),
            purpose: HiddenParamPurposeArtifact::TemplatePrefixBytes,
            route_proof_id: None,
        });
        hidden_params.push(HiddenParamArtifact {
            recipe_id: spawn_actor_witness_recipe_id(actor, entry, spec, HiddenParamPurposeArtifact::TemplateSuffixBytes),
            name: hidden_spawn_actor_suffix_name(spec),
            ty: TypeArtifact::Bytes,
            subject,
            purpose: HiddenParamPurposeArtifact::TemplateSuffixBytes,
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
    let selectors = model.template_selectors_for_entry(actor, entry)?;
    let expanded_routes = expand_route_set(&entry.routes, &selectors);
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
        abi: EntryAbiRefArtifact { actor: actor.name.clone(), entry: entry.name.clone() },
        route_plan: entry_route_plan_artifact(actor, entry, model, &witnesses)?,
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
        observes: entry.observes.iter().map(|observe| observe_artifact(actor, entry, model, observe)).collect::<Result<Vec<_>>>()?,
        spawns: entry.spawns.iter().map(|spawn| spawn_artifact(actor, entry, model, spawn)).collect::<Result<Vec<_>>>()?,
        witnesses,
        consumes: entry
            .consumes
            .iter()
            .map(|consume| ConsumeArtifact { name: consume.name.clone(), actor: consume.actor.clone() })
            .collect(),
        emits: emit_spec_artifact(&entry.emits, model),
        routes: expanded_routes.iter().map(route_artifact).collect(),
    })
}

fn spawn_artifact(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>, spawn: &SpawnDecl) -> Result<SpawnArtifact> {
    Ok(SpawnArtifact {
        name: spawn.name.clone(),
        covenant: spawn.covenant.clone(),
        outputs: spawn
            .outputs
            .iter()
            .map(|output| {
                let state = source_actor_type_state_for_expr(&output.actor, actor, entry, model)?.ok_or_else(|| {
                    ArgentError::new(format!(
                        "spawn `{}.{}` target `{}` is not an actor_type value",
                        spawn.name, output.name, output.actor
                    ))
                })?;
                Ok(SpawnOutputArtifact {
                    name: output.name.clone(),
                    actor: compact_expr(&output.actor),
                    state,
                    group_index: output.group_index,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn observe_artifact(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>, observe: &ObserveDecl) -> Result<ObserveArtifact> {
    Ok(ObserveArtifact {
        name: observe.name.clone(),
        covenant_expr: compact_expr(&observe.covenant_expr),
        covenant_id_source: observe_covenant_id_source(actor, entry, model, observe)?,
        inputs: observe
            .inputs
            .iter()
            .map(|observed| observed_actor_artifact(actor, entry, model, observe, observed))
            .collect::<Result<Vec<_>>>()?,
        outputs: observe
            .outputs
            .iter()
            .map(|observed| observed_actor_artifact(actor, entry, model, observe, observed))
            .collect::<Result<Vec<_>>>()?,
    })
}

fn observe_covenant_id_source(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    observe: &ObserveDecl,
) -> Result<CovenantIdSourceArtifact> {
    match clause_reference(&observe.covenant_expr)? {
        Some(ClauseReference::StateField(field_name)) => {
            let field = model.storage_state(&actor.state)?.fields.iter().find(|field| field.name == field_name).ok_or_else(|| {
                ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` references unknown state field `{}.{field_name}`",
                    actor.name,
                    entry.name,
                    observe.name,
                    word::SELF
                ))
            })?;
            require_covenant_id_source_type(actor, entry, observe, &format!("{}.{field_name}", word::SELF), &field.ty)?;
            Ok(CovenantIdSourceArtifact::StateField { field: field_name })
        }
        Some(ClauseReference::Bare(argument_name)) => {
            if let Some((index, param)) = entry.params.iter().enumerate().find(|(_, param)| param.name == argument_name) {
                require_covenant_id_source_type(actor, entry, observe, &argument_name, &param.ty)?;
                return Ok(CovenantIdSourceArtifact::EntryArgument { index });
            }
            if model.storage_state(&actor.state)?.fields.iter().any(|field| field.name == argument_name) {
                return Err(ArgentError::new(format!(
                    "entry `{}::{}` observe `{}` state field `{argument_name}` must be referenced as `{}.{argument_name}`",
                    actor.name,
                    entry.name,
                    observe.name,
                    word::SELF
                )));
            }
            Err(unsupported_observe_covenant_id_source(actor, entry, observe))
        }
        None => Err(unsupported_observe_covenant_id_source(actor, entry, observe)),
    }
}

fn require_covenant_id_source_type(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    source: &str,
    ty: &TypeRef,
) -> Result<()> {
    if ty.name == word::COVENANT_ID && ty.array.is_none() && ty.actor_state.is_none() {
        return Ok(());
    }
    Err(ArgentError::new(format!(
        "entry `{}::{}` observe `{}` covenant id source `{source}` has type `{}`; expected `{}`",
        actor.name,
        entry.name,
        observe.name,
        source_type_ref(ty),
        word::COVENANT_ID
    )))
}

fn unsupported_observe_covenant_id_source(actor: &ActorDecl, entry: &EntryDecl, observe: &ObserveDecl) -> ArgentError {
    ArgentError::new(format!(
        "entry `{}::{}` observe `{}` covenant id source must be a `{}.<field>` state field or entry argument of type `{}`",
        actor.name,
        entry.name,
        observe.name,
        word::SELF,
        word::COVENANT_ID
    ))
}

fn observed_actor_artifact(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
) -> Result<ObservedActorArtifact> {
    Ok(ObservedActorArtifact {
        name: observed.name.clone(),
        actor: observed.actor.clone(),
        open_state: observed_open_state_for_decl(actor, entry, observe, observed, model)?,
    })
}

fn entry_route_plan_artifact(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
    witnesses: &[WitnessArtifact],
) -> Result<EntryRoutePlanArtifact> {
    let active_input = RouteInputArtifact {
        name: "self".to_string(),
        actor: actor.name.clone(),
        cov_index: matches!(entry.kind, EntryKind::Leader).then_some(0),
    };
    let consumes = entry
        .consumes
        .iter()
        .enumerate()
        .map(|(idx, consume)| RouteInputArtifact {
            name: consume.name.clone(),
            actor: consume.actor.clone(),
            cov_index: Some(consume_cov_index(entry.kind, idx)),
        })
        .collect::<Vec<_>>();
    let leader_input = match entry.kind {
        EntryKind::Leader => Some(active_input.clone()),
        EntryKind::Delegate => consumes.first().cloned(),
    };
    let outputs = route_output_handles(&entry.emits, model);
    Ok(EntryRoutePlanArtifact {
        active_input: Some(active_input),
        leader_input,
        consumes,
        outputs,
        witness_recipe_ids: witnesses.iter().map(|witness| witness.recipe_id.clone()).collect(),
    })
}

fn consume_cov_index(kind: EntryKind, idx: usize) -> usize {
    match kind {
        EntryKind::Leader => idx + 1,
        EntryKind::Delegate => idx,
    }
}

fn route_output_handles(emits: &EmitSpec, model: &Model<'_>) -> Vec<RouteOutputHandleArtifact> {
    match emits {
        EmitSpec::None => Vec::new(),
        EmitSpec::One { actors } => {
            vec![RouteOutputHandleArtifact { name: None, auth_index: 0, actors: model.expand_actor_refs(actors) }]
        }
        EmitSpec::Outputs(outputs) => outputs
            .iter()
            .map(|output| RouteOutputHandleArtifact {
                name: Some(output.name.clone()),
                auth_index: output.auth_index,
                actors: model.expand_actor_refs(&output.actors),
            })
            .collect(),
    }
}

fn sil_entry_artifact(actor: &ActorDecl, entry_index: usize, entry: &EntryDecl, model: &Model<'_>) -> SilEntryArtifact {
    let mut params = entry
        .params
        .iter()
        .map(|param| ParamArtifact { name: param.name.clone(), ty: entry_param_type_artifact(actor, &param.ty, model) })
        .collect::<Vec<_>>();
    params.extend(
        hidden_params_for_entry(actor, entry, model).into_iter().map(|param| ParamArtifact { name: param.name, ty: param.ty }),
    );

    SilEntryArtifact { name: entry.name.clone(), selector: (actor.entries.len() > 1).then_some(entry_index as i64), params }
}

fn emit_spec_artifact(emits: &EmitSpec, model: &Model<'_>) -> EmitArtifact {
    match emits {
        EmitSpec::None => EmitArtifact::None,
        EmitSpec::One { actors } => EmitArtifact::One { actors: model.expand_actor_refs(actors) },
        EmitSpec::Outputs(outputs) => EmitArtifact::Outputs {
            outputs: outputs
                .iter()
                .map(|output| EmitOutputArtifact {
                    name: output.name.clone(),
                    auth_index: output.auth_index,
                    actors: model.expand_actor_refs(&output.actors),
                })
                .collect(),
        },
    }
}

fn route_artifact(route: &RouteCall) -> RouteArtifact {
    RouteArtifact {
        output: route.output.clone(),
        actor: route.actor.clone(),
        template_id: template_receipt_id(&route.actor),
        state_expr: compact_expr(&route.state),
    }
}

fn lower_type_ref(ty: &TypeRef, model: &Model<'_>) -> String {
    if model.is_actor_enum_type(ty) {
        "int".to_string()
    } else if ty.name == word::COVENANT_ID && ty.array.is_none() {
        "byte[32]".to_string()
    } else {
        ty.to_sil()
    }
}

fn lower_entry_param_type(actor: &ActorDecl, ty: &TypeRef, model: &Model<'_>) -> String {
    if ty.array.is_none()
        && (ty.name == actor.state
            || matches!(
                (model.storage_state_name(&actor.state), model.storage_state_name(&ty.name)),
                (Ok(actor_storage), Ok(param_storage)) if actor_storage == param_storage
            ))
    {
        "State".to_string()
    } else {
        lower_type_ref(ty, model)
    }
}

fn source_type_ref(ty: &TypeRef) -> String {
    if let Some(state) = &ty.actor_state { format!("{}<{state}>", word::ACTOR_TYPE) } else { ty.to_sil() }
}

fn type_artifact(ty: &TypeRef, model: &Model<'_>) -> TypeArtifact {
    if ty.is_actor_type() {
        TypeArtifact::FixedBytes { len: 32 }
    } else if ty.name == word::COVENANT_ID {
        match ty.array {
            Some(len) => TypeArtifact::FixedArray { item: Box::new(TypeArtifact::FixedBytes { len: 32 }), len },
            None => TypeArtifact::FixedBytes { len: 32 },
        }
    } else if model.is_actor_enum_type(ty) {
        TypeArtifact::Int
    } else {
        TypeArtifact::from_parts(&ty.name, ty.array)
    }
}

fn entry_param_type_artifact(actor: &ActorDecl, ty: &TypeRef, model: &Model<'_>) -> TypeArtifact {
    if ty.array.is_none()
        && (ty.name == actor.state
            || matches!(
                (model.storage_state_name(&actor.state), model.storage_state_name(&ty.name)),
                (Ok(actor_storage), Ok(param_storage)) if actor_storage == param_storage
            ))
    {
        TypeArtifact::Struct { name: "State".to_string() }
    } else {
        type_artifact(ty, model)
    }
}

fn actor_enum_variant_index(actor_enum: &ActorEnumInfo, variant: &str) -> Option<usize> {
    actor_enum.variants.iter().position(|candidate| candidate == variant)
}

fn actor_enum_variant_const_expr(actor_enum: &ActorEnumInfo, variant: &str) -> Option<String> {
    actor_enum_variant_index(actor_enum, variant).map(|index| format!("{index} /*{}*/", to_snake(variant).to_ascii_uppercase()))
}

fn lower_co_spent_calls(expr: &str, source_types: &BTreeMap<String, String>) -> Result<String> {
    let method = format!(".{}", word::CO_SPENT);
    if !expr.contains(&method) {
        return Ok(expr.to_string());
    }
    let tokens =
        lex(expr).map_err(|err| ArgentError::new(format!("failed to lex covenant co-spend expression `{expr}`: {}", err.message)))?;
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut pos = 0usize;
    while pos < tokens.len() {
        if let Some((replacement_start, replacement_end, next_pos, covenant_id)) =
            parse_co_spent_call(expr, &tokens, pos, source_types)?
        {
            out.push_str(&expr[cursor..replacement_start]);
            out.push_str(&format!("OpCovInputCount({}) > 0", covenant_id.trim()));
            cursor = replacement_end;
            pos = next_pos;
            continue;
        }
        if matches!(tokens[pos].kind, TokenKind::Eof) {
            break;
        }
        pos += 1;
    }
    out.push_str(&expr[cursor..]);
    if out.contains(&method) {
        return Err(ArgentError::new(format!(
            "`.{}()` is only available on `{}` values or explicit `{}(expr)` casts",
            word::CO_SPENT,
            word::COVENANT_ID,
            word::COVENANT_ID,
        )));
    }
    Ok(out)
}

fn co_spent_covenant_ids(expr: &str, source_types: &BTreeMap<String, String>) -> Result<Vec<String>> {
    if !expr.contains(&format!(".{}", word::CO_SPENT)) {
        return Ok(Vec::new());
    }
    let tokens =
        lex(expr).map_err(|err| ArgentError::new(format!("failed to lex covenant co-spend expression `{expr}`: {}", err.message)))?;
    let mut ids = Vec::new();
    let mut pos = 0usize;
    while pos < tokens.len() {
        if let Some((_replacement_start, _replacement_end, next_pos, covenant_id)) =
            parse_co_spent_call(expr, &tokens, pos, source_types)?
        {
            ids.push(covenant_id.trim().to_string());
            pos = next_pos;
            continue;
        }
        if matches!(tokens[pos].kind, TokenKind::Eof) {
            break;
        }
        pos += 1;
    }
    Ok(ids)
}

fn parse_require_statement(statement: &str) -> Option<&str> {
    let statement = statement.trim();
    let inner = statement.strip_prefix(&format!("{}(", word::REQUIRE))?.strip_suffix(')')?;
    Some(inner)
}

fn parse_co_spent_call(
    expr: &str,
    tokens: &[Token],
    pos: usize,
    source_types: &BTreeMap<String, String>,
) -> Result<Option<(usize, usize, usize, String)>> {
    if is_ident(tokens, pos, word::COVENANT_ID) && is_symbol(tokens, pos + 1, '(') {
        let close = matching_symbol(tokens, pos + 1, '(', ')')
            .ok_or_else(|| ArgentError::new(format!("unterminated {}(...) co-spend expression `{expr}`", word::COVENANT_ID)))?;
        if is_symbol(tokens, close + 1, '.')
            && is_ident(tokens, close + 2, word::CO_SPENT)
            && is_symbol(tokens, close + 3, '(')
            && is_symbol(tokens, close + 4, ')')
        {
            return Ok(Some((
                tokens[pos].span.start,
                tokens[close + 4].span.end,
                close + 5,
                expr[tokens[pos + 1].span.end..tokens[close].span.start].to_string(),
            )));
        }
        return Ok(None);
    }

    if matches!(tokens.get(pos).map(|token| &token.kind), Some(TokenKind::Ident(_)))
        && is_symbol(tokens, pos + 1, '.')
        && is_ident(tokens, pos + 2, word::CO_SPENT)
        && is_symbol(tokens, pos + 3, '(')
        && is_symbol(tokens, pos + 4, ')')
    {
        let ident = expr[tokens[pos].span.start..tokens[pos].span.end].to_string();
        if source_types.get(&ident).is_none_or(|ty| ty != word::COVENANT_ID) {
            return Err(ArgentError::new(format!(
                "`.{}()` is only available on `{}` values, found `{ident}`",
                word::CO_SPENT,
                word::COVENANT_ID,
            )));
        }
        return Ok(Some((tokens[pos].span.start, tokens[pos + 4].span.end, pos + 5, ident)));
    }

    Ok(None)
}

fn matching_symbol(tokens: &[Token], open_pos: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    for (pos, token) in tokens.iter().enumerate().skip(open_pos) {
        match token.kind {
            TokenKind::Symbol(symbol) if symbol == open => depth += 1,
            TokenKind::Symbol(symbol) if symbol == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(pos);
                }
            }
            TokenKind::Eof => return None,
            _ => {}
        }
    }
    None
}

fn is_ident(tokens: &[Token], pos: usize, ident: &str) -> bool {
    matches!(tokens.get(pos).map(|token| &token.kind), Some(TokenKind::Ident(candidate)) if candidate == ident)
}

fn is_symbol(tokens: &[Token], pos: usize, symbol: char) -> bool {
    matches!(tokens.get(pos).map(|token| &token.kind), Some(TokenKind::Symbol(candidate)) if *candidate == symbol)
}

fn lower_actor_enum_literals(expr: &str, model: &Model<'_>) -> Result<String> {
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

fn emit_emit_spec_json(out: &mut String, emits: &EmitSpec) {
    match emits {
        EmitSpec::None => out.push_str("{ \"kind\": \"none\" }"),
        EmitSpec::One { actors } => {
            out.push_str("{ \"kind\": \"one\", \"actors\": [");
            for (idx, actor) in actors.iter().enumerate() {
                if idx > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("\"{}\"", json_escape(actor)));
            }
            out.push_str("] }");
        }
        EmitSpec::Outputs(outputs) => {
            out.push_str("{ \"kind\": \"outputs\", \"outputs\": [");
            for (output_idx, output) in outputs.iter().enumerate() {
                if output_idx > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!(
                    "{{ \"name\": \"{}\", \"auth_index\": {}, \"actors\": [",
                    json_escape(&output.name),
                    output.auth_index
                ));
                for (actor_idx, actor) in output.actors.iter().enumerate() {
                    if actor_idx > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("\"{}\"", json_escape(actor)));
                }
                out.push_str("] }");
            }
            out.push_str("] }");
        }
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

fn to_snake(input: &str) -> String {
    let mut out = String::new();
    let chars = input.chars().collect::<Vec<_>>();
    for (idx, ch) in chars.iter().copied().enumerate() {
        if ch.is_ascii_uppercase() {
            let prev = idx.checked_sub(1).and_then(|prev| chars.get(prev)).copied();
            let next = chars.get(idx + 1).copied();
            let starts_new_word = prev.is_some_and(|prev| {
                prev != '_'
                    && (prev.is_ascii_lowercase() || prev.is_ascii_digit() || next.is_some_and(|next| next.is_ascii_lowercase()))
            });
            if starts_new_word && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn reject_reserved_identifier(context: &str, name: &str) -> Result<()> {
    if name.starts_with(RESERVED_GENERATED_PREFIX) {
        return Err(ArgentError::new(format!(
            "{context} identifier `{name}` uses reserved generated namespace `{RESERVED_GENERATED_PREFIX}`"
        )));
    }
    if name == "State" {
        return Err(ArgentError::new(format!("{context} identifier `State` is reserved for generated Silverscript state")));
    }
    Ok(())
}

fn hidden_actor_suffix(actor: &str) -> String {
    to_snake(actor)
}

fn hidden_template_init_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}init_{}_template", hidden_actor_suffix(actor))
}

fn hidden_template_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_template", hidden_actor_suffix(actor))
}

fn hidden_template_root_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}template_root")
}

fn route_family_suffix_by_id(family_id: &str) -> String {
    let hub = family_id.strip_prefix("route_family/").and_then(|rest| rest.rsplit('/').next()).unwrap_or(family_id);
    to_snake(hub)
}

fn hidden_route_family_commitment_init_name(family: &RouteFamily) -> String {
    format!("{RESERVED_GENERATED_PREFIX}init_{}_routes_digest", route_family_suffix_by_id(&family.id))
}

fn hidden_route_family_commitment_name(family: &RouteFamily) -> String {
    hidden_route_family_commitment_name_by_id(&family.id)
}

fn hidden_route_family_commitment_name_by_id(family_id: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_routes_digest", route_family_suffix_by_id(family_id))
}

fn hidden_route_family_table_init_name(family: &RouteFamily) -> String {
    format!("{RESERVED_GENERATED_PREFIX}init_{}_routes", route_family_suffix_by_id(&family.id))
}

fn hidden_route_family_table_name(family: &RouteFamily) -> String {
    hidden_route_family_table_name_by_id(&family.id)
}

fn hidden_route_family_table_name_by_id(family_id: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_routes", route_family_suffix_by_id(family_id))
}

fn route_leaves_contain_family(leaves: &[RouteRootLeaf], family_id: &str) -> bool {
    leaves.iter().any(|leaf| matches!(leaf, RouteRootLeaf::Family(id) if id == family_id))
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

fn route_field_kind<'a>(state: &'a str, model: &'a Model<'_>) -> RouteFieldKind<'a> {
    let families = model.route_families_for_state(state);
    if !families.is_empty() {
        return RouteFieldKind::FamilyTables { families };
    }

    let actor_templates = model
        .route_leaves_for_state(state)
        .iter()
        .filter_map(|leaf| match leaf {
            RouteRootLeaf::Actor(actor) => Some(actor.as_str()),
            RouteRootLeaf::Family(_) => None,
        })
        .collect::<Vec<_>>();
    let family_commitments = model
        .route_leaves_for_state(state)
        .iter()
        .filter_map(|leaf| match leaf {
            RouteRootLeaf::Actor(_) => None,
            RouteRootLeaf::Family(family_id) => model.route_families.iter().find(|family| family.id == *family_id),
        })
        .collect::<Vec<_>>();

    if actor_templates.is_empty() && family_commitments.is_empty() {
        RouteFieldKind::None
    } else {
        RouteFieldKind::Direct { actor_templates, family_commitments }
    }
}

enum RouteFieldKind<'a> {
    None,
    Direct { actor_templates: Vec<&'a str>, family_commitments: Vec<&'a RouteFamily> },
    FamilyTables { families: Vec<&'a RouteFamily> },
}

fn hidden_template_init_args_for_state(state: &str, model: &Model<'_>) -> Vec<String> {
    let mut args = match route_field_kind(state, model) {
        RouteFieldKind::None => Vec::new(),
        RouteFieldKind::Direct { actor_templates, family_commitments } => {
            let mut args =
                actor_templates.into_iter().map(|actor| format!("byte[32] {}", hidden_template_init_name(actor))).collect::<Vec<_>>();
            args.extend(
                family_commitments.into_iter().map(|family| format!("byte[32] {}", hidden_route_family_commitment_init_name(family))),
            );
            args
        }
        RouteFieldKind::FamilyTables { families } => {
            let mut args = Vec::new();
            for family in families {
                args.extend(
                    family.direct_template_actors().iter().map(|actor| format!("byte[32] {}", hidden_template_init_name(actor))),
                );
                args.push(format!("byte[{}] {}", family.table_byte_len(), hidden_route_family_table_init_name(family)));
            }
            args
        }
    };
    args.extend(
        observed_template_specs_for_state(state, model)
            .iter()
            .map(|spec| format!("byte[32] {}", hidden_observed_actor_template_init_name(spec))),
    );
    args
}

fn emit_route_template_table(out: &mut String, state: &str, model: &Model<'_>) {
    let observed_templates = observed_template_specs_for_state(state, model);
    match route_field_kind(state, model) {
        RouteFieldKind::None => {}
        RouteFieldKind::Direct { actor_templates, family_commitments } => {
            for actor in actor_templates {
                out.push_str(&format!("    byte[32] {} = {};\n", hidden_template_name(actor), hidden_template_init_name(actor)));
            }
            for family in family_commitments {
                out.push_str(&format!(
                    "    byte[32] {} = {};\n",
                    hidden_route_family_commitment_name(family),
                    hidden_route_family_commitment_init_name(family)
                ));
            }
        }
        RouteFieldKind::FamilyTables { families } => {
            for family in families {
                for actor in family.direct_template_actors() {
                    out.push_str(&format!("    byte[32] {} = {};\n", hidden_template_name(actor), hidden_template_init_name(actor)));
                }
                out.push_str(&format!(
                    "    byte[{}] {} = {};\n",
                    family.table_byte_len(),
                    hidden_route_family_table_name(family),
                    hidden_route_family_table_init_name(family)
                ));
            }
        }
    }
    for spec in observed_templates {
        out.push_str(&format!(
            "    byte[32] {} = {};\n",
            hidden_observed_actor_template_name(&spec),
            hidden_observed_actor_template_init_name(&spec)
        ));
    }
}

fn emit_hidden_template_fields(out: &mut String, state: &str, model: &Model<'_>, indent: usize) {
    let field_indent = " ".repeat(indent);
    let observed_templates = observed_template_specs_for_state(state, model);
    match route_field_kind(state, model) {
        RouteFieldKind::None => {
            for spec in &observed_templates {
                out.push_str(&format!("{field_indent}byte[32] {};\n", hidden_observed_actor_template_name(spec)));
            }
        }
        RouteFieldKind::Direct { actor_templates, family_commitments } => {
            for actor in actor_templates {
                out.push_str(&format!("{field_indent}byte[32] {};\n", hidden_template_name(actor)));
            }
            for family in family_commitments {
                out.push_str(&format!("{field_indent}byte[32] {};\n", hidden_route_family_commitment_name(family)));
            }
            for spec in &observed_templates {
                out.push_str(&format!("{field_indent}byte[32] {};\n", hidden_observed_actor_template_name(spec)));
            }
        }
        RouteFieldKind::FamilyTables { families } => {
            for family in families {
                for actor in family.direct_template_actors() {
                    out.push_str(&format!("{field_indent}byte[32] {};\n", hidden_template_name(actor)));
                }
                out.push_str(&format!(
                    "{field_indent}byte[{}] {};\n",
                    family.table_byte_len(),
                    hidden_route_family_table_name(family)
                ));
            }
            for spec in &observed_templates {
                out.push_str(&format!("{field_indent}byte[32] {};\n", hidden_observed_actor_template_name(spec)));
            }
        }
    }
}

fn hidden_template_object_fields_for_state(source_state: &str, target_state: &str, model: &Model<'_>) -> Vec<(String, String)> {
    let mut fields = match route_field_kind(target_state, model) {
        RouteFieldKind::None => Vec::new(),
        RouteFieldKind::Direct { actor_templates, family_commitments } => {
            let mut fields = actor_templates
                .into_iter()
                .map(|actor| (hidden_template_name(actor), hidden_template_expr_for_actor(source_state, actor, model)))
                .collect::<Vec<_>>();
            fields.extend(
                family_commitments
                    .into_iter()
                    .map(|family| (hidden_route_family_commitment_name(family), hidden_route_family_commitment_name(family))),
            );
            fields
        }
        RouteFieldKind::FamilyTables { families } => {
            let mut fields = Vec::new();
            for family in families {
                let table_expr = hidden_route_family_table_name(family);
                fields.extend(
                    family
                        .direct_template_actors()
                        .iter()
                        .map(|actor| (hidden_template_name(actor), hidden_template_expr_for_actor(source_state, actor, model))),
                );
                fields.push((hidden_route_family_table_name(family), table_expr));
            }
            fields
        }
    };
    fields.extend(observed_template_specs_for_state(target_state, model).into_iter().map(|spec| {
        let field = hidden_observed_actor_template_name(&spec);
        (field.clone(), field)
    }));
    fields
}

fn hidden_template_expr_for_actor(source_state: &str, actor: &str, model: &Model<'_>) -> String {
    observed_template_specs_for_state(source_state, model)
        .into_iter()
        .find(|spec| spec.actor == actor)
        .map(|spec| hidden_observed_actor_template_name(&spec))
        .unwrap_or_else(|| hidden_template_name(actor))
}

fn template_receipt_id(actor: &str) -> String {
    format!("template/{}", hidden_actor_suffix(actor))
}

fn template_witness_recipe_id(actor: &str, purpose: HiddenParamPurposeArtifact) -> String {
    format!("witness/{}/{}", hidden_actor_suffix(actor), hidden_param_purpose_id(purpose))
}

fn route_template_family_receipt_id(state: &str, anchor_actor: &str) -> String {
    format!("route_family/{state}/{}", hidden_actor_suffix(anchor_actor))
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

fn hidden_witness_prefix_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_prefix", hidden_actor_suffix(actor))
}

fn hidden_witness_suffix_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_suffix", hidden_actor_suffix(actor))
}

fn hidden_witness_prefix_len_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_prefix_len", hidden_actor_suffix(actor))
}

fn hidden_witness_suffix_len_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_suffix_len", hidden_actor_suffix(actor))
}

fn hidden_template_selector_prefix_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_prefix")
}

fn hidden_template_selector_suffix_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_suffix")
}

fn hidden_template_selector_prefix_len_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_prefix_len")
}

fn hidden_template_selector_suffix_len_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_suffix_len")
}

fn hidden_template_selector_index_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_selector")
}

fn hidden_template_selector_template_name(selector: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{selector}_template")
}

fn observed_actor_spec_suffix(spec: &ObservedActorWitnessSpec) -> String {
    spec.source.as_ref().map_or_else(|| actor_expr_suffix(&spec.actor), ClauseActorTypeRef::witness_suffix)
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

fn hidden_observed_actor_prefix_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_prefix", spec.observe, observed_actor_spec_suffix(spec))
}

fn hidden_observed_actor_suffix_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_suffix", spec.observe, observed_actor_spec_suffix(spec))
}

fn hidden_observed_actor_prefix_len_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_prefix_len", spec.observe, observed_actor_spec_suffix(spec))
}

fn hidden_observed_actor_suffix_len_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_suffix_len", spec.observe, observed_actor_spec_suffix(spec))
}

fn hidden_observed_actor_template_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_template", spec.observe, observed_actor_spec_suffix(spec))
}

fn hidden_observed_actor_template_init_name(spec: &ObservedActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}init_{}_{}_template", spec.observe, observed_actor_spec_suffix(spec))
}

fn hidden_spawn_actor_prefix_name(spec: &SpawnActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}spawn_{}_prefix", spec.source.witness_suffix())
}

fn hidden_spawn_actor_suffix_name(spec: &SpawnActorWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}spawn_{}_suffix", spec.source.witness_suffix())
}

fn hidden_state_expansion_preimage_name(spec: &StateExpansionWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_preimage", to_snake(&spec.field), to_snake(&spec.memory_state))
}

fn hidden_state_expansion_field_name(spec: &StateExpansionWitnessSpec, field: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}", to_snake(&spec.field), to_snake(field))
}

fn hidden_observed_output_field_name(spec: &ObservedOutputFieldWitnessSpec) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{}_{}_next_{}", spec.observe, spec.handle, to_snake(&spec.field))
}

fn hidden_observe_cov_id_name(observe: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_cov_id")
}

fn hidden_observed_input_idx_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_input_idx")
}

fn hidden_observed_output_idx_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_output_idx")
}

fn hidden_spawn_output_idx_name(spawn: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{spawn}_{handle}_output_idx")
}

fn hidden_spawn_preimage_name(spawn: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{spawn}_genesis_preimage")
}

fn hidden_observed_input_state_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_state")
}

fn observed_actor_side_label(side: ObservedActorSideArtifact) -> &'static str {
    match side {
        ObservedActorSideArtifact::Input => "input",
        ObservedActorSideArtifact::Output => "output",
    }
}

fn hidden_cov_id_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}cov_id")
}

fn hidden_input_idx_name(input: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{input}_input_idx")
}

fn hidden_next_output_idx_name() -> String {
    format!("{RESERVED_GENERATED_PREFIX}next_output_idx")
}

fn hidden_output_idx_name(output: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{output}_output_idx")
}

fn state_struct_name_for_actor(actor: &str, model: &Model<'_>) -> Result<String> {
    Ok(model.actor(actor)?.state.clone())
}

fn contract_state_type_for_actor(actor: &str, current_actor: &ActorDecl, model: &Model<'_>) -> Result<String> {
    let target_state = model.actor(actor)?.state.as_str();
    if target_state == current_actor.state { Ok("State".to_string()) } else { state_struct_name_for_actor(actor, model) }
}

fn contract_state_type_for_observed_actor(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observe: &ObserveDecl,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<String> {
    if let Some(target_state) = observed_open_state_for_decl(actor, entry, observe, observed, model)? {
        if target_state == actor.state { Ok("State".to_string()) } else { Ok(target_state.to_string()) }
    } else {
        contract_state_type_for_actor(&observed.actor, actor, model)
    }
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
    let trimmed = normalized.trim_matches('\n');
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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use super::*;

    #[test]
    fn rejects_route_outside_named_output_union() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].routes =
            vec![RouteCall { output: Some("next".to_string()), actor: "Game".to_string(), state: "next_game".to_string() }];

        let err = Model::from_program(&program).expect_err("route must be rejected");
        assert!(err.to_string().contains("routes output `next` to `Game`"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_route_inside_named_output_union() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].emits = EmitSpec::Outputs(vec![EmitOutput {
            name: "next".to_string(),
            actors: vec!["Player".to_string(), "Game".to_string()],
            auth_index: 0,
        }]);
        let route = RouteCall { output: Some("next".to_string()), actor: "Game".to_string(), state: "next_game".to_string() };
        program.modules[0].actors[0].entries[0].routes = vec![route.clone()];
        program.modules[0].actors[0].entries[0].terminal_route_sets = vec![vec![route]];

        Model::from_program(&program).expect("route should be accepted");
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
            EmitOutput { name: "a".to_string(), actors: vec!["Player".to_string()], auth_index: 0 },
            EmitOutput { name: "b".to_string(), actors: vec!["Player".to_string()], auth_index: 1 },
        ]);
        let route = RouteCall { output: Some("a".to_string()), actor: "Player".to_string(), state: "next_a".to_string() };
        program.modules[0].actors[0].entries[0].routes = vec![route.clone()];
        program.modules[0].actors[0].entries[0].terminal_route_sets = vec![vec![route]];

        let err = Model::from_program(&program).expect_err("missing output coverage must be rejected");
        assert!(err.to_string().contains("does not validate output `b`"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_source_with_missing_named_output_coverage() {
        let module = crate::parser::parse_module(
            PathBuf::from("test.ag"),
            r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits {
                    a: Foo;
                    b: Foo;
                } {
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
                int value;
            }

            actor Foo owns FooState {
                entry bump() emits {
                    next: Foo at auth[0];
                } {
                    FooState next_state = {
                        value: value + 1,
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

        assert!(err.to_string().contains("expected `;`"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_duplicate_named_output_coverage() {
        let mut program = test_program();
        let first = RouteCall { output: Some("next".to_string()), actor: "Player".to_string(), state: "next_player".to_string() };
        let second = RouteCall { output: Some("next".to_string()), actor: "Player".to_string(), state: "other_player".to_string() };
        program.modules[0].actors[0].entries[0].routes = vec![first.clone(), second.clone()];
        program.modules[0].actors[0].entries[0].terminal_route_sets = vec![vec![first, second]];

        let err = Model::from_program(&program).expect_err("duplicate output coverage must be rejected");
        assert!(err.to_string().contains("validates output `next` more than once"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_delegate_become() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].kind = EntryKind::Delegate;
        program.modules[0].actors[0].entries[0].consumes.push(ConsumeDecl { name: "leader".to_string(), actor: "Player".to_string() });
        program.modules[0].actors[0].entries[0].emits = EmitSpec::None;
        program.modules[0].actors[0].entries[0].routes =
            vec![RouteCall { output: Some("next".to_string()), actor: "Player".to_string(), state: "next_player".to_string() }];

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
                int value;
            }

            state WorkerState {
                int value;
            }

            state UnrelatedState {
                int value;
            }

            actor Leader owns LeaderState {
                entry standalone() emits one Leader {
                    become Leader(self.state);
                }

                entry coordinated() consumes {
                    worker: Worker;
                } emits one Leader {
                    require(worker.value >= 0);
                    become Leader(self.state);
                }
            }

            actor Worker owns WorkerState {
                delegate assist() consumes {
                    leader: Leader;
                } {
                    require(leader.value >= 0);
                }
            }

            actor Unrelated owns UnrelatedState {
                entry standalone() emits one Unrelated {
                    become Unrelated(self.state);
                }
            }

            app Test {
                actor Leader;
                actor Worker;
                actor Unrelated;
            }
        "#;
        let path = PathBuf::from("test.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");

        let leader_sil = emit_actor(model.actor("Leader").expect("Leader exists"), &model).expect("Leader emits");
        assert!(leader_sil.contains("require(OpCovInputCount(gen__cov_id) == 1);"), "{leader_sil}");
        assert!(leader_sil.contains("require(OpCovInputCount(gen__cov_id) == 2);"), "{leader_sil}");

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
        duplicate.actors.push(ActorDecl { name: "Player".to_string(), state: "PlayerState".to_string(), entries: Vec::new() });
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
            return_ty: TypeRef::new("int"),
            body: "1".to_string(),
        });
        let mut duplicate = empty_module("second.ag");
        duplicate.functions.push(FunctionDecl {
            name: "helper".to_string(),
            params: Vec::new(),
            return_ty: TypeRef::new("int"),
            body: "2".to_string(),
        });
        program.modules.push(duplicate);

        let err = Model::from_program(&program).expect_err("duplicate function declaration must be rejected");
        assert_duplicate_top_level_error(&err, "fn", "helper");
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
    fn rejects_reserved_entry_parameter_from_model() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0]
            .params
            .push(ParamDecl { name: "gen__next_output_idx".to_string(), ty: TypeRef::new("int") });

        let err = Model::from_program(&program).expect_err("reserved entry parameter must be rejected");
        assert!(err.to_string().contains("reserved generated namespace"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_reserved_output_handle_from_model() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].emits =
            EmitSpec::Outputs(vec![EmitOutput { name: "gen__next".to_string(), actors: vec!["Player".to_string()], auth_index: 0 }]);
        let route = RouteCall { output: Some("gen__next".to_string()), actor: "Player".to_string(), state: "next_player".to_string() };
        program.modules[0].actors[0].entries[0].routes = vec![route.clone()];
        program.modules[0].actors[0].entries[0].terminal_route_sets = vec![vec![route]];

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
        let module = crate::parser::parse_module(
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
        let module = crate::parser::parse_module(
            PathBuf::from("test.ag"),
            r#"
            state FooState {}

            actor Foo owns FooState {
                entry step() emits one Foo {
                    require(next.value == self.value);
                    become Foo(self.state);
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
    fn self_transition_uses_same_template_shortcut() {
        let module = crate::parser::parse_module(
            PathBuf::from("test.ag"),
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
    fn terminal_state_does_not_carry_its_own_template() {
        let path = PathBuf::from("terminal-route.ag");
        let module = crate::parser::parse_module(
            path.clone(),
            r#"
            state SourceState {
                int count;
            }

            state TerminalState {
                int count;
            }

            actor Source owns SourceState {
                entry finish() emits one Terminal {
                    TerminalState next = {
                        count: count + 1,
                    };
                    become Terminal(next);
                }
            }

            actor Terminal owns TerminalState {
                entry step() emits one Terminal {
                    TerminalState next = {
                        count: count + 1,
                    };
                    become Terminal(next);
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
        assert!(terminal_sil.contains("validateOutputState(gen__next_output_idx, next);"), "{terminal_sil}");
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
    }

    #[test]
    fn emits_portable_artifact_schema() {
        let module = crate::parser::parse_module(
            PathBuf::from("test.ag"),
            r#"
            state FooState {
                byte[32] owner;
                int count;
            }

            actor Foo owns FooState {
                entry step(amount: int) emits one Foo {
                    require(next.value == self.value);
                    become Foo(self.state);
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
            artifact.argent.template_plan.templates[0].canonical_template_hash,
            artifact.sil_abi.contract("Foo").unwrap().compiled.template.hash_hex
        );
        artifact.verify_template_plan().expect("template plan receipt verifies");
        assert_eq!(
            artifact.argent.states, artifact.sil_abi.states,
            "source and ABI structural state descriptors should be derived from the same model"
        );

        let state = artifact.argent.states.iter().find(|state| state.name == "FooState").expect("source state is present");
        assert_eq!(
            state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
            ["owner", "count"],
            "source state field order must stay stable"
        );
        assert_eq!(state.fields[0].ty, TypeArtifact::FixedBytes { len: 32 });
        assert_eq!(state.fields[1].ty, TypeArtifact::Int);

        let actor = artifact.argent.actors.iter().find(|actor| actor.name == "Foo").expect("actor is present");
        assert_eq!(actor.abi.actor, "Foo");
        let sil_contract = artifact.sil_abi.contract(&actor.abi.actor).expect("outer actor should point at Sil ABI contract");
        assert_eq!(sil_contract.source_path, "sil/Foo.sil");
        assert_compiled_projection(sil_contract.name.as_str(), &sil_contract.compiled);
        assert_eq!(
            sil_contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
            ["owner", "count"],
            "runtime state field order must match generated Silverscript state order"
        );
        assert!(
            runtime_state_plan(&artifact, "Foo").is_none(),
            "pure source runtime state should not need an Argent field-role overlay"
        );

        let entry = actor.entries.iter().find(|entry| entry.name == "step").expect("entry is present");
        assert_eq!(entry.kind, EntryKindArtifact::Leader);
        assert_eq!(entry.abi.actor, "Foo");
        assert_eq!(entry.abi.entry, "step");
        assert!(entry.hidden_params.is_empty(), "exact same-state continuation should not expose template witnesses");
        assert!(entry.witnesses.is_empty(), "exact same-state continuation should not expose route witnesses");
        assert!(matches!(entry.emits, EmitArtifact::One { .. }));
        assert_eq!(entry.routes[0].actor, "Foo");
        assert_eq!(entry.routes[0].state_expr, "self.state");
        assert_eq!(
            entry.route_plan.active_input.as_ref().map(|input| (input.actor.as_str(), input.cov_index)),
            Some(("Foo", Some(0)))
        );
        assert_eq!(entry.route_plan.outputs[0].auth_index, 0);
        assert_eq!(entry.route_plan.outputs[0].name, None);

        let sil_entry = sil_contract.entry(&entry.abi.entry).expect("outer entry should point at Sil ABI entry");
        assert_eq!(sil_entry.selector, None);
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
    fn state_expansion_uses_base_storage_layout() {
        let (sil, artifact) = emit_fixture("state_expansion", "Forager");

        assert_eq!(sil, include_str!("../tests/fixtures/emit/state_expansion/Forager.sil"));

        let expansion = artifact.argent.state_expansions.first().expect("state expansion is recorded");
        assert_eq!(expansion.state, "ForagerState");
        assert_eq!(expansion.base, "AgentCapsule");
        assert_eq!(expansion.digests.len(), 1);
        assert_eq!(expansion.digests[0].field, "strategy");
        assert_eq!(expansion.digests[0].state, "ForagerStrategy");

        let forager_state = artifact.argent.states.iter().find(|state| state.name == "ForagerState").expect("ForagerState exists");
        assert_eq!(forager_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["strategy", "energy"]);

        let contract = artifact.sil_abi.contract("Forager").expect("Forager Sil ABI exists");
        assert_eq!(contract.runtime_state.source, "ForagerState");
        assert_eq!(contract.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(), ["strategy", "energy"]);
        let hold = contract.entry("hold").expect("hold ABI exists");
        assert_eq!(
            hold.params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            ["gen__strategy_forager_strategy_preimage"]
        );
        assert_eq!(hold.params[0].ty, TypeArtifact::FixedBytes { len: 8 });

        let actor = artifact.argent.actors.iter().find(|actor| actor.name == "Forager").expect("Forager actor is present");
        let hold = actor.entries.iter().find(|entry| entry.name == "hold").expect("hold entry is present");
        assert_eq!(hold.hidden_params.len(), 1);
        assert_eq!(hold.hidden_params[0].name, "gen__strategy_forager_strategy_preimage");
        assert_eq!(hold.hidden_params[0].ty, TypeArtifact::FixedBytes { len: 8 });
        assert_eq!(hold.hidden_params[0].purpose, HiddenParamPurposeArtifact::StateExpansionPreimage);
    }

    #[test]
    fn expanded_actor_records_canonical_and_capsule_template_cuts() {
        let (sil, artifact) = emit_fixture("capsule_route_context", "ReserveAsset");
        let (wallet_sil, _) = emit_fixture("capsule_route_context", "WalletAsset");

        assert_eq!(sil, include_str!("../tests/fixtures/emit/capsule_route_context/ReserveAsset.sil"));
        assert_eq!(wallet_sil, include_str!("../tests/fixtures/emit/capsule_route_context/WalletAsset.sil"));
        assert!(sil.contains("byte[32] gen__wallet_asset_template"), "{sil}");

        let contract = artifact.sil_abi.contract("ReserveAsset").expect("ReserveAsset Sil ABI exists");
        let runtime_plan = runtime_state_plan(&artifact, "ReserveAsset").expect("route context is recorded");
        assert!(!runtime_plan.field_roles.is_empty());
        let receipt = artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == "ReserveAsset")
            .expect("ReserveAsset template receipt exists");
        assert_eq!(receipt.canonical_template_hash, contract.compiled.template.hash_hex);
        let handle = receipt.actor_type_handle.as_ref().expect("expanded actor exposes a capsule handle");
        assert_eq!(handle.state, "AssetCapsule");
        assert_eq!(handle.context_fields, runtime_plan.field_roles.iter().map(|field| field.name.clone()).collect::<Vec<_>>());
        assert_ne!(handle.template.hash_hex, receipt.canonical_template_hash);

        let canonical_prefix = crate::codec::decode_hex(&contract.compiled.template.prefix_hex).expect("canonical prefix decodes");
        let capsule_prefix = crate::codec::decode_hex(&handle.template.prefix_hex).expect("capsule prefix decodes");
        assert!(capsule_prefix.starts_with(&canonical_prefix));
        assert!(capsule_prefix.len() > canonical_prefix.len());
        assert_eq!(handle.template.suffix_hex, contract.compiled.template.suffix_hex);
        artifact.verify_template_plan().expect("capsule template receipt verifies");

        let mut corrupted = artifact.clone();
        let receipt = corrupted
            .argent
            .template_plan
            .templates
            .iter_mut()
            .find(|template| template.actor == "ReserveAsset")
            .expect("ReserveAsset template receipt exists");
        let handle = receipt.actor_type_handle.as_mut().expect("expanded actor exposes a capsule handle");
        let mut prefix = crate::codec::decode_hex(&handle.template.prefix_hex).expect("capsule prefix decodes");
        *prefix.last_mut().expect("capsule prefix contains context") ^= 1;
        handle.template.prefix_hex = encode_hex(&prefix);
        let err = corrupted.verify_template_plan().expect_err("corrupted capsule context is rejected");
        assert!(matches!(err, TemplatePlanError::ActorTypeHandleMismatch { .. }), "unexpected error: {err}");

        let mut corrupted = artifact.clone();
        let handle = corrupted
            .argent
            .template_plan
            .templates
            .iter_mut()
            .find(|template| template.actor == "ReserveAsset")
            .and_then(|template| template.actor_type_handle.as_mut())
            .expect("ReserveAsset capsule handle exists");
        handle.template.hash_hex = "00".repeat(32);
        let err = corrupted.verify_template_plan().expect_err("corrupted capsule hash is rejected");
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
        let module = crate::parser::parse_module(
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
                entry step() emits one Forager {
                    ForagerState next_state = {
                        strategy: {
                            hunger: strategy.hunger + 1,
                        },
                    };

                    become Forager(next_state);
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
        let err = emit_actor(actor, &model).expect_err("untyped virtual slot payload must be rejected");

        assert!(err.to_string().contains("must use `ForagerStrategy { ... }`"), "unexpected error: {err}");
    }

    #[test]
    fn builds_examples_with_compiled_artifacts() {
        assert_example_build_artifact(
            "examples/tickets.ag",
            "tickets",
            &[
                ("Issuer", "edcdc16f35a3a5fb4b128879c4d06bb83c83533135aa06b22975334dc0b785b5"),
                ("Ticket", "701a0a1f8be9e25c8af238ae081dd2a654ed76891e854bc711ac2c293d8c4f40"),
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
                covid kcc20_covid;
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
                entry mint(minted_amount: int)
                observes asset by self.kcc20_covid {
                    inputs {
                        proxy: MinterProxy;
                    }

                    outputs {
                        proxy: MinterProxy;
                        recipient: KCC20;
                    }
                }
                emits {
                    controller: Minter;
                } {
                    MinterState next_minter = {
                        kcc20_covid: kcc20_covid,
                        amount: amount - minted_amount,
                    };

                    become controller <- Minter(next_minter);
                }
            }

            app Test {
                actor Minter;
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
        assert_eq!(
            observe.inputs.iter().map(|input| (input.name.as_str(), input.actor.as_str())).collect::<Vec<_>>(),
            vec![("proxy", "MinterProxy")]
        );
        assert_eq!(
            observe.outputs.iter().map(|output| (output.name.as_str(), output.actor.as_str())).collect::<Vec<_>>(),
            vec![("proxy", "MinterProxy"), ("recipient", "KCC20")]
        );
        assert_eq!(
            mint.hidden_params.iter().map(|param| (param.name.as_str(), &param.subject, param.purpose)).collect::<Vec<_>>(),
            vec![
                (
                    "gen__asset_minter_proxy_prefix_len",
                    &HiddenParamSubjectArtifact::ObservedActor {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Input,
                        handle: "proxy".to_string(),
                        actor: "MinterProxy".to_string(),
                    },
                    HiddenParamPurposeArtifact::TemplatePrefixLen,
                ),
                (
                    "gen__asset_minter_proxy_suffix_len",
                    &HiddenParamSubjectArtifact::ObservedActor {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Input,
                        handle: "proxy".to_string(),
                        actor: "MinterProxy".to_string(),
                    },
                    HiddenParamPurposeArtifact::TemplateSuffixLen,
                ),
                (
                    "gen__asset_kcc20_prefix",
                    &HiddenParamSubjectArtifact::ObservedActor {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Output,
                        handle: "recipient".to_string(),
                        actor: "KCC20".to_string(),
                    },
                    HiddenParamPurposeArtifact::TemplatePrefixBytes,
                ),
                (
                    "gen__asset_kcc20_suffix",
                    &HiddenParamSubjectArtifact::ObservedActor {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Output,
                        handle: "recipient".to_string(),
                        actor: "KCC20".to_string(),
                    },
                    HiddenParamPurposeArtifact::TemplateSuffixBytes,
                ),
            ]
        );
        assert_eq!(
            mint.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "witness/observed/asset/input/minter_proxy/template_prefix_len",
                "witness/observed/asset/input/minter_proxy/template_suffix_len",
                "witness/observed/asset/output/kcc20/template_prefix_bytes",
                "witness/observed/asset/output/kcc20/template_suffix_bytes",
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
                (
                    "gen__asset_minter_proxy_template",
                    RuntimeFieldRoleArtifact::ObservedTemplate {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Input,
                        handle: "proxy".to_string(),
                        contract: "MinterProxy".to_string(),
                    },
                ),
                (
                    "gen__asset_kcc20_template",
                    RuntimeFieldRoleArtifact::ObservedTemplate {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Output,
                        handle: "recipient".to_string(),
                        contract: "KCC20".to_string(),
                    },
                ),
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
            state LocalState {}

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step(unused: int, target_id: covid)
                observes asset by target_id {
                    inputs {
                        foreign: Foreign;
                    }
                }
                emits none {
                    require(unused >= 0);
                }
            }

            app Test {
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
                entry step(first: covid, second: covid)
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
            err.to_string().contains("covenant id source must be a `self.<field>` state field or entry argument of type `covid`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn observe_covenant_id_source_requires_covid_type() {
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

        assert!(err.to_string().contains("has type `byte[32]`; expected `covid`"), "unexpected error: {err}");
    }

    #[test]
    fn observe_covenant_id_state_fields_require_self() {
        let err = parse_and_validate(
            r#"
            state LocalState {
                covid target_id;
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
                covid target_id;
                actor_type<ForeignState> foreign_type;
            }

            actor Local owns LocalState {
                entry step()
                observes asset by self.target_id {
                    inputs {
                        foreign: foreign_type;
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
                        next_pair: pair_type;
                    }
                }
                emits none {
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
                covid remote_id;
                actor_type<RemoteState> target;
            }

            actor Local owns LocalState {
                entry inspect(self_target: actor_type<RemoteState>)
                observes remote by self.remote_id {
                    inputs {
                        stored: self.target;
                        argument: self_target;
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
                "gen__remote_self_target_prefix_len",
                "gen__remote_self_target_suffix_len",
                "gen__remote_arg_self_target_prefix_len",
                "gen__remote_arg_self_target_suffix_len",
            ]
        );
    }

    #[test]
    fn observed_slots_lower_to_foreign_state_checks() {
        let out_dir = std::env::temp_dir().join(format!("argent-icc-observed-input-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);

        let program = crate::loader::load_program(Path::new("examples/icc/minter.ag")).expect("ICC example loads");
        emit_build(&program, &out_dir).expect("ICC example builds");

        let minter_sil = fs::read_to_string(out_dir.join("sil/Minter.sil")).expect("Minter.sil exists");
        assert!(minter_sil.contains("contract Minter(\n    byte[32] gen__init_asset_minter_proxy_template,"), "{minter_sil}");
        assert!(minter_sil.contains("entrypoint function mint(\n"), "{minter_sil}");
        assert!(minter_sil.contains("sig owner_sig,"), "{minter_sil}");
        assert!(minter_sil.contains("byte[32] recipient_owner,"), "{minter_sil}");
        assert!(minter_sil.contains("int gen__asset_minter_proxy_prefix_len,"), "{minter_sil}");
        assert!(minter_sil.contains("byte[] gen__asset_kcc20_suffix"), "{minter_sil}");
        assert!(
            minter_sil.contains("byte[32] gen__asset_minter_proxy_template = gen__init_asset_minter_proxy_template;"),
            "{minter_sil}"
        );
        assert!(minter_sil.contains("struct MinterProxyState"), "{minter_sil}");
        assert!(minter_sil.contains("struct KCC20State"), "{minter_sil}");
        assert!(minter_sil.contains("byte[32] gen__asset_cov_id = kcc20_covid; // observe asset"), "{minter_sil}");
        assert!(minter_sil.contains("require(OpCovInputCount(gen__asset_cov_id) == 1);"), "{minter_sil}");
        assert!(minter_sil.contains("require(OpCovOutputCount(gen__asset_cov_id) == 2);"), "{minter_sil}");
        assert!(!minter_sil.contains("gen__asset_minter_proxy_prefix.length"), "{minter_sil}");
        assert!(!minter_sil.contains("gen__asset_minter_proxy_suffix.length"), "{minter_sil}");
        assert!(minter_sil.contains("MinterProxyState gen__asset_proxy_state = readInputStateWithTemplate("), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_proxy_input_idx,"), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_minter_proxy_template"), "{minter_sil}");
        assert!(minter_sil.contains("// :: observed output asset.proxy: MinterProxy"), "{minter_sil}");
        assert!(minter_sil.contains("int gen__asset_proxy_output_idx = OpCovOutputIdx(gen__asset_cov_id, 0);"), "{minter_sil}");
        assert!(minter_sil.contains("// :: observed output asset.recipient: KCC20"), "{minter_sil}");
        assert!(minter_sil.contains("int gen__asset_recipient_output_idx = OpCovOutputIdx(gen__asset_cov_id, 1);"), "{minter_sil}");
        assert!(
            minter_sil.contains("validateOutputStateWithInputTemplate(\n            gen__asset_proxy_output_idx,"),
            "{minter_sil}"
        );
        assert!(minter_sil.contains("gen__asset_proxy_input_idx,"), "{minter_sil}");
        assert!(minter_sil.contains("validateOutputStateWithTemplate(\n            gen__asset_recipient_output_idx,"), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_kcc20_template"), "{minter_sil}");
        assert!(minter_sil.contains("MinterProxyState prev_proxy = gen__asset_proxy_state;"), "{minter_sil}");

        let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");
        artifact.verify_template_plan().expect("observed witness receipts verify");

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn icc_asset_lowers_covid_co_spend_and_else_if() {
        let out_dir = std::env::temp_dir().join(format!("argent-icc-asset-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);

        let program = crate::loader::load_program(Path::new("examples/icc/kcc20_asset.ag")).expect("ICC asset app loads");
        emit_build(&program, &out_dir).expect("ICC asset app builds");

        let kcc20_sil = fs::read_to_string(out_dir.join("sil/KCC20.sil")).expect("KCC20.sil exists");
        assert!(kcc20_sil.contains("} else if (identifier_type == IDENTIFIER_COVENANT_ID) {"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("require(checkSig(owner_sig, owner_identifier));"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("// :: co-spent with owner_identifier"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("require(OpCovInputCount(owner_identifier) > 0);"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("State next_state = {"), "{kcc20_sil}");

        let proxy_sil = fs::read_to_string(out_dir.join("sil/MinterProxy.sil")).expect("MinterProxy.sil exists");
        assert!(proxy_sil.contains("byte[32] controller_id = init_controller_id;"), "{proxy_sil}");
        assert!(proxy_sil.contains("entrypoint function mint(\n        State next_proxy,"), "{proxy_sil}");
        assert!(proxy_sil.contains("// :: co-spent with controller_id"), "{proxy_sil}");
        assert!(proxy_sil.contains("require(OpCovInputCount(controller_id) > 0);"), "{proxy_sil}");

        let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");
        let proxy_entry =
            artifact.sil_abi.contract("MinterProxy").expect("MinterProxy ABI exists").entry("mint").expect("mint ABI exists");
        assert_eq!(proxy_entry.params[0].name, "next_proxy");
        assert_eq!(proxy_entry.params[0].ty, TypeArtifact::Struct { name: "State".to_string() });

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn rejects_co_spent_on_non_covid_value() {
        let out_dir = std::env::temp_dir().join(format!("argent-co-spent-type-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);
        let module = crate::parser::parse_module(
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
                covid target_id;
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
                        foreign: Foreign;
                    }
                }
                observes asset by self.target_id {
                    outputs {
                        foreign: Foreign;
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
        .expect_err("duplicate observe names must be rejected");

        assert!(err.to_string().contains("declares observe `asset` more than once"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_duplicate_observed_handles() {
        let err = parse_and_validate(
            r#"
            state ForeignState {}
            state LocalState {
                covid target_id;
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
                        foreign: Foreign;
                        foreign: Foreign;
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
        .expect_err("duplicate observed handles must be rejected");

        assert!(err.to_string().contains("observe `asset` declares input `foreign` more than once"), "unexpected error: {err}");
    }

    #[test]
    fn observed_template_witnesses_are_keyed_by_actor_not_handle() {
        let (sil, artifact) = emit_fixture("observed_template_witnesses", "Local");

        assert_eq!(sil, include_str!("../tests/fixtures/emit/observed_template_witnesses/Local.sil"));

        assert_eq!(
            runtime_state_plan(&artifact, "Local")
                .expect("Local runtime state role overlay exists")
                .field_roles
                .iter()
                .map(|role| (role.name.as_str(), role.role.clone()))
                .collect::<Vec<_>>(),
            vec![(
                "gen__asset_foreign_template",
                RuntimeFieldRoleArtifact::ObservedTemplate {
                    observe: "asset".to_string(),
                    side: ObservedActorSideArtifact::Input,
                    handle: "src".to_string(),
                    contract: "Foreign".to_string(),
                },
            )]
        );

        let local_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local artifact actor exists");
        let step = local_actor.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
        assert_eq!(step.observes[0].covenant_id_source, CovenantIdSourceArtifact::StateField { field: "target_id".to_string() });
        assert_eq!(
            step.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            vec!["gen__asset_foreign_prefix_len", "gen__asset_foreign_suffix_len"]
        );
        assert_eq!(
            step.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "witness/observed/asset/input/foreign/template_prefix_len",
                "witness/observed/asset/input/foreign/template_suffix_len",
            ]
        );
    }

    #[test]
    fn consumed_route_reuses_input_template() {
        let (sil, artifact) = emit_fixture("input_template_route_reuse", "Controller");

        assert_eq!(sil, include_str!("../tests/fixtures/emit/input_template_route_reuse/Controller.sil"));

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
    fn open_observed_actor_binding_lowers_to_runtime_template_handle() {
        let (sil, artifact) = emit_fixture("open_observed_actor_binding", "Cell");

        assert_eq!(sil, include_str!("../tests/fixtures/emit/open_observed_actor_binding/Cell.sil"));

        assert!(runtime_state_plan(&artifact, "Cell").is_none(), "{:#?}", artifact.argent.template_plan.runtime_states);

        let cell_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Cell").expect("Cell artifact actor exists");
        let advance = cell_actor.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
        let observe = advance.observes.first().expect("advance observes remote");
        assert_eq!(observe.inputs[0].open_state.as_deref(), Some("AgentCapsule"));
        assert_eq!(observe.outputs[0].open_state.as_deref(), Some("AgentCapsule"));
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

        assert_eq!(sil, include_str!("../tests/fixtures/emit/open_observed_state_handle/Cell.sil"));

        assert!(runtime_state_plan(&artifact, "Cell").is_none(), "{:#?}", artifact.argent.template_plan.runtime_states);

        let cell_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Cell").expect("Cell artifact actor exists");
        let advance = cell_actor.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
        let observe = advance.observes.first().expect("advance observes remote");
        assert_eq!(observe.inputs[0].actor, "self.agent_type");
        assert_eq!(observe.outputs[0].actor, "self.agent_type");
        assert_eq!(observe.inputs[0].open_state.as_deref(), Some("AgentCapsule"));
        assert_eq!(observe.outputs[0].open_state.as_deref(), Some("AgentCapsule"));
        assert_eq!(
            advance.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            vec!["gen__remote_self_agent_type_prefix_len", "gen__remote_self_agent_type_suffix_len"]
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
                covid agent_covid;
            }

            actor Cell owns CellState {
                entry inspect()
                observes remote by self.agent_covid {
                    inputs {
                        agent: actor_type<AgentCapsule> as observed_agent;
                    }
                }
                emits none {
                    AgentCapsule prev_state = remote.inputs.agent.state;
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
                covid target_id;
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
                        a: Foreign;
                        b: Foreign;
                    }
                }
                emits none {
                    ForeignState next = {
                        amount: 1,
                    };

                    require asset.outputs become {
                        a <- Foreign(next);
                    };
                }
            }

            app Test {
                actor Local;
            }
            "#,
        );

        assert!(err.to_string().contains("observe `asset` does not validate output `b`"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_observed_output_become_actor_mismatch() {
        let err = emit_inline_error(
            r#"
            state ForeignState {
                int amount;
            }

            state LocalState {
                covid target_id;
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
                        next: ForeignA;
                    }
                }
                emits none {
                    ForeignState next_state = {
                        amount: 1,
                    };

                    require asset.outputs become {
                        next <- ForeignB(next_state);
                    };
                }
            }

            app Test {
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

        let program = crate::loader::load_program(Path::new("examples/stones/app.ag")).expect("stones example loads");
        emit_build(&program, &out_dir).expect("stones example builds");
        let player_sil = fs::read_to_string(out_dir.join("sil/Player.sil")).expect("Player.sil exists");
        let league_sil = fs::read_to_string(out_dir.join("sil/League.sil")).expect("League.sil exists");
        let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");

        assert!(player_sil.contains("entrypoint function accept_start(\n"), "{player_sil}");
        assert!(player_sil.contains("sig owner_sig,"), "{player_sil}");
        assert!(player_sil.contains("pubkey owner_pk,"), "{player_sil}");
        assert!(player_sil.contains("int gen__player_prefix_len,"), "{player_sil}");
        assert!(player_sil.contains("int gen__player_suffix_len"), "{player_sil}");
        assert!(!player_sil.contains("entrypoint function accept_start(sig owner_sig, pubkey owner_pk, byte[]"), "{player_sil}");
        assert!(player_sil.contains("entrypoint function start_game(\n"), "{player_sil}");
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
        assert!(player_sil.contains("validateOutputState(gen__self_out_output_idx, next_self);"), "{player_sil}");
        assert!(player_sil.contains("validateOutputState(gen__opponent_out_output_idx, next_opponent);"), "{player_sil}");
        assert!(player_sil.contains("validateOutputStateWithTemplate(\n            gen__game_output_idx,"), "{player_sil}");
        assert!(league_sil.contains("entrypoint function register_player(\n"), "{league_sil}");
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
        assert_eq!(
            player_runtime_plan.field_roles[2].role,
            RuntimeFieldRoleArtifact::Template { contract: "StonesSettle".to_string() }
        );
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
        let register_player =
            league_actor.entries.iter().find(|entry| entry.name == "register_player").expect("register_player exists");
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
    fn direct_route_families_are_inferred_without_hints() {
        let artifact = inline_artifact("toy-chess-family", &toy_chess_source());
        let families = artifact.argent.template_plan.route_families.iter().map(|family| {
            (
                family.id.as_str(),
                family.state.as_str(),
                family.anchor_actor.as_str(),
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
                (
                    "gen__mux_routes",
                    RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["Pawn".to_string(), "Knight".to_string()] }
                ),
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
        assert_eq!(choose_knight_const.routes.iter().map(|route| route.actor.as_str()).collect::<Vec<_>>(), vec!["Knight"]);
        artifact.verify_template_plan().expect("template plan receipt verifies inferred route family");
    }

    #[test]
    fn toy_chess_sil_uses_one_level_route_family_shape() {
        let path = PathBuf::from("toy-chess-shape.ag");
        let module = crate::parser::parse_module(path.clone(), toy_chess_source()).expect("toy chess source parses");
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
        assert!(player_sil.contains("entrypoint function enter_mux(\n"), "{player_sil}");
        assert!(player_sil.contains("byte[] gen__mux_prefix,"), "{player_sil}");
        assert!(player_sil.contains("byte[] gen__mux_suffix,"), "{player_sil}");
        assert!(player_sil.contains("byte[64] gen__mux_routes"), "{player_sil}");
        assert!(player_sil.contains("require(blake2b(gen__mux_routes) == gen__mux_routes_digest);"), "{player_sil}");
        assert!(!player_sil.contains("gen__pawn_template"), "{player_sil}");
        assert!(!player_sil.contains("gen__knight_template"), "{player_sil}");

        let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
        assert!(mux_sil.contains("byte[64] gen__init_mux_routes"), "{mux_sil}");
        assert!(mux_sil.contains("byte[64] gen__mux_routes = gen__init_mux_routes;"), "{mux_sil}");
        assert!(
            mux_sil.contains("entrypoint function choose(int target, byte[] gen__target_prefix, byte[] gen__target_suffix)"),
            "{mux_sil}"
        );
        assert!(mux_sil.contains("if (target == 1 /*KNIGHT*/)"), "{mux_sil}");
        assert!(mux_sil.contains("int gen__target_selector = target;"), "{mux_sil}");
        assert!(mux_sil.contains("require(gen__target_selector >= 0);"), "{mux_sil}");
        assert!(mux_sil.contains("require(gen__target_selector < 2);"), "{mux_sil}");
        assert!(mux_sil.contains("byte[32] gen__target_template = byte[32]("), "{mux_sil}");
        assert!(mux_sil.contains("gen__mux_routes.slice(gen__target_selector * 32, gen__target_selector * 32 + 32)"), "{mux_sil}");
        assert!(mux_sil.contains("validateOutputStateWithTemplate(\n            gen__next_output_idx,"), "{mux_sil}");
        assert!(mux_sil.contains("gen__target_prefix,"), "{mux_sil}");
        assert!(mux_sil.contains("gen__target_template"), "{mux_sil}");
        assert!(
            mux_sil.contains("entrypoint function choose_knight_const(byte[] gen__target_prefix, byte[] gen__target_suffix)"),
            "{mux_sil}"
        );
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
    fn actor_enum_order_drives_route_table_order() {
        let source = toy_chess_source().replace(
            "actor enum MoveActor {\n                Pawn;\n                Knight;\n            }",
            "actor enum MoveActor {\n                Knight;\n                Pawn;\n            }",
        );
        let path = PathBuf::from("toy-chess-selector-order.ag");
        let module = crate::parser::parse_module(path.clone(), source).expect("toy chess source parses");
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
    fn fixed_actor_enum_selector_still_builds_full_selector_table() {
        let path = PathBuf::from("fixed-selector-table.ag");
        let module = crate::parser::parse_module(
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
                entry choose_knight_const() emits one MoveActor {
                    BoardState next_board = {
                        ply: ply + 1,
                    };

                    actor_type<BoardState> target = MoveActor::Knight;
                    become target(next_board);
                }
            }

            actor Pawn owns BoardState {
                entry idle() emits none {
                    require(ply >= 0);
                }
            }

            actor Knight owns BoardState {
                entry idle() emits none {
                    require(ply >= 0);
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
        assert_eq!(choose_knight_const.routes.iter().map(|route| route.actor.as_str()).collect::<Vec<_>>(), vec!["Knight"]);

        let mux_sil = actor_sil.get("Mux").expect("Mux Sil is emitted");
        assert!(mux_sil.contains("int gen__target_selector = 1 /*KNIGHT*/;"), "{mux_sil}");
        assert!(mux_sil.contains("byte[32] gen__target_template = byte[32]("), "{mux_sil}");
        assert!(mux_sil.contains("gen__mux_routes.slice(gen__target_selector * 32, gen__target_selector * 32 + 32)"), "{mux_sil}");
        artifact.verify_template_plan().expect("template plan receipt verifies");
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
                entry choose_first(target: FirstMove) emits one FirstMove {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become target(next_board);
                }

                entry choose_second(target: SecondMove) emits one SecondMove {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become target(next_board);
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
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };

        let err = Model::from_program(&program).expect_err("conflicting actor enum orders must be rejected");
        assert!(err.to_string().contains("different selector order"), "unexpected error: {err}");
    }

    #[test]
    fn actor_enum_selectors_must_cover_the_inferred_route_family() {
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
                Pawn;
                Bishop;
            }

            actor Mux owns BoardState {
                entry choose_first(target: FirstMove) emits one FirstMove {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become target(next_board);
                }

                entry choose_second(target: SecondMove) emits one SecondMove {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become target(next_board);
                }
            }

            actor Pawn owns BoardState {}
            actor Knight owns BoardState {}
            actor Bishop owns BoardState {}

            app IncompleteSelectorSet {
                actor Mux;
                actor Pawn;
                actor Knight;
                actor Bishop;
            }
        "#;
        let path = PathBuf::from("incomplete-selector-set.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };

        let err = Model::from_program(&program).expect_err("incomplete route-family selector sets must be rejected");
        assert!(err.to_string().contains("variants must exactly match the route table actors"), "unexpected error: {err}");
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
        let module = crate::parser::parse_module(path.clone(), artifact_source.to_string()).expect("source parses");
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
                entry to_b() emits one B {
                    BoardState next = {
                        n: n + 1,
                    };

                    become B(next);
                }
            }

            actor B owns BoardState {
                entry to_a() emits one A {
                    BoardState next = {
                        n: n + 1,
                    };

                    become A(next);
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
        artifact.verify_template_plan().expect("direct two-actor route plan verifies");
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
                entry to_b() emits one B {
                    BoardState next = {
                        n: n + 1,
                    };

                    become B(next);
                }
            }

            actor B owns BoardState {
                entry to_c() emits one C {
                    BoardState next = {
                        n: n + 1,
                    };

                    become C(next);
                }
            }

            actor C owns BoardState {
                entry to_a() emits one A {
                    BoardState next = {
                        n: n + 1,
                    };

                    become A(next);
                }
            }

            actor D owns BoardState {
                entry to_e() emits one E {
                    BoardState next = {
                        n: n + 1,
                    };

                    become E(next);
                }
            }

            actor E owns BoardState {
                entry to_f() emits one F {
                    BoardState next = {
                        n: n + 1,
                    };

                    become F(next);
                }
            }

            actor F owns BoardState {
                entry to_d() emits one D {
                    BoardState next = {
                        n: n + 1,
                    };

                    become D(next);
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
                    family.anchor_actor.as_str(),
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
                        RouteTemplateLeafArtifact::Template { actor: "B".to_string(), template_id: "template/b".to_string() },
                        RouteTemplateLeafArtifact::Template { actor: "C".to_string(), template_id: "template/c".to_string() },
                    ],
                ),
                (
                    "route_table/BoardState/gen__d_routes",
                    vec![
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
            vec![
                ("gen__a_template", RuntimeFieldRoleArtifact::Template { contract: "A".to_string() }),
                ("gen__a_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["B".to_string(), "C".to_string()] }),
                ("gen__d_template", RuntimeFieldRoleArtifact::Template { contract: "D".to_string() }),
                ("gen__d_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["E".to_string(), "F".to_string()] }),
            ]
        );
        artifact.verify_template_plan().expect("multi-family route state receipt verifies");
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
                entry enter_a() emits one HubA {
                    BoardState next = {
                        n: n,
                    };

                    become HubA(next);
                }
            }

            actor PlayerB owns PlayerState {
                entry enter_b() emits one HubB {
                    BoardState next = {
                        n: n,
                    };

                    become HubB(next);
                }
            }

            actor HubB owns BoardState {
                entry to_leaf() emits one Leaf {
                    BoardState next = {
                        n: n + 1,
                    };

                    become Leaf(next);
                }
            }

            actor HubA owns BoardState {
                entry to_leaf() emits one Leaf {
                    BoardState next = {
                        n: n + 1,
                    };

                    become Leaf(next);
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
            vec![("gen__leaf_template", RuntimeFieldRoleArtifact::Template { contract: "Leaf".to_string() })]
        );
        artifact.verify_template_plan().expect("direct route plan verifies");
    }

    #[test]
    fn route_family_with_multiple_external_entries_uses_first_entry_as_anchor() {
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
                entry enter_a() emits one HubA {
                    BoardState next = {
                        n: n,
                    };

                    become HubA(next);
                }
            }

            actor PlayerB owns PlayerState {
                entry enter_b() emits one HubB {
                    BoardState next = {
                        n: n,
                    };

                    become HubB(next);
                }
            }

            actor HubB owns BoardState {
                entry to_leaf_a() emits one LeafA {
                    BoardState next = {
                        n: n + 1,
                    };

                    become LeafA(next);
                }
            }

            actor HubA owns BoardState {
                entry to_leaf_b() emits one LeafB {
                    BoardState next = {
                        n: n + 1,
                    };

                    become LeafB(next);
                }
            }

            actor LeafA owns BoardState {
                entry to_a() emits one HubA {
                    BoardState next = {
                        n: n + 1,
                    };

                    become HubA(next);
                }
            }

            actor LeafB owns BoardState {
                entry to_b() emits one HubB {
                    BoardState next = {
                        n: n + 1,
                    };

                    become HubB(next);
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
        assert_eq!(family.anchor_actor, "HubB");
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
        artifact.verify_template_plan().expect("multi-entry route family receipt verifies");
    }

    fn inline_artifact(name: &str, source: &str) -> Artifact {
        let path = PathBuf::from(format!("{name}.ag"));
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");
        let actor_sil = actor_sil_for_model(&model);
        emit_artifact(&program, &model, &actor_sil).expect("artifact emits")
    }

    #[test]
    fn genesis_spawn_lowers_to_pinned_sil_and_artifact_metadata() {
        let (controller_sil, controller_artifact) =
            emit_selected_fixture("tests/fixtures/runtime/context_genesis_spawn/app.ag", "ControllerApp", "Controller");
        assert_eq!(controller_sil, include_str!("../tests/fixtures/runtime/context_genesis_spawn/Controller.sil"));
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
                "gen__spawn_self_pair_type_prefix",
                "gen__spawn_self_pair_type_suffix",
            ]
        );
        controller_artifact.verify_template_plan().expect("spawn metadata verifies");
        let mut malformed = controller_artifact.clone();
        malformed.argent.actors[0].entries[0].spawns[0].outputs[1].group_index = 2;
        assert!(
            matches!(malformed.verify_template_plan(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
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
            matches!(noncanonical_template_subject.verify_template_plan(), Err(TemplatePlanError::InvalidSpawnMetadata { .. })),
            "shared spawn template witnesses must use their first output as subject"
        );

        let (pair_sil, _) = emit_selected_fixture("tests/fixtures/runtime/context_genesis_spawn/app.ag", "PairApp", "Pair");
        assert_eq!(pair_sil, include_str!("../tests/fixtures/runtime/context_genesis_spawn/Pair.sil"));
    }

    #[test]
    fn multiple_genesis_spawns_lower_to_pinned_sil_and_artifact_metadata() {
        let source = "tests/fixtures/runtime/context_multiple_genesis_spawns/app.ag";
        let (controller_sil, controller_artifact) = emit_selected_fixture(source, "ControllerApp", "Controller");
        assert_eq!(controller_sil, include_str!("../tests/fixtures/runtime/context_multiple_genesis_spawns/Controller.sil"));
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
                "gen__spawn_self_pair_type_prefix",
                "gen__spawn_self_pair_type_suffix",
            ]
        );
        controller_artifact.verify_template_plan().expect("multiple-spawn metadata verifies");

        let (pair_sil, _) = emit_selected_fixture(source, "PairApp", "Pair");
        assert_eq!(pair_sil, include_str!("../tests/fixtures/runtime/context_multiple_genesis_spawns/Pair.sil"));
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
                entry launch(self_pair_type: actor_type<PairState>)
                spawns stored by stored_id {
                    outputs {
                        pair: self.pair_type;
                    }
                }
                spawns argument by argument_id {
                    outputs {
                        pair: self_pair_type;
                    }
                }
                emits one Launcher {
                    PairState stored_pair = { value: 1 };
                    PairState argument_pair = { value: 2 };
                    require stored.outputs become {
                        pair <- self.pair_type(stored_pair);
                    };
                    require argument.outputs become {
                        pair <- self_pair_type(argument_pair);
                    };
                    become Launcher(self.state);
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
                "gen__spawn_self_pair_type_prefix",
                "gen__spawn_self_pair_type_suffix",
                "gen__spawn_arg_self_pair_type_prefix",
                "gen__spawn_arg_self_pair_type_suffix",
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
                        pair: self.first_type;
                    }
                }
                emits one Launcher {
                    PairState pair = { value: 1 };
                    require child.outputs become {
                        pair <- self.first_type(pair);
                    };
                    become Launcher(self.state);
                }

                entry launch_second()
                spawns child by child_id {
                    outputs {
                        pair: self.second_type;
                    }
                }
                emits one Launcher {
                    PairState pair = { value: 2 };
                    require child.outputs become {
                        pair <- self.second_type(pair);
                    };
                    become Launcher(self.state);
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
        assert_eq!(first_recipe.recipe_id, "witness/Launcher/launch_first/spawn/child/pair/template_prefix_bytes");
        assert_eq!(second_recipe.recipe_id, "witness/Launcher/launch_second/spawn/child/pair/template_prefix_bytes");
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
                        pair: self.pair_type;
                    }
                }
                spawns second by second_id {
                    outputs {
                        pair: self.pair_type;
                    }
                }
                emits one Launcher {
                    PairState pair = { value: 1 };
                    require first.outputs become {
                        pair <- self.pair_type(pair);
                    };
                    require second.outputs become {
                        pair <- self.pair_type(pair);
                    };
                    become Launcher(self.state);
                }
            }

            app Test {
                actor Launcher;
            }
        "#;
        let path = PathBuf::from("test.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");
        let sil = emit_actor(model.actor("Launcher").expect("launcher exists"), &model).expect("Launcher emits");
        assert!(sil.contains("require(gen__first_pair_output_idx < gen__second_pair_output_idx);"), "{sil}");
        let actor_sil = actor_sil_for_model(&model);
        emit_artifact(&program, &model, &actor_sil).expect("generated Sil compiles");
    }

    #[test]
    fn rejects_spawn_name_shared_with_observe() {
        let err = parse_and_validate(
            r#"
            state PairState {}
            state LauncherState {
                covid observed_id;
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch()
                observes pair by self.observed_id {}
                spawns pair by pair_id {
                    outputs {
                        next_pair: self.pair_type;
                    }
                }
                emits one Launcher {
                    require(1 == 1);
                    become Launcher(self.state);
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
                covid pair_id;
                actor_type<PairState> pair_type;
            }

            actor Launcher owns LauncherState {
                entry launch()
                spawns pair by pair_id {
                    outputs {
                        next_pair: self.pair_type;
                    }
                }
                emits one Launcher {
                    require(1 == 1);
                    become Launcher(self.state);
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

    fn emit_fixture(case: &str, actor: &str) -> (String, Artifact) {
        let path = PathBuf::from("tests/fixtures/emit").join(case).join("app.ag");
        let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&path)).expect("fixture source exists");
        let module = crate::parser::parse_module(path.clone(), source).expect("fixture source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("fixture model validates");
        let actor = model.actor(actor).expect("fixture actor exists");
        let sil = emit_actor(actor, &model).expect("fixture actor emits");
        let actor_sil = actor_sil_for_model(&model);
        let artifact = emit_artifact(&program, &model, &actor_sil).expect("fixture artifact emits");
        (sil, artifact)
    }

    fn emit_selected_fixture(path: &str, app: &str, actor: &str) -> (String, Artifact) {
        let path = PathBuf::from(path);
        let source = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&path)).expect("fixture source exists");
        let module = crate::parser::parse_module(path.clone(), source).expect("fixture source parses");
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
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");
        for actor in &model.actors {
            if let Err(err) = emit_actor(actor, &model) {
                return err;
            }
        }
        panic!("expected inline source to fail during emission")
    }

    fn parse_and_validate(source: &str) -> Result<()> {
        let path = PathBuf::from("test.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string())?;
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
                entry register() emits one Player {
                    PlayerState next_player = {
                        nonce: nonce,
                    };
                    become Player(next_player);
                }
            }

            actor Player owns PlayerState {
                entry enter_mux() emits one Mux {
                    BoardState next_board = {
                        selector: nonce,
                        ply: 0,
                    };
                    become Mux(next_board);
                }
            }

            actor Mux owns BoardState {
                entry choose(target: MoveActor) emits one MoveActor {
                    if (target == MoveActor::Knight) {
                        require(selector >= 0);
                    }

                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };

                    become target(next_board);
                }

                entry choose_knight_const() emits one MoveActor {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };

                    actor_type<BoardState> target = MoveActor::Knight;
                    become target(next_board);
                }

                entry choose_pawn() emits one Pawn {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become Pawn(next_board);
                }

                entry choose_knight() emits one Knight {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become Knight(next_board);
                }
            }

            actor Pawn owns BoardState {
                entry back_to_mux() emits one Mux {
                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become Mux(next_board);
                }
            }

            actor Knight owns BoardState {
                entry back_to_mux() emits one Mux {
                    require(selector >= 0);

                    BoardState next_board = {
                        selector: selector,
                        ply: ply + 1,
                    };
                    become Mux(next_board);
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
    fn artifact_codec_matches_silverscript_sigscript_builder() {
        let module = crate::parser::parse_module(
            PathBuf::from("test.ag"),
            r#"
            state FooState {
                int count;
                byte[4] tag;
                bool flag;
            }

            actor Foo owns FooState {
                entry bump(amount: int, next_tag: byte[4], next_flag: bool, b: byte) emits none {
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
        let bump = sil_contract.entries.iter().find(|entry| entry.name == "bump").expect("bump entry exists");
        let done = sil_contract.entries.iter().find(|entry| entry.name == "done").expect("done entry exists");
        assert_eq!(bump.selector, Some(0));
        assert_eq!(done.selector, Some(1));

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
        let sil_bump = compiled
            .build_sig_script("bump", vec![SilExpr::int(17), SilExpr::bytes(vec![1, 2, 3, 4]), SilExpr::bool(true), SilExpr::byte(1)])
            .expect("Sil bump sigscript builds");
        assert_eq!(portable_bump, sil_bump);

        let portable_done =
            crate::codec::encode_contract_entry_sig_script(&sil_abi, "Foo", "done", &[]).expect("portable done sigscript builds");
        let sil_done = compiled.build_sig_script("done", vec![]).expect("Sil done sigscript builds");
        assert_eq!(portable_done, sil_done);
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

        let program = crate::loader::load_program(Path::new(input)).expect("example loads");
        emit_build(&program, &out_dir).expect("example builds");
        let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");
        artifact.check_schema_version().expect("artifact schema version is supported");
        artifact.verify_template_plan().expect("template plan receipt verifies");

        let expected_hashes = expected_hashes.iter().copied().collect::<BTreeMap<_, _>>();
        assert!(!artifact.argent.actors.is_empty(), "artifact should contain Argent actors");
        for actor in &artifact.argent.actors {
            let sil_contract = artifact
                .sil_abi
                .contract(&actor.abi.actor)
                .unwrap_or_else(|| panic!("actor `{}` should reference a Sil ABI contract", actor.name));
            assert_compiled_projection(sil_contract.name.as_str(), &sil_contract.compiled);
            assert_runtime_state_round_trip(sil_contract, &sil_contract.compiled);
            if let Some(expected_hash) = expected_hashes.get(sil_contract.name.as_str()) {
                assert_eq!(&sil_contract.compiled.template.hash_hex, expected_hash, "actor `{}` template hash changed", actor.name);
            }
        }

        let _ = fs::remove_dir_all(out_dir);
    }

    fn assert_runtime_state_round_trip(actor: &SilContractArtifact, compiled: &CompiledContractArtifact) {
        let script = crate::codec::decode_hex(&compiled.script_hex).expect("script hex decodes");
        let state_start = compiled.state_span.offset;
        let state_end = state_start + compiled.state_span.len;
        let state_script = &script[state_start..state_end];
        let state_values =
            crate::codec::decode_runtime_state_script(&actor.runtime_state, state_script).expect("runtime state decodes");
        let reencoded =
            crate::codec::encode_runtime_state_script(&actor.runtime_state, &state_values).expect("runtime state re-encodes");
        assert_eq!(reencoded, state_script, "actor `{}` runtime state must re-encode byte-for-byte", actor.name);
    }

    fn assert_compiled_projection(actor: &str, compiled: &CompiledContractArtifact) {
        assert!(!compiled.script_hex.is_empty(), "actor `{actor}` should have script bytes");
        assert!(compiled.state_span.len > 0, "actor `{actor}` should have a non-empty state span");
        assert_eq!(compiled.template.hash_hex.len(), 64, "actor `{actor}` should have a 32-byte template hash");

        let state_start = compiled.state_span.offset * 2;
        let state_end = state_start + compiled.state_span.len * 2;
        assert!(state_end <= compiled.script_hex.len(), "actor `{actor}` state span should fit inside script hex");
        assert_eq!(
            &compiled.script_hex[..state_start],
            compiled.template.prefix_hex,
            "actor `{actor}` prefix must be the bytes before the state span"
        );
        assert_eq!(
            &compiled.script_hex[state_end..],
            compiled.template.suffix_hex,
            "actor `{actor}` suffix must be the bytes after the state span"
        );

        let state_hex = &compiled.script_hex[state_start..state_end];
        assert_eq!(
            format!("{}{}{}", compiled.template.prefix_hex, state_hex, compiled.template.suffix_hex),
            compiled.script_hex,
            "actor `{actor}` script must reconstruct from prefix, initial state, and suffix"
        );

        let prefix = crate::codec::decode_hex(&compiled.template.prefix_hex).expect("prefix hex decodes");
        let suffix = crate::codec::decode_hex(&compiled.template.suffix_hex).expect("suffix hex decodes");
        let template_hash = silverscript_lang::template::template_hash(&prefix, &suffix);
        assert_eq!(
            encode_hex(&template_hash),
            compiled.template.hash_hex,
            "actor `{actor}` template hash must use the canonical template hash"
        );
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
                                auth_index: 0,
                            }]),
                            body: String::new(),
                            routes: Vec::new(),
                            terminal_route_sets: Vec::new(),
                        }],
                    },
                    ActorDecl { name: "Game".to_string(), state: "GameState".to_string(), entries: Vec::new() },
                ],
                actor_enums: Vec::new(),
                apps: vec![AppDecl { name: "Test".to_string(), actors: vec!["Player".to_string(), "Game".to_string()] }],
            }],
        }
    }
}
