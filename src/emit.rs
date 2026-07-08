use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::artifact::*;
use crate::ast::*;
use crate::codec::encode_hex;
use crate::error::{ArgentError, Result};
use crate::lexer::{RESERVED_GENERATED_PREFIX, Token, TokenKind, lex};
use silverscript_lang::ast::Expr as SilExpr;
use silverscript_lang::compiler::{CompileOptions, CompiledContract, compile_contract};

pub fn emit_build(program: &Program, out_dir: impl AsRef<Path>) -> Result<()> {
    let out_dir = out_dir.as_ref();
    let sil_dir = out_dir.join("sil");
    fs::create_dir_all(&sil_dir).map_err(|err| ArgentError::at(out_dir, err.to_string()))?;

    let model = Model::from_program(program)?;
    let mut actor_sil = BTreeMap::new();
    for actor in &model.actors {
        let sil = emit_actor(actor, &model)?;
        fs::write(sil_dir.join(format!("{}.sil", actor.name)), &sil)
            .map_err(|err| ArgentError::at(sil_dir.join(format!("{}.sil", actor.name)), err.to_string()))?;
        actor_sil.insert(actor.name.clone(), sil);
    }

    fs::write(out_dir.join("manifest.json"), emit_manifest(program, &model))
        .map_err(|err| ArgentError::at(out_dir.join("manifest.json"), err.to_string()))?;

    fs::write(out_dir.join("artifact.json"), emit_artifact_json(program, &model, &actor_sil)?)
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

impl<'a> Model<'a> {
    fn from_program(program: &'a Program) -> Result<Self> {
        validate_unique_apps(program)?;
        let consts = collect_consts(program)?;
        let functions = collect_functions(program)?;
        let states = collect_states(program)?;
        let all_actors = collect_actors(program)?;
        let actor_enum_decls = collect_actor_enums(program)?;

        let app = program.apps().next();
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
            state_route_leaves,
        };
        model.validate()?;
        Ok(model)
    }

    fn state(&self, name: &str) -> Result<&StateDecl> {
        self.states.get(name).copied().ok_or_else(|| ArgentError::new(format!("unknown state `{name}`")))
    }

    fn actor(&self, name: &str) -> Result<&ActorDecl> {
        self.actors_by_name.get(name).copied().ok_or_else(|| ArgentError::new(format!("unknown actor `{name}`")))
    }

    fn actor_state(&self, name: &str) -> Result<&StateDecl> {
        let actor = self.actor(name)?;
        self.state(&actor.state)
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

    fn validate_reserved_identifiers(&self) -> Result<()> {
        reject_reserved_identifier("app", &self.app_name)?;
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
            reject_reserved_identifier("state", &state.name)?;
            for field in &state.fields {
                reject_reserved_identifier(&format!("state `{}` field", state.name), &field.name)?;
            }
        }
        for actor_enum in self.actor_enums.values() {
            reject_reserved_identifier("actor enum", &actor_enum.name)?;
        }
        for actor in self.actors_by_name.values() {
            reject_reserved_identifier("actor", &actor.name)?;
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
            self.validate_observed_open_bindings(actor, entry, observe)?;
            self.validate_observed_actor_handles(actor, entry, observe, "input", &observe.inputs)?;
            self.validate_observed_actor_handles(actor, entry, observe, "output", &observe.outputs)?;
        }
        Ok(())
    }

    fn validate_observed_open_bindings(&self, actor: &ActorDecl, entry: &EntryDecl, observe: &ObserveDecl) -> Result<()> {
        let mut bindings = BTreeMap::new();
        let mut source_names = self.state(&actor.state)?.fields.iter().map(|field| field.name.as_str()).collect::<BTreeSet<_>>();
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

    fn validate_observed_actor_handles(
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
            reject_duplicate_top_level("const", &konst.name, &module.path, &mut seen)?;
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
            reject_duplicate_top_level("fn", &function.name, &module.path, &mut seen)?;
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
            reject_duplicate_top_level("state", &state.name, &module.path, &mut seen)?;
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
            reject_duplicate_top_level("actor", &actor.name, &module.path, &mut seen)?;
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
        let is_actor_handle = matches!(&tokens[pos].kind, TokenKind::Ident(word) if word == "actor")
            && matches!(tokens[pos + 1].kind, TokenKind::Symbol('<'))
            && matches!(tokens[pos + 3].kind, TokenKind::Symbol('>'))
            && matches!(tokens.get(pos + 4).map(|token| &token.kind), Some(TokenKind::Ident(_)))
            && matches!(tokens.get(pos + 5).map(|token| &token.kind), Some(TokenKind::Symbol('=')));
        if is_actor_handle {
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
            "entry `{}::{}` declares actor handle `{name}` as actor<{expected_state}>, but `{actor_enum_name}` contains actor<{}>",
            ctx.actor.name,
            ctx.entry.name,
            actor_enum.state,
            name = request.name,
            actor_enum_name = request.actor_enum_name
        )));
    }
    if ctx.actor.state != actor_enum.state {
        return Err(ArgentError::new(format!(
            "entry `{}::{}` uses actor enum `{actor_enum_name}` for state `{}`, but the entry actor owns `{}`; selector handles currently require the same state",
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
            reject_duplicate_top_level("app", &app.name, &module.path, &mut seen)?;
        }
    }
    Ok(())
}

fn compute_state_template_deps<'a>(
    actors: &[&'a ActorDecl],
    actors_by_name: &BTreeMap<String, &'a ActorDecl>,
    template_actors: &[String],
    actor_enums: &BTreeMap<String, ActorEnumInfo>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let template_actor_set = template_actors.iter().cloned().collect::<BTreeSet<_>>();
    let mut direct = BTreeMap::<String, BTreeSet<String>>::new();
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();

    for actor in actors {
        direct.entry(actor.state.clone()).or_default();
        adjacency.entry(actor.state.clone()).or_default();

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
                adjacency.entry(actor.state.clone()).or_default().insert(target.state.clone());
                adjacency.entry(target.state.clone()).or_default().insert(actor.state.clone());

                if template_actor_set.contains(&route.actor)
                    && route_validation_kind(actor, &route) == RouteValidationKind::ForeignTemplate
                {
                    direct.entry(actor.state.clone()).or_default().insert(route.actor.clone());
                }
            }
        }
    }

    let mut result = BTreeMap::new();
    let mut visited = BTreeSet::new();
    for state in adjacency.keys() {
        if visited.contains(state) {
            continue;
        }
        let mut stack = vec![state.clone()];
        let mut component = BTreeSet::new();
        while let Some(next) = stack.pop() {
            if !visited.insert(next.clone()) {
                continue;
            }
            component.insert(next.clone());
            if let Some(neighbors) = adjacency.get(&next) {
                stack.extend(neighbors.iter().filter(|neighbor| !visited.contains(*neighbor)).cloned());
            }
        }

        let mut component_deps = BTreeSet::new();
        for component_state in &component {
            if let Some(state_deps) = direct.get(component_state) {
                component_deps.extend(state_deps.iter().cloned());
            }
        }
        for component_state in component {
            let ordered = template_actors.iter().filter(|actor| component_deps.contains(*actor)).cloned().collect::<Vec<_>>();
            result.insert(component_state, ordered.clone());
        }
    }

    Ok(result)
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
            if component.len() < 2 {
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
            if table_actors.is_empty() {
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
    let state = model.state(&actor.state)?;
    let mut out = String::new();
    out.push_str("pragma silverscript ^0.1.0;\n\n");
    out.push_str("// Generated by argentc. Do not edit by hand.\n");
    out.push_str("// This is plain Silverscript: no covenant macros are used.\n\n");

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
    }

    for state_name in state_names {
        if state_name == current_actor.state {
            continue;
        }
        if !emitted.insert(state_name.clone()) {
            continue;
        }
        let state = model.state(&state_name)?;
        out.push_str(&format!("    struct {} {{\n", state.name));
        emit_hidden_template_fields(out, state.name.as_str(), model, 8);
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
    let witness_specs = entry_witness_specs(actor, entry, model);
    let sil_params = lower_entry_params(actor, &entry.params, &witness_specs, model);
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

    if !entry.consumes.is_empty() {
        out.push_str("        // :: cov inputs\n");
        let cov_id = hidden_cov_id_name();
        out.push_str(&format!("        byte[32] {cov_id} = OpInputCovenantId(this.activeInputIndex);\n"));
        match entry.kind {
            EntryKind::Leader => {
                let count = entry.consumes.len() + 1;
                out.push_str(&format!("        require(OpCovInputCount({cov_id}) == {count});\n"));
                out.push_str(&format!("        require(OpCovInputIdx({cov_id}, 0) == this.activeInputIndex);\n"));
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

    out.push_str("        // :: auth outputs\n");
    match &entry.emits {
        EmitSpec::None => {
            out.push_str("        require(OpAuthOutputCount(this.activeInputIndex) == 0);\n");
        }
        EmitSpec::One { actors } => {
            out.push_str("        require(OpAuthOutputCount(this.activeInputIndex) == 1);\n");
            let output_idx = hidden_next_output_idx_name();
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {output_idx} = OpAuthOutputIdx(this.activeInputIndex, 0)"),
                &format!("emits one {}", actors.join(" | ")),
            );
        }
        EmitSpec::Outputs(outputs) => {
            out.push_str(&format!("        require(OpAuthOutputCount(this.activeInputIndex) == {});\n", outputs.len()));
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
    out.push_str(&lower_entry_body(actor, entry, model)?);
    out.push_str("    }\n");
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
            let spec = observed_output_spec(observe, output);
            let prefix = hidden_observed_actor_prefix_name(&spec);
            let suffix = hidden_observed_actor_suffix_name(&spec);
            push_generated_call(out, 8, &format!("byte[32] {} = ", output.actor), "blake2b", &[format!("{prefix} + {suffix}")]);
        }
        for (idx, input) in observe.inputs.iter().enumerate() {
            let lens_spec = observed_input_lens_source_for_input(observe, input);
            let template_spec = observed_template_spec_for_input(observe, input);
            let input_idx = hidden_observed_input_idx_name(&observe.name, &input.name);
            let state_name = hidden_observed_input_state_name(&observe.name, &input.name);
            let state_struct = contract_state_type_for_observed_actor(actor, entry, observe, input, model)?;
            push_generated_statement_with_comment(
                out,
                8,
                &format!("int {input_idx} = OpCovInputIdx({cov_id}, {idx})"),
                &format!("observed input {}.{}: {}", observe.name, input.name, input.actor),
            );
            if lens_spec.side == ObservedActorSideArtifact::Output {
                out.push_str(&format!(
                    "        int {} = {}.length;\n",
                    hidden_observed_actor_prefix_len_name(&observed_input_spec(observe, input)),
                    hidden_observed_actor_prefix_name(&lens_spec)
                ));
                out.push_str(&format!(
                    "        int {} = {}.length;\n",
                    hidden_observed_actor_suffix_len_name(&observed_input_spec(observe, input)),
                    hidden_observed_actor_suffix_name(&lens_spec)
                ));
            }
            push_generated_call(
                out,
                8,
                &format!("{state_struct} {state_name} = "),
                "readInputStateWithTemplate",
                &[
                    input_idx,
                    hidden_observed_actor_prefix_len_name(&observed_input_spec(observe, input)),
                    hidden_observed_actor_suffix_len_name(&observed_input_spec(observe, input)),
                    observed_actor_template_expr_for_entry(actor, entry, model, observe, input, &template_spec)?,
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
}

impl<'a, 'm> BodyLowerer<'a, 'm> {
    fn new(actor: &'a ActorDecl, entry: &'a EntryDecl, model: &'m Model<'a>) -> Result<Self> {
        let tokens = lex(&entry.body)
            .map_err(|err| ArgentError::new(format!("failed to lex body for `{}::{}`: {}", actor.name, entry.name, err.message)))?;

        let mut types = BTreeMap::new();
        let mut source_types = BTreeMap::new();
        for field in &model.state(&actor.state)?.fields {
            types.insert(field.name.clone(), lower_type_ref(&field.ty, model));
            source_types.insert(field.name.clone(), source_type_ref(&field.ty));
        }
        for param in &entry.params {
            types.insert(param.name.clone(), lower_entry_param_type(actor, &param.ty, model));
            source_types.insert(param.name.clone(), source_type_ref(&param.ty));
        }
        for observe in &entry.observes {
            for (binding, state) in observed_open_bindings(observe) {
                types.insert(binding.to_string(), "byte[32]".to_string());
                source_types.insert(binding.to_string(), format!("actor<{state}>"));
            }
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
        })
    }

    fn lower(mut self) -> Result<String> {
        let mut out = String::new();
        self.lower_statements(&mut out, 8, None)?;
        if out.trim().is_empty() {
            out.push_str("        require(1 == 1);\n");
        }
        Ok(out)
    }

    fn lower_statements(&mut self, out: &mut String, indent: usize, end: Option<char>) -> Result<()> {
        while !self.is_eof() && !end.is_some_and(|symbol| self.check_symbol(symbol)) {
            if self.consume_ident("if") {
                self.lower_if(out, indent)?;
            } else if self.consume_ident("become") {
                self.lower_become(out, indent)?;
            } else if self.check_observed_outputs_become_start() {
                self.lower_observed_outputs_become(out, indent)?;
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
        self.lower_statements(out, indent + 4, Some('}'))?;
        self.expect_symbol('}')?;
        push_indent(out, indent);
        out.push('}');

        if self.consume_ident("else") {
            if self.consume_ident("if") {
                out.push_str(" else ");
                self.lower_if_inner(out, indent, false)?;
                return Ok(());
            }
            self.expect_symbol('{')?;
            out.push_str(" else {\n");
            self.lower_statements(out, indent + 4, Some('}'))?;
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
            if let Some(state) = parse_actor_handle_type(source_ty) {
                self.lower_actor_handle_statement(out, indent, state, name, expr)?;
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
            for covenant_id in authorized_covenant_ids(require_expr, &self.source_types)? {
                push_indent(out, indent);
                out.push_str(&format!("// :: authorized by {} (via co-spend)\n", covenant_id.trim()));
            }
        }

        push_indent(out, indent);
        out.push_str(&self.lower_expr(&statement, None, indent)?);
        out.push_str(";\n");
        Ok(())
    }

    fn lower_actor_handle_statement(&mut self, out: &mut String, indent: usize, state: &str, name: &str, expr: &str) -> Result<()> {
        let selector = self
            .selectors
            .get(name)
            .ok_or_else(|| ArgentError::new(format!("actor handle `{name}` must be initialized as `ActorEnum[selector]`")))?
            .clone();
        if selector.state != state {
            return Err(ArgentError::new(format!(
                "actor handle `{name}` is declared as actor<{state}>, but `{}` contains actor<{}>",
                selector.actor_enum, selector.state
            )));
        }
        self.validate_actor_handle_initializer(name, expr, &selector)?;
        self.ensure_selector_template(out, indent, name)?;
        Ok(())
    }

    fn validate_actor_handle_initializer(&self, name: &str, expr: &str, selector: &TemplateSelector) -> Result<()> {
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

    fn lower_observed_outputs_become(&mut self, out: &mut String, indent: usize) -> Result<()> {
        self.expect_ident("require")?;
        let observe_name = self.expect_any_ident()?;
        self.expect_symbol('.')?;
        self.expect_ident("outputs")?;
        self.expect_ident("become")?;
        let routes = self.parse_become_routes()?;

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

        let spec = observed_output_spec(observe, observed_output);
        let output_idx = hidden_observed_output_idx_name(observe_name, &observed_output.name);

        push_indent(out, indent);
        out.push_str(&format!("// :: observed become {}.{} -> {}\n", observe_name, observed_output.name, observed_output.actor));
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
        if observed_is_source_actor_handle(self.actor, self.entry, observed, self.model)? {
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
                let prefix = hidden_witness_prefix_name(&route.actor);
                let suffix = hidden_witness_suffix_name(&route.actor);
                let template = hidden_template_name(&route.actor);
                push_generated_call(
                    out,
                    indent,
                    "",
                    "validateOutputStateWithTemplate",
                    &[output_idx, state_arg, prefix, suffix, template],
                );
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
        if let Some((state_name, body)) = split_state_constructor(expr) {
            return self.lower_state_constructor(state_name, body, indent);
        }
        self.lower_refs(expr)
    }

    fn lower_self_state_expr(&self, ty: &str, indent: usize) -> Result<String> {
        let state_name = if ty == "State" { &self.actor.state } else { ty };
        let state = self.model.state(state_name)?;
        let fields = state.fields.iter().map(|field| (field.name.clone(), field.name.clone())).collect::<Vec<_>>();
        self.render_state_object_for_state(state_name, &fields, indent)
    }

    fn lower_state_constructor(&self, state_name: &str, body: &str, indent: usize) -> Result<String> {
        self.model.state(state_name)?;
        self.lower_state_object_for_state(state_name, body, indent)
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
        let fields = parse_state_fields(body)
            .into_iter()
            .map(|(name, expr)| self.lower_expr(&expr, None, indent + 4).map(|lowered| (name, lowered)))
            .collect::<Result<Vec<_>>>()?;
        self.render_state_object_for_state(state_name, &fields, indent)
    }

    fn lower_local_type(&self, source_ty: &str) -> String {
        if self.model.actor_enums.contains_key(source_ty) {
            return "int".to_string();
        }
        if source_ty == "covid" {
            return "byte[32]".to_string();
        }
        if source_ty == self.actor.state { "State".to_string() } else { source_ty.to_string() }
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
        let field_indent = " ".repeat(indent + 4);
        let close_indent = " ".repeat(indent);
        let mut out = String::new();
        out.push_str("{\n");
        for (field, expr) in hidden_template_object_fields_for_state(&self.actor.state, state_name, self.model) {
            out.push_str(&format!("{field_indent}{field}: {expr},\n"));
        }
        if !self.model.route_leaves_for_state(state_name).is_empty() {
            out.push_str(&format!("{field_indent}// :: {RESERVED_GENERATED_PREFIX} ^ | src:\n"));
        }
        for (name, expr) in fields {
            out.push_str(&format!("{field_indent}{name}: {expr},\n"));
        }
        out.push_str(&close_indent);
        out.push('}');
        Ok(out)
    }

    fn lower_refs(&self, expr: &str) -> Result<String> {
        let mut out = expr.replace("self.value", "tx.inputs[this.activeInputIndex].value");
        out = out.replace("self.covenant_id", "OpInputCovenantId(this.activeInputIndex)");
        for field in &self.model.state(&self.actor.state)?.fields {
            out = out.replace(&format!("self.{}", field.name), &field.name);
        }
        out = lower_authorized_calls(&out, &self.source_types)?;
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

    fn check_observed_outputs_become_start(&self) -> bool {
        matches!(&self.current().kind, TokenKind::Ident(actual) if actual == "require")
            && matches!(self.peek_kind(1), Some(TokenKind::Ident(_)))
            && matches!(self.peek_kind(2), Some(TokenKind::Symbol('.')))
            && matches!(self.peek_kind(3), Some(TokenKind::Ident(actual)) if actual == "outputs")
            && matches!(self.peek_kind(4), Some(TokenKind::Ident(actual)) if actual == "become")
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

fn parse_actor_handle_type(ty: &str) -> Option<&str> {
    let ty = ty.trim();
    ty.strip_prefix("actor<")?.strip_suffix('>').map(str::trim).filter(|state| is_identifier(state))
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryWitnessSpecs {
    templates: Vec<TemplateWitnessSpec>,
    families: Vec<RouteFamilyWitnessSpec>,
    selectors: Vec<TemplateSelectorWitnessSpec>,
    observed_actors: Vec<ObservedActorWitnessSpec>,
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

fn lower_entry_params(actor: &ActorDecl, params: &[ParamDecl], witness_specs: &EntryWitnessSpecs, model: &Model<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for param in params {
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
            }
            ObservedActorSideArtifact::Output => {
                out.push(format!("byte[] {}", hidden_observed_actor_prefix_name(spec)));
                out.push(format!("byte[] {}", hidden_observed_actor_suffix_name(spec)));
            }
        }
    }
    out
}

fn entry_witness_specs(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> EntryWitnessSpecs {
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
    let byte_actors = entry
        .routes
        .iter()
        .filter(|route| !selectors.contains_key(&route.actor))
        .filter(|route| route_validation_kind(actor, route) == RouteValidationKind::ForeignTemplate)
        .map(|route| route.actor.clone())
        .collect::<BTreeSet<_>>();
    let mut specs = template_witness_specs_for_actor(actor, model, read_actors, byte_actors);
    specs.selectors = selector_specs;
    specs.observed_actors = observed_actor_witness_specs(actor, entry, model);
    specs
}

fn observed_actor_witness_specs(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Vec<ObservedActorWitnessSpec> {
    entry.observes.iter().flat_map(|observe| observed_actor_witness_specs_for_observe(actor, entry, observe, model)).collect()
}

fn template_witness_specs_for_actor(
    actor: &ActorDecl,
    model: &Model<'_>,
    read_actors: BTreeSet<String>,
    byte_actors: BTreeSet<String>,
) -> EntryWitnessSpecs {
    let mut specs = template_witness_specs(model, read_actors, byte_actors);
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
    }
}

fn template_witness_specs(
    model: &Model<'_>,
    read_actors: BTreeSet<String>,
    byte_actors: BTreeSet<String>,
) -> Vec<TemplateWitnessSpec> {
    let mut required = read_actors.union(&byte_actors).cloned().collect::<BTreeSet<_>>();
    let mut ordered = Vec::new();
    for actor in &model.template_actors {
        if required.remove(actor) {
            ordered.push(TemplateWitnessSpec {
                actor: actor.clone(),
                form: witness_form(actor, &byte_actors),
                source: TemplateWitnessSource::Field,
            });
        }
    }
    ordered.extend(required.into_iter().map(|actor| {
        let form = witness_form(&actor, &byte_actors);
        TemplateWitnessSpec { actor, form, source: TemplateWitnessSource::Field }
    }));
    ordered
}

fn witness_form(actor: &str, byte_actors: &BTreeSet<String>) -> TemplateWitnessForm {
    if byte_actors.contains(actor) { TemplateWitnessForm::Bytes } else { TemplateWitnessForm::Len }
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
) -> Vec<ObservedActorWitnessSpec> {
    observed_actor_specs_for_observe(actor, entry, observe, model).expect("observed actor specs are valid after model validation")
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
        let spec = observed_actor_spec(observe, ObservedActorSideArtifact::Output, &output.name, &output.actor);
        if seen.insert((spec.side, observed_witness_key(actor, entry, observe, output, model)?)) {
            specs.push(spec);
        }
    }
    for input in &observe.inputs {
        if observe_has_output_actor(observe, &input.actor) {
            continue;
        }
        let spec = observed_actor_spec(observe, ObservedActorSideArtifact::Input, &input.name, &input.actor);
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
    if observed_is_source_actor_handle(actor, entry, observed, model)? {
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
    source_actor_handle_state_for_expr(&observed.actor, actor, entry, model)
}

fn observed_is_dynamic_binding(observe: &ObserveDecl, observed: &ObservedActorDecl) -> bool {
    observed_dynamic_binding_state(observe, observed).is_some()
}

fn observed_is_source_actor_handle(
    actor: &ActorDecl,
    entry: &EntryDecl,
    observed: &ObservedActorDecl,
    model: &Model<'_>,
) -> Result<bool> {
    Ok(source_actor_handle_state_for_expr(&observed.actor, actor, entry, model)?.is_some())
}

fn source_actor_handle_state_for_expr(expr: &str, actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<Option<String>> {
    let expr = expr.trim();
    let current_state = model.state(&actor.state)?;
    let source_ty = if let Some(field_name) = expr.strip_prefix("self.") {
        current_state.fields.iter().find(|field| field.name == field_name).map(|field| &field.ty)
    } else if is_identifier(expr) {
        entry
            .params
            .iter()
            .find(|param| param.name == expr)
            .map(|param| &param.ty)
            .or_else(|| current_state.fields.iter().find(|field| field.name == expr).map(|field| &field.ty))
    } else {
        None
    };
    let Some(state) = source_ty.and_then(|ty| ty.actor_state.as_ref()) else {
        return Ok(None);
    };
    model.state(state)?;
    Ok(Some(state.clone()))
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
    if observed_is_source_actor_handle(actor, entry, observed, model)? {
        return lower_entry_expr(actor, entry, model, &observed.actor, Some("byte[32]"));
    }
    Ok(hidden_observed_actor_template_name(spec))
}

fn observed_template_spec_for_input(observe: &ObserveDecl, input: &ObservedActorDecl) -> ObservedActorWitnessSpec {
    if let Some(output) = first_observed_output_for_actor(observe, &input.actor) {
        return observed_actor_spec(observe, ObservedActorSideArtifact::Output, &output.name, &output.actor);
    }
    observed_actor_spec(observe, ObservedActorSideArtifact::Input, &input.name, &input.actor)
}

fn observed_input_lens_source_for_input(observe: &ObserveDecl, input: &ObservedActorDecl) -> ObservedActorWitnessSpec {
    if let Some(output) = first_observed_output_for_actor(observe, &input.actor) {
        return observed_actor_spec(observe, ObservedActorSideArtifact::Output, &output.name, &output.actor);
    }
    observed_actor_spec(observe, ObservedActorSideArtifact::Input, &input.name, &input.actor)
}

fn observed_input_spec(observe: &ObserveDecl, input: &ObservedActorDecl) -> ObservedActorWitnessSpec {
    ObservedActorWitnessSpec {
        observe: observe.name.clone(),
        side: ObservedActorSideArtifact::Input,
        handle: input.name.clone(),
        actor: input.actor.clone(),
    }
}

fn observed_output_spec(observe: &ObserveDecl, output: &ObservedActorDecl) -> ObservedActorWitnessSpec {
    ObservedActorWitnessSpec {
        observe: observe.name.clone(),
        side: ObservedActorSideArtifact::Output,
        handle: output.name.clone(),
        actor: output.actor.clone(),
    }
}

fn observed_actor_spec(observe: &ObserveDecl, side: ObservedActorSideArtifact, handle: &str, actor: &str) -> ObservedActorWitnessSpec {
    ObservedActorWitnessSpec { observe: observe.name.clone(), side, handle: handle.to_string(), actor: actor.to_string() }
}

fn observe_has_output_actor(observe: &ObserveDecl, actor: &str) -> bool {
    observe.outputs.iter().any(|output| output.actor == actor)
}

fn first_observed_output_for_actor<'a>(observe: &'a ObserveDecl, actor: &str) -> Option<&'a ObservedActorDecl> {
    observe.outputs.iter().find(|output| output.actor == actor)
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
                    EntryKind::Leader => "leader",
                    EntryKind::Delegate => "delegate",
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
            fields: state
                .fields
                .iter()
                .map(|field| FieldArtifact { name: field.name.clone(), ty: type_artifact(&field.ty, model) })
                .collect(),
        })
        .collect();

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
    let template_plan = template_plan_artifact(model, &templates, &argent_actors, &sil_contracts)?;
    let interfaces = interface_set_artifact(model)?;

    let mut artifact = Artifact {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        id: String::new(),
        generator: GeneratorArtifact { name: "argentc".to_string(), version: env!("CARGO_PKG_VERSION").to_string() },
        app: model.app_name.clone(),
        root: manifest_path(&program.root),
        modules: program.modules.iter().map(|module| manifest_path(&module.path)).collect(),
        argent: ArgentArtifact { templates, template_plan, interfaces, states: states.clone(), actor_enums, actors: argent_actors },
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
    let state = model.state(&actor.state)?;
    let runtime_fields = runtime_state_fields(state, model);
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
                hash_hex: contract.compiled.template.hash_hex.clone(),
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
                            HiddenParamSubjectArtifact::RouteFamily { .. } => None,
                            HiddenParamSubjectArtifact::TemplateSelector { .. } => None,
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

    Ok(TemplatePlanArtifact { templates, runtime_states, route_tables, route_proofs, route_families, witness_recipes })
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

    Ok(ActorArtifact {
        name: actor.name.clone(),
        state: actor.state.clone(),
        abi: ActorAbiRefArtifact { actor: actor.name.clone() },
        entries,
    })
}

fn sil_contract_artifact(actor: &ActorDecl, model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<SilContractArtifact> {
    let state = model.state(&actor.state)?;
    let entries = actor.entries.iter().enumerate().map(|(idx, entry)| sil_entry_artifact(actor, idx, entry, model)).collect();
    let sil = actor_sil
        .get(&actor.name)
        .ok_or_else(|| ArgentError::new(format!("missing generated Silverscript for actor `{}`", actor.name)))?;

    Ok(SilContractArtifact {
        name: actor.name.clone(),
        source_path: format!("sil/{}.sil", actor.name),
        runtime_state: RuntimeStateArtifact { source: state.name.clone(), fields: runtime_state_fields(state, model) },
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
    let state = model.state(&actor.state)?;
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
    if ty.is_actor_handle() {
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
        ("covid", None) => Ok(zero_byte_array_expr(32)),
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
    let template_hash = blake2b_simd::Params::new().hash_length(32).to_state().update(prefix).update(suffix).finalize();

    Ok(CompiledContractArtifact {
        script_hex: encode_hex(&compiled.script),
        template: CompiledTemplateArtifact {
            prefix_hex: encode_hex(prefix),
            suffix_hex: encode_hex(suffix),
            hash_hex: encode_hex(template_hash.as_bytes()),
        },
        state_span: StateSpanArtifact { offset: layout.start, len: layout.len },
    })
}

fn runtime_state_field_defs(state: &StateDecl, model: &Model<'_>) -> Vec<(String, TypeArtifact, Option<RuntimeFieldRoleArtifact>)> {
    let mut fields = Vec::new();
    match route_field_kind(&state.name, model) {
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
    for spec in observed_template_specs_for_state(&state.name, model) {
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
    fields
}

fn runtime_state_fields(state: &StateDecl, model: &Model<'_>) -> Vec<RuntimeFieldArtifact> {
    runtime_state_field_defs(state, model).into_iter().map(|(name, ty, _role)| RuntimeFieldArtifact { name, ty }).collect()
}

fn runtime_state_plan_artifact(actor: &ActorDecl, model: &Model<'_>) -> Result<Option<RuntimeStatePlanArtifact>> {
    let state = model.state(&actor.state)?;
    let field_roles = runtime_state_field_defs(state, model)
        .into_iter()
        .filter_map(|(name, _ty, role)| role.map(|role| RuntimeFieldRolePlanArtifact { name, role }))
        .collect::<Vec<_>>();
    if field_roles.is_empty() {
        return Ok(None);
    }
    Ok(Some(RuntimeStatePlanArtifact { contract: actor.name.clone(), source: state.name.clone(), field_roles }))
}

fn hidden_params_for_entry(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Vec<HiddenParamArtifact> {
    let witness_specs = entry_witness_specs(actor, entry, model);
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
        witnesses,
        consumes: entry
            .consumes
            .iter()
            .map(|consume| ConsumeArtifact { name: consume.name.clone(), actor: consume.actor.clone() })
            .collect(),
        emits: emit_spec_artifact(&entry.emits, model),
        routes: expanded_routes.iter().map(route_artifact).collect(),
        terminal_paths: entry
            .terminal_route_sets
            .iter()
            .map(|routes| TerminalPathArtifact { routes: expand_route_set(routes, &selectors).iter().map(route_artifact).collect() })
            .collect(),
    })
}

fn observe_artifact(actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>, observe: &ObserveDecl) -> Result<ObserveArtifact> {
    Ok(ObserveArtifact {
        name: observe.name.clone(),
        covenant_expr: compact_expr(&observe.covenant_expr),
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
    let selectors = model.template_selectors_for_entry(actor, entry)?;
    let terminal_paths = entry
        .terminal_route_sets
        .iter()
        .map(|routes| planned_terminal_path_artifact(actor, routes, entry, model, &selectors))
        .collect::<Result<Vec<_>>>()?;

    Ok(EntryRoutePlanArtifact {
        active_input: Some(active_input),
        leader_input,
        consumes,
        outputs,
        terminal_paths,
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

fn planned_terminal_path_artifact(
    actor: &ActorDecl,
    routes: &[RouteCall],
    entry: &EntryDecl,
    model: &Model<'_>,
    selectors: &BTreeMap<String, TemplateSelector>,
) -> Result<PlannedTerminalPathArtifact> {
    let read_actors = entry.consumes.iter().map(|consume| consume.actor.clone()).collect::<BTreeSet<_>>();
    let byte_actors = routes
        .iter()
        .filter(|route| !selectors.contains_key(&route.actor))
        .filter(|route| route_validation_kind(actor, route) == RouteValidationKind::ForeignTemplate)
        .map(|route| route.actor.clone())
        .collect::<BTreeSet<_>>();
    let selector_names =
        routes.iter().filter_map(|route| selectors.get(&route.actor).map(|selector| selector.name.clone())).collect::<BTreeSet<_>>();

    let mut witness_recipe_ids =
        witness_recipe_ids_for_specs(template_witness_specs_for_actor(actor, model, read_actors, byte_actors));
    for selector_name in &selector_names {
        witness_recipe_ids.extend(template_selector_witness_recipe_ids(selector_name));
    }

    let mut planned_routes = Vec::new();
    for route in routes {
        if let Some(selector) = selectors.get(&route.actor) {
            let selector_recipe_ids = template_selector_witness_recipe_ids(&selector.name);
            for variant in selector.route_actors() {
                let concrete_route = RouteCall { output: route.output.clone(), actor: variant.clone(), state: route.state.clone() };
                let output = route_output_handle(&entry.emits, &concrete_route, model)?;
                planned_routes.push(PlannedRouteArtifact {
                    output: output.name.clone(),
                    auth_index: output.auth_index,
                    actor: variant.clone(),
                    template_id: template_receipt_id(&variant),
                    state_expr: compact_expr(&route.state),
                    witness_recipe_ids: selector_recipe_ids.clone(),
                });
            }
            continue;
        }

        let output = route_output_handle(&entry.emits, route, model)?;
        planned_routes.push(PlannedRouteArtifact {
            output: output.name.clone(),
            auth_index: output.auth_index,
            actor: route.actor.clone(),
            template_id: template_receipt_id(&route.actor),
            state_expr: compact_expr(&route.state),
            witness_recipe_ids: if route_validation_kind(actor, route) == RouteValidationKind::ForeignTemplate {
                witness_recipe_ids_for_specs(template_witness_specs_for_actor(
                    actor,
                    model,
                    BTreeSet::new(),
                    [route.actor.clone()].into_iter().collect(),
                ))
            } else {
                Vec::new()
            },
        });
    }

    Ok(PlannedTerminalPathArtifact { routes: planned_routes, witness_recipe_ids })
}

fn template_selector_witness_recipe_ids(selector_name: &str) -> Vec<String> {
    vec![
        template_selector_witness_recipe_id(selector_name, HiddenParamPurposeArtifact::TemplatePrefixBytes),
        template_selector_witness_recipe_id(selector_name, HiddenParamPurposeArtifact::TemplateSuffixBytes),
    ]
}

fn witness_recipe_ids_for_specs(specs: EntryWitnessSpecs) -> Vec<String> {
    let mut ids = Vec::new();
    for spec in specs.templates {
        push_actor_witness_recipe_ids(&mut ids, &spec);
    }
    for spec in specs.families {
        ids.push(route_family_witness_recipe_id(&spec.family_id, HiddenParamPurposeArtifact::RouteFamilyTable));
    }
    for spec in specs.selectors {
        ids.extend(template_selector_witness_recipe_ids(&spec.name));
    }
    for spec in specs.observed_actors {
        match spec.side {
            ObservedActorSideArtifact::Input => {
                ids.push(observed_actor_witness_recipe_id(&spec, HiddenParamPurposeArtifact::TemplatePrefixLen));
                ids.push(observed_actor_witness_recipe_id(&spec, HiddenParamPurposeArtifact::TemplateSuffixLen));
            }
            ObservedActorSideArtifact::Output => {
                ids.push(observed_actor_witness_recipe_id(&spec, HiddenParamPurposeArtifact::TemplatePrefixBytes));
                ids.push(observed_actor_witness_recipe_id(&spec, HiddenParamPurposeArtifact::TemplateSuffixBytes));
            }
        }
    }
    ids
}

fn push_actor_witness_recipe_ids(out: &mut Vec<String>, spec: &TemplateWitnessSpec) {
    match spec.form {
        TemplateWitnessForm::Bytes => {
            out.push(template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplatePrefixBytes));
            out.push(template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplateSuffixBytes));
        }
        TemplateWitnessForm::Len => {
            out.push(template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplatePrefixLen));
            out.push(template_witness_recipe_id(&spec.actor, HiddenParamPurposeArtifact::TemplateSuffixLen));
        }
    }
}

fn route_output_handle(emits: &EmitSpec, route: &RouteCall, model: &Model<'_>) -> Result<RouteOutputHandleArtifact> {
    match (emits, &route.output) {
        (EmitSpec::One { actors }, None) => {
            Ok(RouteOutputHandleArtifact { name: None, auth_index: 0, actors: model.expand_actor_refs(actors) })
        }
        (EmitSpec::Outputs(outputs), Some(name)) => outputs
            .iter()
            .find(|output| &output.name == name)
            .map(|output| RouteOutputHandleArtifact {
                name: Some(output.name.clone()),
                auth_index: output.auth_index,
                actors: model.expand_actor_refs(&output.actors),
            })
            .ok_or_else(|| ArgentError::new(format!("route references unknown output `{name}`"))),
        (EmitSpec::Outputs(_), None) => Err(ArgentError::new("named output route is missing an output handle")),
        (EmitSpec::One { .. }, Some(name)) => Err(ArgentError::new(format!("single-output route unexpectedly named `{name}`"))),
        (EmitSpec::None, _) => Err(ArgentError::new("route cannot target an entry that emits none")),
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
    } else if ty.name == "covid" && ty.array.is_none() {
        "byte[32]".to_string()
    } else {
        ty.to_sil()
    }
}

fn lower_entry_param_type(actor: &ActorDecl, ty: &TypeRef, model: &Model<'_>) -> String {
    if ty.name == actor.state && ty.array.is_none() { "State".to_string() } else { lower_type_ref(ty, model) }
}

fn source_type_ref(ty: &TypeRef) -> String {
    if let Some(state) = &ty.actor_state { format!("actor<{state}>") } else { ty.to_sil() }
}

fn type_artifact(ty: &TypeRef, model: &Model<'_>) -> TypeArtifact {
    if ty.is_actor_handle() {
        TypeArtifact::FixedBytes { len: 32 }
    } else if model.is_actor_enum_type(ty) {
        TypeArtifact::Int
    } else {
        TypeArtifact::from_parts(&ty.name, ty.array)
    }
}

fn entry_param_type_artifact(actor: &ActorDecl, ty: &TypeRef, model: &Model<'_>) -> TypeArtifact {
    if ty.name == actor.state && ty.array.is_none() {
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

fn lower_authorized_calls(expr: &str, source_types: &BTreeMap<String, String>) -> Result<String> {
    if !expr.contains(".authorized") {
        return Ok(expr.to_string());
    }
    let tokens =
        lex(expr).map_err(|err| ArgentError::new(format!("failed to lex authorization expression `{expr}`: {}", err.message)))?;
    let mut out = String::new();
    let mut cursor = 0usize;
    let mut pos = 0usize;
    while pos < tokens.len() {
        if let Some((replacement_start, replacement_end, next_pos, covenant_id)) =
            parse_authorized_call(expr, &tokens, pos, source_types)?
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
    if out.contains(".authorized") {
        return Err(ArgentError::new("`.authorized()` is only available on `covid` values or explicit `covid(expr)` casts"));
    }
    Ok(out)
}

fn authorized_covenant_ids(expr: &str, source_types: &BTreeMap<String, String>) -> Result<Vec<String>> {
    if !expr.contains(".authorized") {
        return Ok(Vec::new());
    }
    let tokens =
        lex(expr).map_err(|err| ArgentError::new(format!("failed to lex authorization expression `{expr}`: {}", err.message)))?;
    let mut ids = Vec::new();
    let mut pos = 0usize;
    while pos < tokens.len() {
        if let Some((_replacement_start, _replacement_end, next_pos, covenant_id)) =
            parse_authorized_call(expr, &tokens, pos, source_types)?
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
    let inner = statement.strip_prefix("require(")?.strip_suffix(')')?;
    Some(inner)
}

fn parse_authorized_call(
    expr: &str,
    tokens: &[Token],
    pos: usize,
    source_types: &BTreeMap<String, String>,
) -> Result<Option<(usize, usize, usize, String)>> {
    if is_ident(tokens, pos, "covid") && is_symbol(tokens, pos + 1, '(') {
        let close = matching_symbol(tokens, pos + 1, '(', ')')
            .ok_or_else(|| ArgentError::new(format!("unterminated covid(...) authorization expression `{expr}`")))?;
        if is_symbol(tokens, close + 1, '.')
            && is_ident(tokens, close + 2, "authorized")
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
        && is_ident(tokens, pos + 2, "authorized")
        && is_symbol(tokens, pos + 3, '(')
        && is_symbol(tokens, pos + 4, ')')
    {
        let ident = expr[tokens[pos].span.start..tokens[pos].span.end].to_string();
        if source_types.get(&ident).is_none_or(|ty| ty != "covid") {
            return Err(ArgentError::new(format!("`.authorized()` is only available on `covid` values, found `{ident}`")));
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
        RouteFieldKind::None => {
            if observed_templates.is_empty() {
                out.push_str("    // No foreign route templates required.\n");
            }
        }
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
            if !observed_templates.is_empty() {
                out.push_str(&format!("{field_indent}// :: {RESERVED_GENERATED_PREFIX} ^ | src:\n"));
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
            out.push_str(&format!("{field_indent}// :: {RESERVED_GENERATED_PREFIX} ^ | src:\n"));
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
            out.push_str(&format!("{field_indent}// :: {RESERVED_GENERATED_PREFIX} ^ | src:\n"));
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

fn hidden_param_purpose_id(purpose: HiddenParamPurposeArtifact) -> &'static str {
    match purpose {
        HiddenParamPurposeArtifact::TemplatePrefixBytes => "template_prefix_bytes",
        HiddenParamPurposeArtifact::TemplateSuffixBytes => "template_suffix_bytes",
        HiddenParamPurposeArtifact::TemplatePrefixLen => "template_prefix_len",
        HiddenParamPurposeArtifact::TemplateSuffixLen => "template_suffix_len",
        HiddenParamPurposeArtifact::RouteTemplateLeaf => "route_template_leaf",
        HiddenParamPurposeArtifact::RouteTemplateProof => "route_template_proof",
        HiddenParamPurposeArtifact::RouteFamilyTable => "route_family_table",
        HiddenParamPurposeArtifact::RouteFamilyProof => "route_family_proof",
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
    if let Some(field) = spec.actor.strip_prefix("self.")
        && is_identifier(field)
    {
        return to_snake(field);
    }
    if is_identifier(&spec.actor) {
        return hidden_actor_suffix(&spec.actor);
    }
    to_snake(&compact_expr(&spec.actor).replace(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_', "_"))
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

fn hidden_observe_cov_id_name(observe: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_cov_id")
}

fn hidden_observed_input_idx_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_input_idx")
}

fn hidden_observed_output_idx_name(observe: &str, handle: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}{observe}_{handle}_output_idx")
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
    let trimmed = body.trim_matches('\n');
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
        program.modules[0].actors[0].entries[0].emits = EmitSpec::None;
        program.modules[0].actors[0].entries[0].routes =
            vec![RouteCall { output: Some("next".to_string()), actor: "Player".to_string(), state: "next_player".to_string() }];

        let err = Model::from_program(&program).expect_err("delegate become must be rejected");
        assert!(err.to_string().contains("cannot use `become`"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_duplicate_state_declarations() {
        let mut program = test_program();
        let mut duplicate = empty_module("second.ag");
        duplicate.states.push(StateDecl { name: "PlayerState".to_string(), fields: Vec::new() });
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
        program.modules[0].states[0].fields.push(FieldDecl { ty: TypeRef::new("int"), name: "gen__player_template".to_string() });

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
        assert!(bump.route_plan.terminal_paths[0].witness_recipe_ids.is_empty());

        let sil_foo = artifact.sil_abi.contract("Foo").expect("Foo Sil ABI exists");
        let sil_bump = sil_foo.entry("bump").expect("bump Sil ABI exists");
        assert_eq!(sil_bump.params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(), ["amount"]);
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
            artifact.argent.template_plan.templates[0].hash_hex,
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
        assert_eq!(entry.terminal_paths[0].routes[0], entry.routes[0]);
        assert_eq!(
            entry.route_plan.active_input.as_ref().map(|input| (input.actor.as_str(), input.cov_index)),
            Some(("Foo", Some(0)))
        );
        assert_eq!(entry.route_plan.outputs[0].auth_index, 0);
        assert_eq!(entry.route_plan.outputs[0].name, None);
        assert_eq!(entry.route_plan.terminal_paths[0].routes[0].actor, "Foo");
        assert_eq!(entry.route_plan.terminal_paths[0].routes[0].template_id, "template/foo");
        assert_eq!(entry.route_plan.terminal_paths[0].routes[0].auth_index, 0);
        assert!(entry.route_plan.terminal_paths[0].witness_recipe_ids.is_empty());

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
    fn builds_examples_with_compiled_artifacts() {
        assert_example_build_artifact(
            "examples/tickets.ag",
            "tickets",
            &[
                ("Issuer", "e91f3e3570438b064be220a2cc0f623450af006ef883810349d2fc07acf8814e"),
                ("Ticket", "be416b25f340479bb31b271c28cdd230764a8595bc1298270736449a1edb4575"),
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
                byte[32] kcc20_covid;
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
                    "gen__asset_minter_proxy_prefix",
                    &HiddenParamSubjectArtifact::ObservedActor {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Output,
                        handle: "proxy".to_string(),
                        actor: "MinterProxy".to_string(),
                    },
                    HiddenParamPurposeArtifact::TemplatePrefixBytes,
                ),
                (
                    "gen__asset_minter_proxy_suffix",
                    &HiddenParamSubjectArtifact::ObservedActor {
                        observe: "asset".to_string(),
                        side: ObservedActorSideArtifact::Output,
                        handle: "proxy".to_string(),
                        actor: "MinterProxy".to_string(),
                    },
                    HiddenParamPurposeArtifact::TemplateSuffixBytes,
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
                "witness/observed/asset/output/minter_proxy/template_prefix_bytes",
                "witness/observed/asset/output/minter_proxy/template_suffix_bytes",
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
                        side: ObservedActorSideArtifact::Output,
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
        assert!(minter_sil.contains("byte[] gen__asset_minter_proxy_prefix,"), "{minter_sil}");
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
        assert!(
            minter_sil.contains("int gen__asset_minter_proxy_prefix_len = gen__asset_minter_proxy_prefix.length;"),
            "{minter_sil}"
        );
        assert!(
            minter_sil.contains("int gen__asset_minter_proxy_suffix_len = gen__asset_minter_proxy_suffix.length;"),
            "{minter_sil}"
        );
        assert!(minter_sil.contains("MinterProxyState gen__asset_proxy_state = readInputStateWithTemplate("), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_proxy_input_idx,"), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_minter_proxy_template"), "{minter_sil}");
        assert!(minter_sil.contains("// :: observed output asset.proxy: MinterProxy"), "{minter_sil}");
        assert!(minter_sil.contains("int gen__asset_proxy_output_idx = OpCovOutputIdx(gen__asset_cov_id, 0);"), "{minter_sil}");
        assert!(minter_sil.contains("// :: observed output asset.recipient: KCC20"), "{minter_sil}");
        assert!(minter_sil.contains("int gen__asset_recipient_output_idx = OpCovOutputIdx(gen__asset_cov_id, 1);"), "{minter_sil}");
        assert!(minter_sil.contains("validateOutputStateWithTemplate(\n            gen__asset_proxy_output_idx,"), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_minter_proxy_prefix,"), "{minter_sil}");
        assert!(minter_sil.contains("validateOutputStateWithTemplate(\n            gen__asset_recipient_output_idx,"), "{minter_sil}");
        assert!(minter_sil.contains("gen__asset_kcc20_template"), "{minter_sil}");
        assert!(minter_sil.contains("MinterProxyState prev_proxy = gen__asset_proxy_state;"), "{minter_sil}");

        let artifact_json = fs::read_to_string(out_dir.join("artifact.json")).expect("artifact json exists");
        let artifact: Artifact = serde_json::from_str(&artifact_json).expect("artifact deserializes");
        artifact.verify_template_plan().expect("observed witness receipts verify");

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn icc_asset_lowers_covid_authorization_and_else_if() {
        let out_dir = std::env::temp_dir().join(format!("argent-icc-asset-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);

        let program = crate::loader::load_program(Path::new("examples/icc/kcc20_asset.ag")).expect("ICC asset app loads");
        emit_build(&program, &out_dir).expect("ICC asset app builds");

        let kcc20_sil = fs::read_to_string(out_dir.join("sil/KCC20.sil")).expect("KCC20.sil exists");
        assert!(kcc20_sil.contains("} else if (identifier_type == IDENTIFIER_COVENANT_ID) {"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("require(checkSig(owner_sig, owner_identifier));"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("// :: authorized by owner_identifier (via co-spend)"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("require(OpCovInputCount(owner_identifier) > 0);"), "{kcc20_sil}");
        assert!(kcc20_sil.contains("State next_state = {"), "{kcc20_sil}");

        let proxy_sil = fs::read_to_string(out_dir.join("sil/MinterProxy.sil")).expect("MinterProxy.sil exists");
        assert!(proxy_sil.contains("byte[32] controller_id = init_controller_id;"), "{proxy_sil}");
        assert!(proxy_sil.contains("entrypoint function mint(\n        State next_proxy,"), "{proxy_sil}");
        assert!(proxy_sil.contains("// :: authorized by controller_id (via co-spend)"), "{proxy_sil}");
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
    fn rejects_authorized_on_non_covid_value() {
        let out_dir = std::env::temp_dir().join(format!("argent-authorized-type-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out_dir);
        let module = crate::parser::parse_module(
            PathBuf::from("test.ag"),
            r#"
            state FooState {
                byte[32] id;
            }

            actor Foo owns FooState {
                entry hold() emits none {
                    require(id.authorized());
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

        let err = emit_build(&program, &out_dir).expect_err("non-covid authorization must be rejected");
        assert!(err.to_string().contains("only available on `covid` values"), "unexpected error: {err}");

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn rejects_duplicate_observe_names() {
        let err = parse_and_validate(
            r#"
            state ForeignState {}
            state LocalState {}

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by target_id {
                    inputs {
                        foreign: Foreign;
                    }
                }
                observes asset by target_id {
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
            state LocalState {}

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by target_id {
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
        let source = r#"
            state ForeignState {
                int count;
            }

            state LocalState {
                byte[32] target_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(1 == 1);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by target_id {
                    inputs {
                        src: Foreign;
                    }

                    outputs {
                        dst: Foreign;
                    }
                }
                emits none {
                    ForeignState prev = asset.inputs.src.state;
                    ForeignState next = {
                        count: prev.count + 1,
                    };

                    require asset.outputs become {
                        dst <- Foreign(next);
                    };
                }
            }

            app Test {
                actor Local;
            }
            "#;

        let path = PathBuf::from("test.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");
        let local = model.actor("Local").expect("Local actor exists");
        let sil = emit_actor(local, &model).expect("Local emits");
        let actor_sil = actor_sil_for_model(&model);
        let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");

        assert!(sil.contains("byte[32] gen__asset_foreign_template = gen__init_asset_foreign_template;"), "{sil}");
        assert!(sil.contains("byte[] gen__asset_foreign_prefix"), "{sil}");
        assert!(sil.contains("byte[] gen__asset_foreign_suffix"), "{sil}");
        assert!(sil.contains("int gen__asset_foreign_prefix_len = gen__asset_foreign_prefix.length;"), "{sil}");
        assert!(sil.contains("int gen__asset_foreign_suffix_len = gen__asset_foreign_suffix.length;"), "{sil}");
        assert!(sil.contains("ForeignState gen__asset_src_state = readInputStateWithTemplate("), "{sil}");
        assert!(sil.contains("gen__asset_src_input_idx,"), "{sil}");
        assert!(sil.contains("gen__asset_foreign_template"), "{sil}");
        assert!(sil.contains("validateOutputStateWithTemplate(\n            gen__asset_dst_output_idx,"), "{sil}");
        assert!(sil.contains("gen__asset_foreign_prefix,"), "{sil}");
        assert!(!sil.contains("gen__asset_src_prefix"), "{sil}");
        assert!(!sil.contains("gen__asset_dst_prefix"), "{sil}");

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
                    side: ObservedActorSideArtifact::Output,
                    handle: "dst".to_string(),
                    contract: "Foreign".to_string(),
                },
            )]
        );

        let local_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Local").expect("Local artifact actor exists");
        let step = local_actor.entries.iter().find(|entry| entry.name == "step").expect("step entry exists");
        assert_eq!(
            step.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            vec!["gen__asset_foreign_prefix", "gen__asset_foreign_suffix"]
        );
        assert_eq!(
            step.route_plan.witness_recipe_ids.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "witness/observed/asset/output/foreign/template_prefix_bytes",
                "witness/observed/asset/output/foreign/template_suffix_bytes",
            ]
        );
    }

    #[test]
    fn open_observed_actor_binding_lowers_to_runtime_template_handle() {
        let source = r#"
            state AgentState {
                byte[32] controller_id;
                byte[32] caps_digest;
                int energy;
            }

            state CellState {
                covid agent_covid;
                actor<AgentState> agent_type;
                int tick;
            }

            actor Cell owns CellState {
                entry advance()
                observes remote by self.agent_covid {
                    inputs {
                        agent: actor<AgentState> as observed_agent;
                    }

                    outputs {
                        agent: observed_agent;
                    }
                }
                emits {
                    cell: Cell;
                } {
                    AgentState prev_state = remote.inputs.agent.state;

                    require(agent_type == observed_agent);
                    require(prev_state.controller_id == self.covenant_id);

                    AgentState next_state = {
                        controller_id: prev_state.controller_id,
                        caps_digest: prev_state.caps_digest,
                        energy: prev_state.energy - 1,
                    };

                    require remote.outputs become {
                        agent <- observed_agent(next_state);
                    };

                    CellState next_cell = {
                        agent_covid: agent_covid,
                        agent_type: agent_type,
                        tick: tick + 1,
                    };

                    become cell <- Cell(next_cell);
                }
            }

            app Test {
                actor Cell;
            }
            "#;

        let path = PathBuf::from("test.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");
        let cell = model.actor("Cell").expect("Cell actor exists");
        let sil = emit_actor(cell, &model).expect("Cell emits");
        let actor_sil = actor_sil_for_model(&model);
        let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");

        assert!(sil.contains("byte[32] init_agent_type"), "{sil}");
        assert!(sil.contains("byte[32] agent_type = init_agent_type;"), "{sil}");
        assert!(sil.contains("byte[32] observed_agent = blake2b("), "{sil}");
        assert!(sil.contains("gen__remote_observed_agent_prefix + gen__remote_observed_agent_suffix"), "{sil}");
        assert!(sil.contains("AgentState gen__remote_agent_state = readInputStateWithTemplate("), "{sil}");
        assert!(sil.contains("gen__remote_agent_input_idx,"), "{sil}");
        assert!(sil.contains("observed_agent\n        );"), "{sil}");
        assert!(sil.contains("require(agent_type == observed_agent);"), "{sil}");
        assert!(sil.contains("validateOutputStateWithTemplate(\n            gen__remote_agent_output_idx,"), "{sil}");
        assert!(sil.contains("observed_agent\n        );"), "{sil}");
        assert!(!sil.contains("gen__remote_observed_agent_template"), "{sil}");
        assert!(!sil.contains("gen__init_remote_observed_agent_template"), "{sil}");

        assert!(runtime_state_plan(&artifact, "Cell").is_none(), "{:#?}", artifact.argent.template_plan.runtime_states);

        let cell_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Cell").expect("Cell artifact actor exists");
        let advance = cell_actor.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
        let observe = advance.observes.first().expect("advance observes remote");
        assert_eq!(observe.inputs[0].open_state.as_deref(), Some("AgentState"));
        assert_eq!(observe.outputs[0].open_state.as_deref(), Some("AgentState"));
        assert_eq!(
            advance.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            vec!["gen__remote_observed_agent_prefix", "gen__remote_observed_agent_suffix"]
        );
    }

    #[test]
    fn open_observed_state_handle_lowers_to_source_actor_handle() {
        let source = r#"
            state AgentState {
                byte[32] controller_id;
                byte[32] caps_digest;
                int energy;
            }

            state CellState {
                covid agent_covid;
                actor<AgentState> agent_type;
                int tick;
            }

            actor Cell owns CellState {
                entry advance()
                observes remote by self.agent_covid {
                    inputs {
                        agent: self.agent_type;
                    }

                    outputs {
                        agent: self.agent_type;
                    }
                }
                emits {
                    cell: Cell;
                } {
                    AgentState prev_state = remote.inputs.agent.state;
                    require(prev_state.controller_id == self.covenant_id);

                    AgentState next_state = {
                        controller_id: prev_state.controller_id,
                        caps_digest: prev_state.caps_digest,
                        energy: prev_state.energy - 1,
                    };

                    require remote.outputs become {
                        agent <- self.agent_type(next_state);
                    };

                    CellState next_cell = {
                        agent_covid: agent_covid,
                        agent_type: agent_type,
                        tick: tick + 1,
                    };

                    become cell <- Cell(next_cell);
                }
            }

            app Test {
                actor Cell;
            }
            "#;

        let path = PathBuf::from("test.ag");
        let module = crate::parser::parse_module(path.clone(), source.to_string()).expect("source parses");
        let program = Program { root: path, modules: vec![module] };
        let model = Model::from_program(&program).expect("model validates");
        let cell = model.actor("Cell").expect("Cell actor exists");
        let sil = emit_actor(cell, &model).expect("Cell emits");
        let actor_sil = actor_sil_for_model(&model);
        let artifact = emit_artifact(&program, &model, &actor_sil).expect("artifact emits");

        assert!(sil.contains("byte[32] init_agent_type"), "{sil}");
        assert!(sil.contains("byte[32] agent_type = init_agent_type;"), "{sil}");
        assert!(!sil.contains("byte[32] observed_agent = blake2b("), "{sil}");
        assert!(sil.contains("AgentState gen__remote_agent_state = readInputStateWithTemplate("), "{sil}");
        assert!(sil.contains("gen__remote_agent_type_prefix.length"), "{sil}");
        assert!(sil.contains("gen__remote_agent_type_suffix.length"), "{sil}");
        assert!(sil.contains("agent_type\n        );"), "{sil}");
        assert!(sil.contains("validateOutputStateWithTemplate(\n            gen__remote_agent_output_idx,"), "{sil}");
        assert!(sil.contains("agent_type\n        );"), "{sil}");
        assert!(!sil.contains("gen__remote_agent_type_template"), "{sil}");
        assert!(!sil.contains("gen__init_remote_agent_type_template"), "{sil}");

        assert!(runtime_state_plan(&artifact, "Cell").is_none(), "{:#?}", artifact.argent.template_plan.runtime_states);

        let cell_actor = artifact.argent.actors.iter().find(|actor| actor.name == "Cell").expect("Cell artifact actor exists");
        let advance = cell_actor.entries.iter().find(|entry| entry.name == "advance").expect("advance entry exists");
        let observe = advance.observes.first().expect("advance observes remote");
        assert_eq!(observe.inputs[0].actor, "self.agent_type");
        assert_eq!(observe.outputs[0].actor, "self.agent_type");
        assert_eq!(observe.inputs[0].open_state.as_deref(), Some("AgentState"));
        assert_eq!(observe.outputs[0].open_state.as_deref(), Some("AgentState"));
        assert_eq!(
            advance.hidden_params.iter().map(|param| param.name.as_str()).collect::<Vec<_>>(),
            vec!["gen__remote_agent_type_prefix", "gen__remote_agent_type_suffix"]
        );
    }

    #[test]
    fn rejects_input_only_open_observed_actor_binding() {
        let err = parse_and_validate(
            r#"
            state AgentState {
                int energy;
            }

            state CellState {
                covid agent_covid;
            }

            actor Cell owns CellState {
                entry inspect()
                observes remote by self.agent_covid {
                    inputs {
                        agent: actor<AgentState> as observed_agent;
                    }
                }
                emits none {
                    AgentState prev_state = remote.inputs.agent.state;
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
                byte[32] target_id;
            }

            actor Foreign owns ForeignState {
                entry hold() emits none {
                    require(amount >= 0);
                }
            }

            actor Local owns LocalState {
                entry step()
                observes asset by target_id {
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
                byte[32] target_id;
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
                observes asset by target_id {
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
        assert!(
            register_player.route_plan.terminal_paths[0].routes[0].witness_recipe_ids.is_empty(),
            "exact league continuation should not need per-route template witnesses"
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
            runtime_state_plan(&artifact, "Player").expect("Player runtime role overlay exists").field_roles[..3]
                .iter()
                .map(|field| (field.name.as_str(), field.role.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("gen__player_template", RuntimeFieldRoleArtifact::Template { contract: "Player".to_string() }),
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

                    actor<BoardState> target = MoveActor::Knight;
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
    fn route_family_without_external_entry_uses_first_actor_as_anchor() {
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

        let family = artifact.argent.template_plan.route_families.first().expect("route family is inferred");
        assert_eq!(family.id, "route_family/BoardState/a");
        assert_eq!(family.anchor_actor, "A");
        assert!(family.entry_actors.is_empty());
        assert_eq!(family.actors, vec!["A", "B"]);
        assert_eq!(family.table_id, "route_table/BoardState/gen__a_routes");

        assert_eq!(
            runtime_state_plan(&artifact, "A").expect("A runtime role overlay exists").field_roles[..2]
                .iter()
                .map(|field| (field.name.as_str(), field.role.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("gen__a_template", RuntimeFieldRoleArtifact::Template { contract: "A".to_string() }),
                ("gen__a_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["B".to_string()] }),
            ]
        );
        artifact.verify_template_plan().expect("zero-entry route family receipt verifies");
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
                entry to_a() emits one A {
                    BoardState next = {
                        n: n + 1,
                    };

                    become A(next);
                }
            }

            actor C owns BoardState {
                entry to_d() emits one D {
                    BoardState next = {
                        n: n + 1,
                    };

                    become D(next);
                }
            }

            actor D owns BoardState {
                entry to_c() emits one C {
                    BoardState next = {
                        n: n + 1,
                    };

                    become C(next);
                }
            }

            app MultiFamilyState {
                actor A;
                actor B;
                actor C;
                actor D;
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
                ("route_family/BoardState/a", "A", vec!["A", "B"], "route_table/BoardState/gen__a_routes"),
                ("route_family/BoardState/c", "C", vec!["C", "D"], "route_table/BoardState/gen__c_routes"),
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
                    vec![RouteTemplateLeafArtifact::Template { actor: "B".to_string(), template_id: "template/b".to_string() }],
                ),
                (
                    "route_table/BoardState/gen__c_routes",
                    vec![RouteTemplateLeafArtifact::Template { actor: "D".to_string(), template_id: "template/d".to_string() }],
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
                ("gen__a_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["B".to_string()] }),
                ("gen__c_template", RuntimeFieldRoleArtifact::Template { contract: "C".to_string() }),
                ("gen__c_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["D".to_string()] }),
            ]
        );
        artifact.verify_template_plan().expect("multi-family route state receipt verifies");
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
                entry to_a() emits one HubA {
                    BoardState next = {
                        n: n + 1,
                    };

                    become HubA(next);
                }
            }

            app MultiEntryFamily {
                actor PlayerA;
                actor PlayerB;
                actor HubB;
                actor HubA;
                actor Leaf;
            }
            "#,
        );

        let family = artifact.argent.template_plan.route_families.first().expect("route family is inferred");
        assert_eq!(family.id, "route_family/BoardState/hub_b");
        assert_eq!(family.anchor_actor, "HubB");
        assert_eq!(family.entry_actors, vec!["HubB", "HubA"]);
        assert_eq!(family.actors, vec!["HubB", "HubA", "Leaf"]);
        assert_eq!(family.table_id, "route_table/BoardState/gen__hub_b_routes");

        assert_eq!(
            runtime_state_plan(&artifact, "HubB").expect("HubB runtime role overlay exists").field_roles[..3]
                .iter()
                .map(|field| (field.name.as_str(), field.role.clone()))
                .collect::<Vec<_>>(),
            vec![
                ("gen__hub_b_template", RuntimeFieldRoleArtifact::Template { contract: "HubB".to_string() }),
                ("gen__hub_a_template", RuntimeFieldRoleArtifact::Template { contract: "HubA".to_string() }),
                ("gen__hub_b_routes", RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["Leaf".to_string()] }),
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

                    actor<BoardState> target = MoveActor::Knight;
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
        let template_hash = blake2b_simd::Params::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize();
        assert_eq!(
            encode_hex(template_hash.as_bytes()),
            compiled.template.hash_hex,
            "actor `{actor}` template hash must be blake2b(prefix || suffix)"
        );
    }

    fn runtime_state_plan<'a>(artifact: &'a Artifact, contract: &str) -> Option<&'a RuntimeStatePlanArtifact> {
        artifact.argent.template_plan.runtime_states.iter().find(|state| state.contract == contract)
    }

    fn subject_label(subject: &HiddenParamSubjectArtifact) -> &str {
        match subject {
            HiddenParamSubjectArtifact::Actor { actor } => actor,
            HiddenParamSubjectArtifact::ObservedActor { actor, .. } => actor,
            HiddenParamSubjectArtifact::RouteFamily { family_id } => family_id,
            HiddenParamSubjectArtifact::TemplateSelector { selector } => selector,
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
                    StateDecl { name: "PlayerState".to_string(), fields: Vec::new() },
                    StateDecl { name: "GameState".to_string(), fields: Vec::new() },
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
