use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::artifact::*;
use crate::ast::*;
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
    consts: Vec<&'a ConstDecl>,
    functions: Vec<&'a FunctionDecl>,
    states: BTreeMap<String, &'a StateDecl>,
    actors_by_name: BTreeMap<String, &'a ActorDecl>,
    actors: Vec<&'a ActorDecl>,
}

impl<'a> Model<'a> {
    fn from_program(program: &'a Program) -> Result<Self> {
        validate_unique_apps(program)?;
        let consts = collect_consts(program)?;
        let functions = collect_functions(program)?;
        let states = collect_states(program)?;
        let all_actors = collect_actors(program)?;

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

        let model = Self { app_name, template_actors, consts, functions, states, actors_by_name: all_actors, actors };
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

    fn validate(&self) -> Result<()> {
        self.validate_reserved_identifiers()?;
        self.validate_generated_actor_suffixes()?;

        let template_actor_set = self.template_actors.iter().cloned().collect::<BTreeSet<_>>();
        for actor in &self.actors {
            for entry in &actor.entries {
                self.validate_entry(actor, entry, &template_actor_set)?;
            }
        }
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
                for target in actors {
                    self.require_template_actor(
                        target,
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
                    for target in &output.actors {
                        self.require_template_actor(
                            target,
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
            self.require_template_actor(
                &route.actor,
                template_actor_set,
                format!("entry `{}::{}` routes to unknown actor `{}`", actor.name, entry.name, route.actor),
            )?;
            self.actor_state(&route.actor)?;
            self.validate_route_allowed(actor, entry, route)?;
        }
        self.validate_route_coverage(actor, entry)?;
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
                if actors.iter().any(|target| target == &route.actor) {
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
                if output.actors.iter().any(|target| target == &route.actor) {
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

fn validate_unique_apps(program: &Program) -> Result<()> {
    let mut seen = BTreeMap::new();
    for module in &program.modules {
        for app in &module.apps {
            reject_duplicate_top_level("app", &app.name, &module.path, &mut seen)?;
        }
    }
    Ok(())
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
    for template_actor in &model.template_actors {
        args.push(format!("    byte[32] {}", hidden_template_init_name(template_actor)));
    }
    for field in &state.fields {
        args.push(format!("    {} init_{}", field.ty.to_sil(), field.name));
    }
    out.push_str(&args.join(",\n"));
    out.push_str("\n) {\n");

    emit_shared_constants(&mut out, model);
    emit_state_layouts(&mut out, actor, model)?;
    emit_shared_functions(&mut out, model);

    emit_section_header(&mut out, "Template capability table");
    for template_actor in &model.template_actors {
        let template = hidden_template_name(template_actor);
        let init_template = hidden_template_init_name(template_actor);
        out.push_str(&format!("    byte[32] {template} = {init_template};\n"));
    }
    out.push('\n');

    emit_section_header(&mut out, &format!("{} state fields", actor.name));
    for field in &state.fields {
        out.push_str(&format!("    {} {} = init_{};\n", field.ty.to_sil(), field.name, field.name));
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
    out.push_str(&format!("    // {title}\n"));
}

fn emit_shared_constants(out: &mut String, model: &Model<'_>) {
    if !model.consts.is_empty() {
        emit_section_header(out, "Shared constants");
        for konst in &model.consts {
            out.push_str(&format!("    {} constant {} = {};\n", konst.ty.to_sil(), konst.name, konst.value));
        }
        out.push('\n');
    }
}

fn emit_state_layouts(out: &mut String, current_actor: &ActorDecl, model: &Model<'_>) -> Result<()> {
    emit_section_header(out, "State layouts");
    let mut emitted = BTreeSet::new();
    for actor in &model.actors {
        if actor.state == current_actor.state {
            continue;
        }
        if !emitted.insert(actor.state.clone()) {
            continue;
        }
        let state = model.state(&actor.state)?;
        out.push_str(&format!("    struct {} {{\n", state.name));
        for template_actor in &model.template_actors {
            out.push_str(&format!("        byte[32] {};\n", hidden_template_name(template_actor)));
        }
        out.push_str("        // ----------- template fields above; source state below\n");
        for field in &state.fields {
            out.push_str(&format!("        {} {};\n", field.ty.to_sil(), field.name));
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
            let params =
                function.params.iter().map(|param| format!("{} {}", param.ty.to_sil(), param.name)).collect::<Vec<_>>().join(", ");
            out.push_str(&format!("    function {}({}) : {} {{\n", function.name, params, function.return_ty.to_sil()));
            out.push_str(&indent_block_body(&function.body, 8));
            out.push_str("    }\n");
        }
        out.push('\n');
    }
}

fn emit_entry(out: &mut String, actor: &ActorDecl, entry: &EntryDecl, model: &Model<'_>) -> Result<()> {
    out.push_str(&format!("    entrypoint function {}(", entry.name));
    let witness_actors = entry_witness_actors(entry, model);
    let sil_params = lower_entry_params(&entry.params, &witness_actors);
    out.push_str(&sil_params.join(", "));
    out.push_str(") {\n");

    for actor_name in &witness_actors {
        let prefix = hidden_witness_prefix_name(actor_name);
        let suffix = hidden_witness_suffix_name(actor_name);
        let prefix_len = hidden_witness_prefix_len_name(actor_name);
        let suffix_len = hidden_witness_suffix_len_name(actor_name);
        out.push_str(&format!("        int {prefix_len} = {prefix}.length;\n"));
        out.push_str(&format!("        int {suffix_len} = {suffix}.length;\n"));
    }
    if !witness_actors.is_empty() {
        out.push('\n');
    }

    if !entry.consumes.is_empty() {
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
            out.push_str(&format!(
                "        int {input_idx} = OpCovInputIdx({cov_id}, {cov_index}); // input {} at cov[{}]\n",
                consume.actor, cov_index
            ));
            out.push_str(&format!(
                "        {state_struct} {} = readInputStateWithTemplate({input_idx}, {prefix_len}, {suffix_len}, {template});\n",
                consume.name
            ));
        }
    }

    match &entry.emits {
        EmitSpec::None => {
            out.push_str("        require(OpAuthOutputCount(this.activeInputIndex) == 0);\n");
        }
        EmitSpec::One { actors } => {
            out.push_str("        require(OpAuthOutputCount(this.activeInputIndex) == 1);\n");
            let output_idx = hidden_next_output_idx_name();
            out.push_str(&format!(
                "        int {output_idx} = OpAuthOutputIdx(this.activeInputIndex, 0); // emits one {}\n",
                actors.join(" | ")
            ));
        }
        EmitSpec::Outputs(outputs) => {
            out.push_str(&format!("        require(OpAuthOutputCount(this.activeInputIndex) == {});\n", outputs.len()));
            for output in outputs {
                let output_idx = hidden_output_idx_name(&output.name);
                out.push_str(&format!(
                    "        int {output_idx} = OpAuthOutputIdx(this.activeInputIndex, {}); // output {}: {}\n",
                    output.auth_index,
                    output.name,
                    output.actors.join(" | ")
                ));
            }
        }
    }

    out.push('\n');
    out.push_str(&lower_entry_body(actor, entry, model)?);
    out.push_str("    }\n");
    Ok(())
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
    input_names: BTreeSet<String>,
    output_names: BTreeSet<String>,
}

impl<'a, 'm> BodyLowerer<'a, 'm> {
    fn new(actor: &'a ActorDecl, entry: &'a EntryDecl, model: &'m Model<'a>) -> Result<Self> {
        let tokens = lex(&entry.body)
            .map_err(|err| ArgentError::new(format!("failed to lex body for `{}::{}`: {}", actor.name, entry.name, err.message)))?;

        let mut types = BTreeMap::new();
        for field in &model.state(&actor.state)?.fields {
            types.insert(field.name.clone(), field.ty.to_sil());
        }
        for param in &entry.params {
            types.insert(param.name.clone(), param.ty.to_sil());
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

        Ok(Self { body: &entry.body, tokens, pos: 0, actor, entry, model, types, input_names, output_names })
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
            } else if self.check_symbol(';') {
                self.advance();
            } else {
                self.lower_plain_statement(out, indent)?;
            }
        }
        Ok(())
    }

    fn lower_if(&mut self, out: &mut String, indent: usize) -> Result<()> {
        self.expect_symbol('(')?;
        let condition = self.take_balanced_expr('(', ')')?;
        self.expect_symbol('{')?;

        push_indent(out, indent);
        out.push_str(&format!("if ({}) {{\n", self.lower_expr(&condition, None, indent)?));
        self.lower_statements(out, indent + 4, Some('}'))?;
        self.expect_symbol('}')?;
        push_indent(out, indent);
        out.push('}');

        if self.consume_ident("else") {
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
            let ty = self.lower_local_type(source_ty);
            let lowered = self.lower_typed_local_initializer(source_ty, &ty, expr, indent)?;
            self.types.insert(name.to_string(), ty.clone());

            push_indent(out, indent);
            out.push_str(&format!("{ty} {name} = {lowered};\n"));
            return Ok(());
        }

        push_indent(out, indent);
        out.push_str(&self.lower_expr(&statement, None, indent)?);
        out.push_str(";\n");
        Ok(())
    }

    fn lower_become(&mut self, out: &mut String, indent: usize) -> Result<()> {
        if self.consume_symbol('{') {
            while !self.check_symbol('}') && !self.is_eof() {
                let route = self.parse_become_route()?;
                self.lower_route(out, indent, route)?;
                self.consume_symbol(';');
            }
            self.expect_symbol('}')?;
            self.consume_symbol(';');
        } else {
            let route = self.parse_become_route()?;
            self.lower_route(out, indent, route)?;
            self.consume_symbol(';');
        }
        Ok(())
    }

    fn parse_become_route(&mut self) -> Result<RouteCall> {
        let first = self.expect_any_ident()?;
        let (output, actor) = if self.consume_left_arrow() { (Some(first), self.expect_any_ident()?) } else { (None, first) };
        self.expect_symbol('(')?;
        let state = self.take_balanced_expr('(', ')')?;
        Ok(RouteCall { output, actor, state })
    }

    fn lower_route(&mut self, out: &mut String, indent: usize, route: RouteCall) -> Result<()> {
        self.model.actor_state(&route.actor)?;
        let output_idx = route.output.as_ref().map_or_else(hidden_next_output_idx_name, |output| hidden_output_idx_name(output));
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

        let prefix = hidden_witness_prefix_name(&route.actor);
        let suffix = hidden_witness_suffix_name(&route.actor);
        let template = hidden_template_name(&route.actor);
        push_indent(out, indent);
        out.push_str(&format!("validateOutputStateWithTemplate({output_idx}, {state_arg}, {prefix}, {suffix}, {template});\n"));
        Ok(())
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
        Ok(self.lower_refs(expr))
    }

    fn lower_self_state_expr(&self, ty: &str, indent: usize) -> Result<String> {
        let state_name = if ty == "State" { &self.actor.state } else { ty };
        let state = self.model.state(state_name)?;
        let fields = state.fields.iter().map(|field| (field.name.clone(), field.name.clone())).collect::<Vec<_>>();
        self.render_state_object(&fields, indent)
    }

    fn lower_state_constructor(&self, state_name: &str, body: &str, indent: usize) -> Result<String> {
        self.model.state(state_name)?;
        self.lower_state_object_for_state(state_name, body, indent)
    }

    fn lower_typed_local_initializer(&self, source_ty: &str, lowered_ty: &str, expr: &str, indent: usize) -> Result<String> {
        if let Some(state_name) = self.source_state_for_local_type(source_ty)
            && let Some(body) = split_state_object_literal(expr)
        {
            return self.lower_state_object_for_state(&state_name, body, indent);
        }
        self.lower_expr(expr, Some(lowered_ty), indent)
    }

    fn lower_state_object_for_state(&self, state_name: &str, body: &str, indent: usize) -> Result<String> {
        self.model.state(state_name)?;
        let fields = parse_state_fields(body)
            .into_iter()
            .map(|(name, expr)| self.lower_expr(&expr, None, indent + 4).map(|lowered| (name, lowered)))
            .collect::<Result<Vec<_>>>()?;
        self.render_state_object(&fields, indent)
    }

    fn lower_local_type(&self, source_ty: &str) -> String {
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

    fn render_state_object(&self, fields: &[(String, String)], indent: usize) -> Result<String> {
        let field_indent = " ".repeat(indent + 4);
        let close_indent = " ".repeat(indent);
        let mut out = String::new();
        out.push_str("{\n");
        for template_actor in &self.model.template_actors {
            let template = hidden_template_name(template_actor);
            out.push_str(&format!("{field_indent}{template}: {template},\n"));
        }
        out.push_str(&format!("{field_indent}// ----------- template fields above; source state below\n"));
        for (name, expr) in fields {
            out.push_str(&format!("{field_indent}{name}: {expr},\n"));
        }
        out.push_str(&close_indent);
        out.push('}');
        Ok(out)
    }

    fn lower_refs(&self, expr: &str) -> String {
        let mut out = expr.replace("self.value", "tx.inputs[this.activeInputIndex].value");
        for name in &self.input_names {
            out = out.replace(&format!("{name}.value"), &format!("tx.inputs[{}].value", hidden_input_idx_name(name)));
        }
        for name in &self.output_names {
            out = out.replace(&format!("{name}.value"), &format!("tx.outputs[{}].value", hidden_output_idx_name(name)));
        }
        out
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

fn push_indent(out: &mut String, indent: usize) {
    out.push_str(&" ".repeat(indent));
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

fn lower_entry_params(params: &[ParamDecl], witness_actors: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for param in params {
        out.push(format!("{} {}", param.ty.to_sil(), param.name));
    }
    for actor_name in witness_actors {
        out.push(format!("byte[] {}", hidden_witness_prefix_name(actor_name)));
        out.push(format!("byte[] {}", hidden_witness_suffix_name(actor_name)));
    }
    out
}

fn entry_witness_actors(entry: &EntryDecl, model: &Model<'_>) -> Vec<String> {
    let mut required = BTreeSet::new();
    for consume in &entry.consumes {
        required.insert(consume.actor.clone());
    }

    match &entry.emits {
        EmitSpec::None => {}
        EmitSpec::One { actors } => {
            required.extend(actors.iter().cloned());
        }
        EmitSpec::Outputs(outputs) => {
            for output in outputs {
                required.extend(output.actors.iter().cloned());
            }
        }
    }

    for route in &entry.routes {
        required.insert(route.actor.clone());
    }

    let mut ordered = Vec::new();
    for actor in &model.template_actors {
        if required.remove(actor) {
            ordered.push(actor.clone());
        }
    }
    ordered.extend(required);
    ordered
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
    let templates = model
        .template_actors
        .iter()
        .map(|actor| TemplateRefArtifact { actor: actor.clone(), symbol: hidden_template_name(actor) })
        .collect();

    let states = model
        .states
        .values()
        .map(|state| StateArtifact {
            name: state.name.clone(),
            fields: state
                .fields
                .iter()
                .map(|field| FieldArtifact { name: field.name.clone(), ty: type_artifact(&field.ty) })
                .collect(),
        })
        .collect();

    let actors = model.actors.iter().map(|actor| actor_artifact(actor, model, actor_sil)).collect::<Result<Vec<_>>>()?;

    Ok(Artifact {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        generator: GeneratorArtifact { name: "argentc".to_string(), version: env!("CARGO_PKG_VERSION").to_string() },
        app: model.app_name.clone(),
        root: manifest_path(&program.root),
        modules: program.modules.iter().map(|module| manifest_path(&module.path)).collect(),
        templates,
        states,
        actors,
    })
}

fn actor_artifact(actor: &ActorDecl, model: &Model<'_>, actor_sil: &BTreeMap<String, String>) -> Result<ActorArtifact> {
    let state = model.state(&actor.state)?;
    let entries = actor.entries.iter().enumerate().map(|(idx, entry)| entry_artifact(actor, idx, entry, model)).collect();
    let sil = actor_sil
        .get(&actor.name)
        .ok_or_else(|| ArgentError::new(format!("missing generated Silverscript for actor `{}`", actor.name)))?;

    Ok(ActorArtifact {
        name: actor.name.clone(),
        state: actor.state.clone(),
        sil: format!("sil/{}.sil", actor.name),
        runtime_state: RuntimeStateArtifact { source: state.name.clone(), fields: runtime_state_fields(state, model) },
        entries,
        compiled: Some(compile_actor_artifact(sil, actor, model)?),
    })
}

fn compile_actor_artifact<'i>(sil: &'i str, actor: &ActorDecl, model: &Model<'_>) -> Result<CompiledActorArtifact> {
    let args: Vec<SilExpr<'i>> = constructor_args_for_actor(actor, model)?;
    let compiled = compile_contract(sil, &args, CompileOptions::default())
        .map_err(|err| ArgentError::new(format!("generated Silverscript for actor `{}` failed to compile: {err}", actor.name)))?;
    compiled_actor_artifact(&compiled)
}

fn constructor_args_for_actor<'i>(actor: &ActorDecl, model: &Model<'_>) -> Result<Vec<SilExpr<'i>>> {
    let state = model.state(&actor.state)?;
    let mut args = Vec::with_capacity(model.template_actors.len() + state.fields.len());

    // These placeholders are valid because Argent-generated constructor
    // arguments are state initializers: hidden template hashes and source state
    // fields. If a constructor argument affects code shape outside the compiled
    // state span, the template hash changes and the contract must be recompiled
    // for that value.
    for _ in &model.template_actors {
        args.push(SilExpr::bytes(vec![0; 32]));
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
    match (&ty.name[..], ty.array) {
        ("byte", Some(len)) => Ok(SilExpr::bytes(vec![0; len])),
        (_, Some(len)) => {
            let item = TypeRef::new(ty.name.clone());
            let values = (0..len).map(|_| placeholder_expr_for_type(&item)).collect::<Result<Vec<_>>>()?;
            Ok(values.into())
        }
        ("int", None) => Ok(SilExpr::int(0)),
        ("bool", None) => Ok(SilExpr::bool(false)),
        ("byte", None) => Ok(SilExpr::byte(0)),
        ("string", None) => Ok(SilExpr::string("")),
        ("pubkey", None) => Ok(SilExpr::bytes(vec![0; 32])),
        ("sig", None) => Ok(SilExpr::bytes(vec![0; 65])),
        ("datasig", None) => Ok(SilExpr::bytes(vec![0; 64])),
        (name, None) => Err(ArgentError::new(format!("unsupported constructor placeholder type `{name}`"))),
    }
}

fn compiled_actor_artifact(compiled: &CompiledContract<'_>) -> Result<CompiledActorArtifact> {
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

    Ok(CompiledActorArtifact {
        script_hex: hex_encode(&compiled.script),
        template: CompiledTemplateArtifact {
            prefix_hex: hex_encode(prefix),
            suffix_hex: hex_encode(suffix),
            hash_hex: hex_encode(template_hash.as_bytes()),
        },
        state_span: StateSpanArtifact { offset: layout.start, len: layout.len },
    })
}

fn runtime_state_fields(state: &StateDecl, model: &Model<'_>) -> Vec<RuntimeFieldArtifact> {
    let mut fields = Vec::new();
    for actor in &model.template_actors {
        fields.push(RuntimeFieldArtifact {
            name: hidden_template_name(actor),
            ty: TypeArtifact::from_parts("byte", Some(32)),
            role: RuntimeFieldRoleArtifact::Template { actor: actor.clone() },
        });
    }
    for field in &state.fields {
        fields.push(RuntimeFieldArtifact {
            name: field.name.clone(),
            ty: type_artifact(&field.ty),
            role: RuntimeFieldRoleArtifact::Source,
        });
    }
    fields
}

fn entry_artifact(actor: &ActorDecl, entry_index: usize, entry: &EntryDecl, model: &Model<'_>) -> EntryArtifact {
    let witness_actors = entry_witness_actors(entry, model);
    let mut hidden_params = Vec::new();
    for actor in &witness_actors {
        hidden_params.push(HiddenParamArtifact {
            name: hidden_witness_prefix_name(actor),
            ty: TypeArtifact::Bytes,
            purpose: HiddenParamPurposeArtifact::TemplatePrefix { actor: actor.clone() },
        });
        hidden_params.push(HiddenParamArtifact {
            name: hidden_witness_suffix_name(actor),
            ty: TypeArtifact::Bytes,
            purpose: HiddenParamPurposeArtifact::TemplateSuffix { actor: actor.clone() },
        });
    }

    EntryArtifact {
        name: entry.name.clone(),
        kind: match entry.kind {
            EntryKind::Leader => EntryKindArtifact::Leader,
            EntryKind::Delegate => EntryKindArtifact::Delegate,
        },
        selector: (actor.entries.len() > 1).then_some(entry_index as i64),
        user_params: entry
            .params
            .iter()
            .map(|param| ParamArtifact { name: param.name.clone(), ty: type_artifact(&param.ty) })
            .collect(),
        hidden_params,
        consumes: entry
            .consumes
            .iter()
            .map(|consume| ConsumeArtifact { name: consume.name.clone(), actor: consume.actor.clone() })
            .collect(),
        emits: emit_spec_artifact(&entry.emits),
        routes: entry.routes.iter().map(route_artifact).collect(),
        terminal_paths: entry
            .terminal_route_sets
            .iter()
            .map(|routes| TerminalPathArtifact { routes: routes.iter().map(route_artifact).collect() })
            .collect(),
    }
}

fn emit_spec_artifact(emits: &EmitSpec) -> EmitArtifact {
    match emits {
        EmitSpec::None => EmitArtifact::None,
        EmitSpec::One { actors } => EmitArtifact::One { actors: actors.clone() },
        EmitSpec::Outputs(outputs) => EmitArtifact::Outputs {
            outputs: outputs
                .iter()
                .map(|output| EmitOutputArtifact {
                    name: output.name.clone(),
                    auth_index: output.auth_index,
                    actors: output.actors.clone(),
                })
                .collect(),
        },
    }
}

fn route_artifact(route: &RouteCall) -> RouteArtifact {
    RouteArtifact { output: route.output.clone(), actor: route.actor.clone(), state_expr: compact_expr(&route.state) }
}

fn type_artifact(ty: &TypeRef) -> TypeArtifact {
    TypeArtifact::from_parts(&ty.name, ty.array)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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
    for ch in input.chars() {
        if ch.is_ascii_uppercase() {
            if !out.is_empty() && !out.ends_with('_') {
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
    Ok(())
}

fn hidden_actor_suffix(actor: &str) -> String {
    to_snake(actor)
}

fn hidden_template_init_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}init_template_{}", hidden_actor_suffix(actor))
}

fn hidden_template_name(actor: &str) -> String {
    format!("{RESERVED_GENERATED_PREFIX}template_{}", hidden_actor_suffix(actor))
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
    if actor == current_actor.name {
        model.actor_state(actor)?;
        Ok("State".to_string())
    } else {
        state_struct_name_for_actor(actor, model)
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
        program.modules[0].states[0].fields.push(FieldDecl { ty: TypeRef::new("int"), name: "gen__template_player".to_string() });

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

        assert!(sil.contains("byte[32] gen__init_template_foo"), "{sil}");
        assert!(sil.contains("byte[32] gen__template_foo = gen__init_template_foo;"), "{sil}");
        assert!(sil.contains("byte[] gen__foo_prefix"), "{sil}");
        assert!(sil.contains("int gen__foo_prefix_len = gen__foo_prefix.length;"), "{sil}");
        assert!(sil.contains("int gen__next_output_idx = OpAuthOutputIdx"), "{sil}");
        assert!(sil.contains("tx.outputs[gen__next_output_idx].value"), "{sil}");
        assert!(sil.contains("validateOutputStateWithTemplate(gen__next_output_idx,"), "{sil}");
        assert!(sil.contains("gen__state_foo_state"), "{sil}");
        assert!(manifest.contains(r#""symbol": "gen__template_foo""#), "{manifest}");
        assert!(!sil.contains("byte[32] init_template_foo"), "{sil}");
        assert!(!sil.contains("int next_output_idx ="), "{sil}");
        assert!(!sil.contains("byte[] foo_prefix"), "{sil}");
        assert!(!sil.contains("__argent_"), "{sil}");
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
        assert_eq!(artifact.templates[0].symbol, "gen__template_foo");

        let state = artifact.states.iter().find(|state| state.name == "FooState").expect("source state is present");
        assert_eq!(
            state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
            ["owner", "count"],
            "source state field order must stay stable"
        );
        assert_eq!(state.fields[0].ty, TypeArtifact::FixedBytes { len: 32 });
        assert_eq!(state.fields[1].ty, TypeArtifact::Int);

        let actor = artifact.actors.iter().find(|actor| actor.name == "Foo").expect("actor is present");
        assert_eq!(actor.sil, "sil/Foo.sil");
        let compiled = actor.compiled.as_ref().expect("actor should compile");
        assert_compiled_projection(actor.name.as_str(), compiled);
        assert_eq!(
            actor.runtime_state.fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>(),
            ["gen__template_foo", "owner", "count"],
            "runtime state field order must match generated Silverscript state order"
        );
        assert_eq!(actor.runtime_state.fields[0].name, "gen__template_foo");
        assert_eq!(actor.runtime_state.fields[0].role, RuntimeFieldRoleArtifact::Template { actor: "Foo".to_string() });
        assert_eq!(actor.runtime_state.fields[1].name, "owner");
        assert_eq!(actor.runtime_state.fields[1].role, RuntimeFieldRoleArtifact::Source);
        assert_eq!(actor.runtime_state.fields[2].role, RuntimeFieldRoleArtifact::Source);

        let entry = actor.entries.iter().find(|entry| entry.name == "step").expect("entry is present");
        assert_eq!(entry.kind, EntryKindArtifact::Leader);
        assert_eq!(entry.selector, None);
        assert_eq!(entry.user_params[0].name, "amount");
        assert_eq!(entry.user_params[0].ty, TypeArtifact::Int);
        assert_eq!(entry.hidden_params.len(), 2);
        assert_eq!(entry.hidden_params[0].name, "gen__foo_prefix");
        assert_eq!(entry.hidden_params[0].ty, TypeArtifact::Bytes);
        assert_eq!(entry.hidden_params[0].purpose, HiddenParamPurposeArtifact::TemplatePrefix { actor: "Foo".to_string() });
        assert_eq!(entry.hidden_params[1].name, "gen__foo_suffix");
        assert!(matches!(entry.emits, EmitArtifact::One { .. }));
        assert_eq!(entry.routes[0].actor, "Foo");
        assert_eq!(entry.routes[0].state_expr, "self.state");
        assert_eq!(entry.terminal_paths[0].routes[0], entry.routes[0]);
    }

    #[test]
    fn builds_examples_with_compiled_artifacts() {
        assert_example_build_artifact(
            "examples/tickets.ag",
            "tickets",
            &[
                ("Issuer", "ec6914616ff6a90665dddde5cf8d63add565f90d5f64ea6cd4400a8dad8ad2d9"),
                ("Ticket", "babefa0b96f878232ddddbf0ea8b0ca7b88e1fd8a6d51b9fddc289557228233e"),
            ],
        );
        assert_example_build_artifact("examples/stones/app.ag", "stones", &[]);
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
        let sil = actor_sil.get("Foo").expect("Foo Sil exists");
        let constructor_args = constructor_args_for_actor(actor, &model).expect("constructor args build");
        let compiled = compile_contract(sil, &constructor_args, CompileOptions::default()).expect("generated Sil compiles");

        let bump = artifact.actors[0].entries.iter().find(|entry| entry.name == "bump").expect("bump entry exists");
        let done = artifact.actors[0].entries.iter().find(|entry| entry.name == "done").expect("done entry exists");
        assert_eq!(bump.selector, Some(0));
        assert_eq!(done.selector, Some(1));

        let portable_bump = crate::codec::encode_actor_entry_sig_script(
            &artifact,
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
            crate::codec::encode_actor_entry_sig_script(&artifact, "Foo", "done", &[]).expect("portable done sigscript builds");
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

        let expected_hashes = expected_hashes.iter().copied().collect::<BTreeMap<_, _>>();
        assert!(!artifact.actors.is_empty(), "artifact should contain actors");
        for actor in &artifact.actors {
            let compiled = actor.compiled.as_ref().unwrap_or_else(|| panic!("actor `{}` should compile", actor.name));
            assert_compiled_projection(actor.name.as_str(), compiled);
            assert_runtime_state_round_trip(actor, compiled);
            if let Some(expected_hash) = expected_hashes.get(actor.name.as_str()) {
                assert_eq!(&compiled.template.hash_hex, expected_hash, "actor `{}` template hash changed", actor.name);
            }
        }

        let _ = fs::remove_dir_all(out_dir);
    }

    fn assert_runtime_state_round_trip(actor: &ActorArtifact, compiled: &CompiledActorArtifact) {
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

    fn assert_compiled_projection(actor: &str, compiled: &CompiledActorArtifact) {
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

        let prefix = decode_hex(&compiled.template.prefix_hex);
        let suffix = decode_hex(&compiled.template.suffix_hex);
        let template_hash = blake2b_simd::Params::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize();
        assert_eq!(
            hex_encode(template_hash.as_bytes()),
            compiled.template.hash_hex,
            "actor `{actor}` template hash must be blake2b(prefix || suffix)"
        );
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input should have even length");
        hex.as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let hi = hex_nibble(chunk[0]);
                let lo = hex_nibble(chunk[1]);
                (hi << 4) | lo
            })
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex digit `{}`", byte as char),
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
                apps: vec![AppDecl { name: "Test".to_string(), actors: vec!["Player".to_string(), "Game".to_string()] }],
            }],
        }
    }
}
