use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::ast::*;
use crate::error::{ArgentError, Result};
use crate::lexer::{RESERVED_GENERATED_PREFIX, Token, TokenKind, lex};

pub fn emit_build(program: &Program, out_dir: impl AsRef<Path>) -> Result<()> {
    let out_dir = out_dir.as_ref();
    let sil_dir = out_dir.join("sil");
    fs::create_dir_all(&sil_dir).map_err(|err| ArgentError::at(out_dir, err.to_string()))?;

    let model = Model::from_program(program)?;
    for actor in &model.actors {
        let sil = emit_actor(actor, &model)?;
        fs::write(sil_dir.join(format!("{}.sil", actor.name)), sil)
            .map_err(|err| ArgentError::at(sil_dir.join(format!("{}.sil", actor.name)), err.to_string()))?;
    }

    fs::write(out_dir.join("manifest.json"), emit_manifest(program, &model))
        .map_err(|err| ArgentError::at(out_dir.join("manifest.json"), err.to_string()))?;
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
    use std::path::PathBuf;

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
