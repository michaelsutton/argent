use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::ast::*;
use crate::error::{ArgentError, Result};

pub fn emit_build(program: &Program, out_dir: impl AsRef<Path>) -> Result<()> {
    let out_dir = out_dir.as_ref();
    let sil_dir = out_dir.join("sil");
    fs::create_dir_all(&sil_dir).map_err(|err| ArgentError::at(out_dir, err.to_string()))?;

    let model = Model::from_program(program)?;
    for actor in &model.actors {
        let sil = emit_actor(actor, &model)?;
        fs::write(sil_dir.join(format!("{}.sil", actor.name)), sil).map_err(|err| {
            ArgentError::at(sil_dir.join(format!("{}.sil", actor.name)), err.to_string())
        })?;
    }

    fs::write(
        out_dir.join("manifest.json"),
        emit_manifest(program, &model),
    )
    .map_err(|err| ArgentError::at(out_dir.join("manifest.json"), err.to_string()))?;
    Ok(())
}

#[derive(Debug)]
struct Model<'a> {
    app_name: String,
    template_actors: Vec<String>,
    consts: Vec<&'a ConstDecl>,
    source_states: Vec<&'a StateDecl>,
    functions: Vec<&'a FunctionDecl>,
    states: BTreeMap<String, &'a StateDecl>,
    actors_by_name: BTreeMap<String, &'a ActorDecl>,
    actors: Vec<&'a ActorDecl>,
}

impl<'a> Model<'a> {
    fn from_program(program: &'a Program) -> Result<Self> {
        let consts = program
            .modules
            .iter()
            .flat_map(|module| module.consts.iter())
            .collect::<Vec<_>>();
        let source_states = program
            .modules
            .iter()
            .flat_map(|module| module.states.iter())
            .collect::<Vec<_>>();
        let functions = program
            .modules
            .iter()
            .flat_map(|module| module.functions.iter())
            .collect::<Vec<_>>();
        let states = program
            .states()
            .map(|state| (state.name.clone(), state))
            .collect::<BTreeMap<_, _>>();
        let all_actors = program
            .actors()
            .map(|actor| (actor.name.clone(), actor))
            .collect::<BTreeMap<_, _>>();

        let app = program.apps().next();
        let (app_name, template_actors) = if let Some(app) = app {
            (app.name.clone(), app.actors.clone())
        } else {
            (
                "ArgentApp".to_string(),
                all_actors.keys().cloned().collect(),
            )
        };

        let mut actors = Vec::new();
        for name in &template_actors {
            let actor = all_actors.get(name).copied().ok_or_else(|| {
                ArgentError::new(format!("app references unknown actor `{name}`"))
            })?;
            if !states.contains_key(&actor.state) {
                return Err(ArgentError::new(format!(
                    "actor `{}` owns unknown state `{}`",
                    actor.name, actor.state
                )));
            }
            actors.push(actor);
        }

        let model = Self {
            app_name,
            template_actors,
            consts,
            source_states,
            functions,
            states,
            actors_by_name: all_actors,
            actors,
        };
        model.validate()?;
        Ok(model)
    }

    fn state(&self, name: &str) -> Result<&StateDecl> {
        self.states
            .get(name)
            .copied()
            .ok_or_else(|| ArgentError::new(format!("unknown state `{name}`")))
    }

    fn actor(&self, name: &str) -> Result<&ActorDecl> {
        self.actors_by_name
            .get(name)
            .copied()
            .ok_or_else(|| ArgentError::new(format!("unknown actor `{name}`")))
    }

    fn actor_state(&self, name: &str) -> Result<&StateDecl> {
        let actor = self.actor(name)?;
        self.state(&actor.state)
    }

    fn validate(&self) -> Result<()> {
        let template_actor_set = self
            .template_actors
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for actor in &self.actors {
            for entry in &actor.entries {
                self.validate_entry(actor, entry, &template_actor_set)?;
            }
        }
        Ok(())
    }

    fn validate_entry(
        &self,
        actor: &ActorDecl,
        entry: &EntryDecl,
        template_actor_set: &BTreeSet<String>,
    ) -> Result<()> {
        for consume in &entry.consumes {
            self.require_template_actor(
                &consume.actor,
                template_actor_set,
                format!(
                    "entry `{}::{}` consumes unknown actor `{}`",
                    actor.name, entry.name, consume.actor
                ),
            )?;
        }

        match &entry.emits {
            EmitSpec::None => {}
            EmitSpec::One { actors } => {
                for target in actors {
                    self.require_template_actor(
                        target,
                        template_actor_set,
                        format!(
                            "entry `{}::{}` emits unknown actor `{target}`",
                            actor.name, entry.name
                        ),
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
                            format!(
                                "entry `{}::{}` output `{}` emits unknown actor `{target}`",
                                actor.name, entry.name, output.name
                            ),
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
                format!(
                    "entry `{}::{}` routes to unknown actor `{}`",
                    actor.name, entry.name, route.actor
                ),
            )?;
            self.actor_state(&route.actor)?;
            self.validate_route_allowed(actor, entry, route)?;
        }
        Ok(())
    }

    fn require_template_actor(
        &self,
        actor: &str,
        template_actor_set: &BTreeSet<String>,
        message: String,
    ) -> Result<()> {
        if !template_actor_set.contains(actor) {
            return Err(ArgentError::new(message));
        }
        self.actor_state(actor)?;
        Ok(())
    }

    fn validate_route_allowed(
        &self,
        actor: &ActorDecl,
        entry: &EntryDecl,
        route: &RouteCall,
    ) -> Result<()> {
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
                let output = outputs
                    .iter()
                    .find(|output| &output.name == output_name)
                    .ok_or_else(|| {
                        ArgentError::new(format!(
                            "entry `{}::{}` routes through unknown output `{output_name}`",
                            actor.name, entry.name
                        ))
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
        args.push(format!(
            "    byte[32] init_template_{}",
            to_snake(template_actor)
        ));
    }
    for field in &state.fields {
        args.push(format!("    {} init_{}", field.ty.to_sil(), field.name));
    }
    out.push_str(&args.join(",\n"));
    out.push_str("\n) {\n");

    emit_shared_constants(&mut out, model);
    emit_state_layouts(&mut out, model)?;
    emit_shared_functions(&mut out, model);

    emit_section_header(&mut out, "Template capability table");
    for template_actor in &model.template_actors {
        let ident = to_snake(template_actor);
        out.push_str(&format!(
            "    byte[32] template_{ident} = init_template_{ident};\n"
        ));
    }
    out.push('\n');

    emit_section_header(&mut out, &format!("{} state fields", actor.name));
    for field in &state.fields {
        out.push_str(&format!(
            "    {} {} = init_{};\n",
            field.ty.to_sil(),
            field.name,
            field.name
        ));
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
            out.push_str(&format!(
                "    {} constant {} = {};\n",
                konst.ty.to_sil(),
                konst.name,
                konst.value
            ));
        }
        out.push('\n');
    }
}

fn emit_state_layouts(out: &mut String, model: &Model<'_>) -> Result<()> {
    emit_section_header(out, "State layouts");
    let mut emitted = BTreeSet::new();
    for actor in &model.actors {
        if !emitted.insert(actor.state.clone()) {
            continue;
        }
        let state = model.state(&actor.state)?;
        out.push_str(&format!("    struct {} {{\n", state.name));
        for template_actor in &model.template_actors {
            out.push_str(&format!(
                "        byte[32] template_{};\n",
                to_snake(template_actor)
            ));
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
            let params = function
                .params
                .iter()
                .map(|param| format!("{} {}", param.ty.to_sil(), param.name))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "    function {}({}) : {} {{\n",
                function.name,
                params,
                function.return_ty.to_sil()
            ));
            out.push_str(&indent_block_body(&function.body, 8));
            out.push_str("    }\n");
        }
        out.push('\n');
    }
}

fn emit_entry(
    out: &mut String,
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
) -> Result<()> {
    out.push_str(&format!("    entrypoint function {}(", entry.name));
    let witness_actors = entry_witness_actors(entry, model);
    let sil_params = lower_entry_params(&entry.params, &witness_actors);
    out.push_str(&sil_params.join(", "));
    out.push_str(") {\n");

    for actor_name in &witness_actors {
        let ident = to_snake(actor_name);
        out.push_str(&format!(
            "        int {ident}_prefix_len = {ident}_prefix.length;\n"
        ));
        out.push_str(&format!(
            "        int {ident}_suffix_len = {ident}_suffix.length;\n"
        ));
    }
    if !witness_actors.is_empty() {
        out.push('\n');
    }

    if !entry.consumes.is_empty() {
        out.push_str("        byte[32] cov_id = OpInputCovenantId(this.activeInputIndex);\n");
        match entry.kind {
            EntryKind::Leader => {
                let count = entry.consumes.len() + 1;
                out.push_str(&format!(
                    "        require(OpCovInputCount(cov_id) == {count});\n"
                ));
                out.push_str(
                    "        require(OpCovInputIdx(cov_id, 0) == this.activeInputIndex);\n",
                );
            }
            EntryKind::Delegate => {
                let min_count = entry.consumes.len() + 1;
                out.push_str(&format!(
                    "        require(OpCovInputCount(cov_id) >= {min_count});\n"
                ));
                out.push_str(
                    "        require(OpCovInputIdx(cov_id, 0) != this.activeInputIndex);\n",
                );
            }
        }

        let slot_offset = match entry.kind {
            EntryKind::Leader => 1,
            EntryKind::Delegate => 0,
        };
        for (idx, consume) in entry.consumes.iter().enumerate() {
            let cov_index = slot_offset + idx;
            let ident = to_snake(&consume.actor);
            let state_struct = state_struct_name_for_actor(&consume.actor, model)?;
            let _state = model.actor_state(&consume.actor)?;
            out.push_str(&format!(
                "        int {}_input_idx = OpCovInputIdx(cov_id, {}); // input {} at cov[{}]\n",
                consume.name, cov_index, consume.actor, cov_index
            ));
            out.push_str(&format!(
                "        {state_struct} {} = readInputStateWithTemplate({}_input_idx, {ident}_prefix_len, {ident}_suffix_len, template_{ident});\n",
                consume.name, consume.name
            ));
        }
    }

    match &entry.emits {
        EmitSpec::None => {
            out.push_str("        require(OpAuthOutputCount(this.activeInputIndex) == 0);\n");
        }
        EmitSpec::One { actors } => {
            out.push_str("        require(OpAuthOutputCount(this.activeInputIndex) == 1);\n");
            out.push_str(&format!(
                "        int next_output_idx = OpAuthOutputIdx(this.activeInputIndex, 0); // emits one {}\n",
                actors.join(" | ")
            ));
        }
        EmitSpec::Outputs(outputs) => {
            out.push_str(&format!(
                "        require(OpAuthOutputCount(this.activeInputIndex) == {});\n",
                outputs.len()
            ));
            for output in outputs {
                out.push_str(&format!(
                    "        int {}_output_idx = OpAuthOutputIdx(this.activeInputIndex, {}); // output {}: {}\n",
                    output.name,
                    output.auth_index,
                    output.name,
                    output.actors.join(" | ")
                ));
            }
        }
    }

    if entry.routes.is_empty() {
        out.push('\n');
        out.push_str(&lower_plain_entry_body(actor, entry, model)?);
    } else {
        emit_route_notes(out, actor, entry, model)?;

        out.push_str("\n        // TODO: lower source body.\n");
        out.push_str(
            "        // Raw source body is retained in the AST for the next compiler pass.\n",
        );
        out.push_str("        require(1 == 1);\n");
    }
    out.push_str("    }\n");
    Ok(())
}

fn lower_plain_entry_body(
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
) -> Result<String> {
    let mut types = BTreeMap::new();
    for field in &model.state(&actor.state)?.fields {
        types.insert(field.name.clone(), field.ty.to_sil());
    }
    for param in &entry.params {
        types.insert(param.name.clone(), param.ty.to_sil());
    }
    for consume in &entry.consumes {
        types.insert(
            consume.name.clone(),
            state_struct_name_for_actor(&consume.actor, model)?,
        );
    }

    let mut out = String::new();
    for line in entry.body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            out.push('\n');
            continue;
        }

        let lowered = if let Some(rest) = trimmed.strip_prefix("let ") {
            lower_local_definition(rest, &mut types, model)?
        } else if let Some(rest) = trimmed.strip_prefix("var ") {
            lower_local_definition(rest, &mut types, model)?
        } else {
            lower_plain_statement(trimmed)
        };

        out.push_str("        ");
        out.push_str(&lowered);
        out.push('\n');
    }

    if out.trim().is_empty() {
        out.push_str("        require(1 == 1);\n");
    }

    Ok(out)
}

fn lower_local_definition(
    rest: &str,
    types: &mut BTreeMap<String, String>,
    model: &Model<'_>,
) -> Result<String> {
    let (name, expr) = rest
        .split_once('=')
        .ok_or_else(|| ArgentError::new(format!("expected initializer in `{rest}`")))?;
    let name = name.trim();
    let expr = expr.trim();
    let expr = expr
        .strip_suffix(';')
        .ok_or_else(|| ArgentError::new(format!("expected `;` after local definition `{rest}`")))?
        .trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return Err(ArgentError::new(format!(
            "unsupported local binding `{name}`"
        )));
    }

    let ty = infer_expr_type(expr, types, model).ok_or_else(|| {
        ArgentError::new(format!(
            "cannot infer type for local `{name}` from expression `{expr}`"
        ))
    })?;
    types.insert(name.to_string(), ty.clone());
    Ok(format!("{ty} {name} = {};", lower_plain_expression(expr)))
}

fn lower_plain_statement(statement: &str) -> String {
    lower_plain_expression(statement)
}

fn lower_plain_expression(expr: &str) -> String {
    expr.replace("self.value", "tx.inputs[this.activeInputIndex].value")
}

fn infer_expr_type(
    expr: &str,
    types: &BTreeMap<String, String>,
    model: &Model<'_>,
) -> Option<String> {
    let expr = expr.trim();
    if let Some(ty) = types.get(expr) {
        return Some(ty.clone());
    }
    if expr.chars().all(|ch| ch.is_ascii_digit()) {
        return Some("int".to_string());
    }
    if expr.starts_with("blake2b(") {
        return Some("byte[32]".to_string());
    }
    if expr.starts_with("checkSig(") {
        return Some("bool".to_string());
    }

    for function in &model.functions {
        if expr.starts_with(&format!("{}(", function.name)) {
            return Some(function.return_ty.to_sil());
        }
    }
    for state in &model.source_states {
        if expr.starts_with(&format!("{} {{", state.name))
            || expr.starts_with(&format!("{}{{", state.name))
        {
            return Some(state.name.clone());
        }
    }

    infer_field_access_type(expr, types, model)
}

fn infer_field_access_type(
    expr: &str,
    types: &BTreeMap<String, String>,
    model: &Model<'_>,
) -> Option<String> {
    let (base, field) = expr.split_once('.')?;
    if field.contains('.') || field.contains('(') || field.contains(' ') {
        return None;
    }
    let base_type = types.get(base)?;
    let state = model
        .source_states
        .iter()
        .find(|state| state.name == *base_type)
        .copied()
        .or_else(|| {
            model.actors.iter().find_map(|actor| {
                if actor.state == *base_type {
                    model.state(&actor.state).ok()
                } else {
                    None
                }
            })
        })?;
    state
        .fields
        .iter()
        .find(|candidate| candidate.name == field)
        .map(|field| field.ty.to_sil())
}

fn lower_entry_params(params: &[ParamDecl], witness_actors: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for param in params {
        out.push(format!("{} {}", param.ty.to_sil(), param.name));
    }
    for actor_name in witness_actors {
        let ident = to_snake(actor_name);
        out.push(format!("byte[] {ident}_prefix"));
        out.push(format!("byte[] {ident}_suffix"));
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

fn emit_route_notes(
    out: &mut String,
    actor: &ActorDecl,
    entry: &EntryDecl,
    model: &Model<'_>,
) -> Result<()> {
    if entry.routes.is_empty() {
        return Ok(());
    }

    out.push_str("\n        // Become routes extracted for the next lowering pass.\n");
    for route in &entry.routes {
        let target = to_snake(&route.actor);
        let output_idx = route
            .output
            .as_ref()
            .map(|output| format!("{output}_output_idx"))
            .unwrap_or_else(|| "next_output_idx".to_string());
        let route_head = route
            .output
            .as_ref()
            .map(|output| format!("{output} <- {}", route.actor))
            .unwrap_or_else(|| route.actor.clone());
        out.push_str(&format!(
            "        // become {}({});\n",
            route_head,
            compact_expr(&route.state)
        ));
        out.push_str(&format!(
            "        // validateOutputStateWithTemplate({}, <{}>, {}_prefix, {}_suffix, template_{});\n",
            output_idx,
            state_struct_name_for_actor(&route.actor, model)?,
            target,
            target,
            target
        ));
    }
    out.push_str(&format!(
        "        // Current actor `{}` copies template_* fields into every generated successor state.\n",
        actor.name
    ));
    Ok(())
}

fn emit_manifest(program: &Program, model: &Model<'_>) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"app\": \"{}\",\n",
        json_escape(&model.app_name)
    ));
    out.push_str(&format!(
        "  \"root\": \"{}\",\n",
        json_escape(&program.root.display().to_string())
    ));

    out.push_str("  \"modules\": [\n");
    for (idx, module) in program.modules.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "    \"{}\"",
            json_escape(&module.path.display().to_string())
        ));
    }
    out.push_str("\n  ],\n");

    out.push_str("  \"templates\": [\n");
    for (idx, actor) in model.template_actors.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str(&format!(
            "    {{ \"actor\": \"{}\", \"symbol\": \"template_{}\", \"hash\": null }}",
            json_escape(actor),
            to_snake(actor)
        ));
    }
    out.push_str("\n  ],\n");

    out.push_str("  \"actors\": [\n");
    for (idx, actor) in model.actors.iter().enumerate() {
        if idx > 0 {
            out.push_str(",\n");
        }
        out.push_str("    {\n");
        out.push_str(&format!(
            "      \"name\": \"{}\",\n",
            json_escape(&actor.name)
        ));
        out.push_str(&format!(
            "      \"state\": \"{}\",\n",
            json_escape(&actor.state)
        ));
        out.push_str(&format!(
            "      \"sil\": \"sil/{}.sil\",\n",
            json_escape(&actor.name)
        ));
        out.push_str("      \"entries\": [\n");
        for (entry_idx, entry) in actor.entries.iter().enumerate() {
            if entry_idx > 0 {
                out.push_str(",\n");
            }
            out.push_str("        {\n");
            out.push_str(&format!(
                "          \"name\": \"{}\",\n",
                json_escape(&entry.name)
            ));
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
                let output = route
                    .output
                    .as_ref()
                    .map(|output| format!("\"{}\"", json_escape(output)))
                    .unwrap_or_else(|| "null".to_string());
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

fn to_snake(input: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in input.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn state_struct_name_for_actor(actor: &str, model: &Model<'_>) -> Result<String> {
    Ok(model.actor(actor)?.state.clone())
}

fn compact_expr(input: &str) -> String {
    let without_comments = input
        .lines()
        .map(|line| line.split_once("//").map(|(code, _)| code).unwrap_or(line))
        .collect::<Vec<_>>()
        .join(" ");
    let compact = without_comments
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let mut chars = compact.chars();
    let prefix = chars.by_ref().take(96).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        compact
    }
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
        .map(|line| {
            line.chars()
                .take_while(|ch| *ch == ' ' || *ch == '\t')
                .count()
        })
        .min()
        .unwrap_or(0);

    let mut out = String::new();
    for line in trimmed.lines() {
        if line.trim().is_empty() {
            out.push('\n');
        } else {
            out.push_str(&indent);
            out.push_str(
                line.get(common_indent..)
                    .unwrap_or_else(|| line.trim_start()),
            );
            out.push('\n');
        }
    }
    out
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn rejects_route_outside_named_output_union() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].routes = vec![RouteCall {
            output: Some("next".to_string()),
            actor: "Game".to_string(),
            state: "next_game".to_string(),
        }];

        let err = Model::from_program(&program).expect_err("route must be rejected");
        assert!(
            err.to_string().contains("routes output `next` to `Game`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn accepts_route_inside_named_output_union() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].emits = EmitSpec::Outputs(vec![EmitOutput {
            name: "next".to_string(),
            actors: vec!["Player".to_string(), "Game".to_string()],
            auth_index: 0,
        }]);
        program.modules[0].actors[0].entries[0].routes = vec![RouteCall {
            output: Some("next".to_string()),
            actor: "Game".to_string(),
            state: "next_game".to_string(),
        }];

        Model::from_program(&program).expect("route should be accepted");
    }

    #[test]
    fn rejects_delegate_become() {
        let mut program = test_program();
        program.modules[0].actors[0].entries[0].kind = EntryKind::Delegate;
        program.modules[0].actors[0].entries[0].emits = EmitSpec::None;
        program.modules[0].actors[0].entries[0].routes = vec![RouteCall {
            output: Some("next".to_string()),
            actor: "Player".to_string(),
            state: "next_player".to_string(),
        }];

        let err = Model::from_program(&program).expect_err("delegate become must be rejected");
        assert!(
            err.to_string().contains("cannot use `become`"),
            "unexpected error: {err}"
        );
    }

    fn test_program() -> Program {
        Program {
            root: PathBuf::from("test.ag"),
            modules: vec![Module {
                path: PathBuf::from("test.ag"),
                imports: Vec::new(),
                consts: Vec::new(),
                states: vec![
                    StateDecl {
                        name: "PlayerState".to_string(),
                        fields: Vec::new(),
                    },
                    StateDecl {
                        name: "GameState".to_string(),
                        fields: Vec::new(),
                    },
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
                        }],
                    },
                    ActorDecl {
                        name: "Game".to_string(),
                        state: "GameState".to_string(),
                        entries: Vec::new(),
                    },
                ],
                apps: vec![AppDecl {
                    name: "Test".to_string(),
                    actors: vec!["Player".to_string(), "Game".to_string()],
                }],
            }],
        }
    }
}
