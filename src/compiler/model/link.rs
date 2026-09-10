//! Links imported app artifacts into the selected application's model.
//!
//! Linked interfaces, templates, states, and actor enums become model inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::artifact::*;
use crate::compiler::loader::stdlib::is_standard_module;
use crate::compiler::syntax::*;
use crate::error::{ArgentError, Result};

#[derive(Debug, Clone)]
pub(crate) struct LinkedActor {
    pub app: String,
    pub actor: String,
    pub state: String,
    pub interface: ActorInterfaceArtifact,
    pub template: ActorTemplateArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkedActorEnum {
    pub name: String,
    pub state: String,
    pub variants: Vec<String>,
}

pub(crate) struct LinkedContext {
    pub states: BTreeMap<String, StateDecl>,
    pub actor_decls: BTreeMap<String, ActorDecl>,
    pub actors: BTreeMap<String, LinkedActor>,
    pub actor_enums: BTreeMap<String, LinkedActorEnum>,
}

pub(crate) fn link_imported_actors(
    program: &Program,
    dependencies: &BTreeMap<String, &Artifact>,
    local_states: &BTreeMap<String, &StateDecl>,
    local_actors: &BTreeMap<String, &ActorDecl>,
) -> Result<LinkedContext> {
    for (app, artifact) in dependencies {
        if artifact.app != *app {
            return Err(ArgentError::new(format!("linked artifact for app `{app}` declares app `{}`", artifact.app)));
        }
        artifact.check_consistency().map_err(|err| ArgentError::new(format!("linked app `{app}` has an invalid artifact: {err}")))?;
    }

    let mut bindings = BTreeMap::<String, (String, String)>::new();
    for module in &program.modules {
        for import in &module.imports {
            match import {
                Import::AppActor { app, actor, .. } => {
                    insert_linked_binding(&mut bindings, actor.clone(), app, actor, &module.path)?;
                }
                Import::App { app, .. } => {
                    insert_app_bindings(&mut bindings, dependencies, app, &module.path)?;
                }
                Import::Module { path } if !is_standard_module(path) => {
                    let base = module.path.parent().ok_or_else(|| ArgentError::at(&module.path, "module path has no parent"))?;
                    let source = fs::canonicalize(base.join(path)).map_err(|err| ArgentError::at(&module.path, err.to_string()))?;
                    let imported = program
                        .modules
                        .iter()
                        .find(|candidate| candidate.path == source)
                        .ok_or_else(|| ArgentError::at(&module.path, format!("module import source `{path}` was not loaded")))?;
                    for app in &imported.apps {
                        if dependencies.contains_key(&app.name) {
                            insert_app_bindings(&mut bindings, dependencies, &app.name, &module.path)?;
                        }
                    }
                }
                Import::Module { .. } | Import::Actor { .. } => {}
            }
        }
    }

    let mut states = BTreeMap::<String, StateDecl>::new();
    let mut actor_decls = BTreeMap::<String, ActorDecl>::new();
    let mut actors = BTreeMap::<String, LinkedActor>::new();
    let mut actor_enums = BTreeMap::<String, LinkedActorEnum>::new();
    for (reference, (app, actor_name)) in bindings {
        if local_actors.contains_key(&reference) {
            return Err(ArgentError::new(format!("imported actor reference `{reference}` conflicts with a local actor declaration")));
        }
        let artifact = dependencies
            .get(&app)
            .ok_or_else(|| ArgentError::new(format!("actor import `{app}::{actor_name}` has no compiled dependency artifact")))?;
        let actor = artifact
            .argent
            .actors
            .iter()
            .find(|actor| actor.name == actor_name)
            .ok_or_else(|| ArgentError::new(format!("app `{app}` does not export actor `{actor_name}`")))?;
        let interface = artifact
            .argent
            .interfaces
            .exports
            .iter()
            .find(|interface| interface.app == app && interface.actor == actor_name)
            .ok_or_else(|| ArgentError::new(format!("app `{app}` has no exported interface for actor `{actor_name}`")))?;
        let template = artifact
            .argent
            .template_plan
            .templates
            .iter()
            .find(|template| template.actor == actor_name)
            .ok_or_else(|| ArgentError::new(format!("app `{app}` has no template receipt for actor `{actor_name}`")))?;
        let exported_template = template.actor_type_handle.template.clone();

        import_linked_state_closure(artifact, &actor.state, local_states, &mut states)?;
        for actor_enum in &artifact.argent.actor_enums {
            if !states.contains_key(&actor_enum.state) {
                continue;
            }
            let linked = LinkedActorEnum {
                name: actor_enum.name.clone(),
                state: actor_enum.state.clone(),
                variants: actor_enum.variants.clone(),
            };
            if let Some(previous) = actor_enums.insert(linked.name.clone(), linked.clone())
                && previous != linked
            {
                return Err(ArgentError::new(format!("linked apps provide conflicting actor enum definitions for `{}`", linked.name)));
            }
        }

        let decl = ActorDecl { name: reference.clone(), state: actor.state.clone(), functions: Vec::new(), entries: Vec::new() };
        let linked = LinkedActor {
            app,
            actor: actor.name.clone(),
            state: actor.state.clone(),
            interface: interface.clone(),
            template: exported_template,
        };
        actor_decls.insert(reference.clone(), decl);
        actors.insert(reference, linked);
    }

    Ok(LinkedContext { states, actor_decls, actors, actor_enums })
}

fn insert_linked_binding(
    bindings: &mut BTreeMap<String, (String, String)>,
    reference: String,
    app: &str,
    actor: &str,
    path: &Path,
) -> Result<()> {
    let binding = (app.to_string(), actor.to_string());
    if let Some(previous) = bindings.insert(reference.clone(), binding.clone())
        && previous != binding
    {
        return Err(ArgentError::at(
            path,
            format!("actor reference `{reference}` is imported as both `{}::{}` and `{app}::{actor}`", previous.0, previous.1),
        ));
    }
    Ok(())
}

fn insert_app_bindings(
    bindings: &mut BTreeMap<String, (String, String)>,
    dependencies: &BTreeMap<String, &Artifact>,
    app: &str,
    path: &Path,
) -> Result<()> {
    let artifact =
        dependencies.get(app).ok_or_else(|| ArgentError::at(path, format!("app `{app}` has no compiled dependency artifact")))?;
    for interface in &artifact.argent.interfaces.exports {
        insert_linked_binding(bindings, format!("{app}::{}", interface.actor), app, &interface.actor, path)?;
    }
    Ok(())
}

fn import_linked_state_closure(
    artifact: &Artifact,
    root: &str,
    local_states: &BTreeMap<String, &StateDecl>,
    linked_states: &mut BTreeMap<String, StateDecl>,
) -> Result<()> {
    let states = artifact.argent.states.iter().map(|state| (state.name.as_str(), state)).collect::<BTreeMap<_, _>>();
    let expansions =
        artifact.argent.state_expansions.iter().map(|expansion| (expansion.state.as_str(), expansion)).collect::<BTreeMap<_, _>>();
    let mut pending = vec![root.to_string()];
    let mut visited = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let state = states
            .get(name.as_str())
            .ok_or_else(|| ArgentError::new(format!("linked app `{}` does not describe state `{name}`", artifact.app)))?;
        let expansion = expansions.get(name.as_str()).copied();
        let fields =
            if expansion.is_some() { Vec::new() } else { state.fields.iter().map(linked_field_decl).collect::<Result<Vec<_>>>()? };
        let expansion = expansion.map(|expansion| StateExpansionDecl {
            base: expansion.base.clone(),
            digests: expansion
                .digests
                .iter()
                .map(|digest| StateDigestExpansionDecl { field: digest.field.clone(), state: digest.state.clone() })
                .collect(),
        });
        let decl = StateDecl { name: name.clone(), fields, expansion };
        if let Some(local) = local_states.get(&name) {
            if !same_state_decl(local, &decl) {
                return Err(ArgentError::new(format!(
                    "linked app `{}` state `{name}` conflicts with its imported source declaration",
                    artifact.app
                )));
            }
        } else if let Some(previous) = linked_states.insert(name.clone(), decl.clone())
            && !same_state_decl(&previous, &decl)
        {
            return Err(ArgentError::new(format!("linked apps provide conflicting state definitions for `{name}`")));
        }

        if let Some(expansion) = &decl.expansion {
            pending.push(expansion.base.clone());
            pending.extend(expansion.digests.iter().map(|digest| digest.state.clone()));
        }
        let physical_state =
            expansions.get(name.as_str()).and_then(|expansion| states.get(expansion.base.as_str()).copied()).unwrap_or(state);
        for field in &physical_state.fields {
            let ty = linked_field_type(field)?;
            if states.contains_key(ty.name.as_str()) {
                pending.push(ty.name.clone());
            }
            if let Some(actor_state) = ty.actor_state
                && states.contains_key(actor_state.as_str())
            {
                pending.push(actor_state);
            }
        }
    }
    Ok(())
}

fn linked_field_decl(field: &ArgentFieldArtifact) -> Result<FieldDecl> {
    Ok(FieldDecl { ty: linked_field_type(field)?, name: field.name.clone(), virtual_slot: field.virtual_slot })
}

fn linked_field_type(field: &ArgentFieldArtifact) -> Result<TypeRef> {
    if let Some(source) = &field.source_type {
        return Ok(TypeRef {
            name: source.name.clone(),
            array: source.array.map(|array| match array {
                SourceArrayArtifact::Dynamic => ArrayDim::Dynamic,
                SourceArrayArtifact::Fixed(len) => ArrayDim::Fixed(len),
            }),
            actor_state: source.actor_state.clone(),
        });
    }
    linked_type_ref(&field.ty)
}

fn linked_type_ref(ty: &TypeArtifact) -> Result<TypeRef> {
    let scalar = |name: &str| Ok(TypeRef::new(name));
    match ty {
        TypeArtifact::Int => scalar("int"),
        TypeArtifact::Temporal => scalar("temporal"),
        TypeArtifact::Bool => scalar("bool"),
        TypeArtifact::Byte => scalar("byte"),
        TypeArtifact::Bytes => Ok(TypeRef::dynamic_array("byte")),
        TypeArtifact::Text => scalar("string"),
        TypeArtifact::Pubkey => scalar("pubkey"),
        TypeArtifact::Sig => scalar("sig"),
        TypeArtifact::Datasig => scalar("datasig"),
        TypeArtifact::FixedBytes { len } => Ok(TypeRef::array("byte", *len)),
        TypeArtifact::FixedArray { item, len } => {
            let item = linked_type_ref(item)?;
            if item.array.is_some() || item.actor_state.is_some() {
                return Err(ArgentError::new("linked artifacts cannot expose nested array state fields"));
            }
            Ok(TypeRef::array(item.name, *len))
        }
        TypeArtifact::DynamicArray { item } => {
            let item = linked_type_ref(item)?;
            if item.array.is_some() || item.actor_state.is_some() {
                return Err(ArgentError::new("linked artifacts cannot expose nested array state fields"));
            }
            Ok(TypeRef::dynamic_array(item.name))
        }
        TypeArtifact::Struct { name } => scalar(name),
    }
}

fn same_state_decl(left: &StateDecl, right: &StateDecl) -> bool {
    left.name == right.name
        && left.fields.len() == right.fields.len()
        && left
            .fields
            .iter()
            .zip(&right.fields)
            .all(|(left, right)| left.name == right.name && left.ty == right.ty && left.virtual_slot == right.virtual_slot)
        && match (&left.expansion, &right.expansion) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.base == right.base
                    && left.digests.len() == right.digests.len()
                    && left
                        .digests
                        .iter()
                        .zip(&right.digests)
                        .all(|(left, right)| left.field == right.field && left.state == right.state)
            }
            _ => false,
        }
}
