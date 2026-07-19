use std::path::PathBuf;

use crate::language::word;

#[derive(Debug, Clone)]
pub struct Program {
    pub root: PathBuf,
    pub modules: Vec<Module>,
}

#[derive(Debug, Clone)]
pub struct Module {
    pub path: PathBuf,
    pub imports: Vec<Import>,
    pub consts: Vec<ConstDecl>,
    pub states: Vec<StateDecl>,
    pub functions: Vec<FunctionDecl>,
    pub actors: Vec<ActorDecl>,
    pub actor_enums: Vec<ActorEnumDecl>,
    pub apps: Vec<AppDecl>,
}

#[derive(Debug, Clone)]
pub enum Import {
    Module { path: String },
    Actor { name: String, path: String },
}

#[derive(Debug, Clone)]
pub struct ConstDecl {
    pub ty: TypeRef,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct StateDecl {
    pub name: String,
    pub fields: Vec<FieldDecl>,
    pub expansion: Option<StateExpansionDecl>,
}

#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub ty: TypeRef,
    pub name: String,
    pub virtual_slot: bool,
}

#[derive(Debug, Clone)]
pub struct StateExpansionDecl {
    pub base: String,
    pub digests: Vec<StateDigestExpansionDecl>,
}

#[derive(Debug, Clone)]
pub struct StateDigestExpansionDecl {
    pub field: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct FunctionDecl {
    pub name: String,
    pub params: Vec<ParamDecl>,
    pub return_ty: TypeRef,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct ActorDecl {
    pub name: String,
    pub state: String,
    pub entries: Vec<EntryDecl>,
}

#[derive(Debug, Clone)]
pub struct ActorEnumDecl {
    pub name: String,
    pub variants: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EntryDecl {
    pub kind: EntryKind,
    pub name: String,
    pub params: Vec<ParamDecl>,
    pub consumes: Vec<ConsumeDecl>,
    pub observes: Vec<ObserveDecl>,
    pub spawns: Vec<SpawnDecl>,
    pub emits: EmitSpec,
    pub body: String,
    pub routes: Vec<RouteCall>,
    pub terminal_route_sets: Vec<Vec<RouteCall>>,
}

#[derive(Debug, Clone)]
pub struct SpawnDecl {
    pub name: String,
    pub covenant: String,
    pub outputs: Vec<SpawnOutputDecl>,
}

#[derive(Debug, Clone)]
pub struct SpawnOutputDecl {
    pub name: String,
    pub actor: String,
    pub group_index: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EntryKind {
    Leader,
    Delegate,
}

#[derive(Debug, Clone)]
pub struct ParamDecl {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Debug, Clone)]
pub struct ConsumeDecl {
    pub name: String,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct ObserveDecl {
    pub name: String,
    pub covenant_expr: String,
    pub inputs: Vec<ObservedActorDecl>,
    pub outputs: Vec<ObservedActorDecl>,
}

#[derive(Debug, Clone)]
pub struct ObservedActorDecl {
    pub name: String,
    pub actor: String,
    pub open_state: Option<String>,
}

#[derive(Debug, Clone)]
pub enum EmitSpec {
    None,
    One { actors: Vec<String> },
    Outputs(Vec<EmitOutput>),
}

#[derive(Debug, Clone)]
pub struct EmitOutput {
    pub name: String,
    pub actors: Vec<String>,
    pub auth_index: usize,
}

#[derive(Debug, Clone)]
pub struct AppDecl {
    pub name: String,
    pub actors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RouteCall {
    pub output: Option<String>,
    pub actor: String,
    pub state: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TypeRef {
    pub name: String,
    pub array: Option<usize>,
    pub actor_state: Option<String>,
}

impl TypeRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), array: None, actor_state: None }
    }

    pub fn array(name: impl Into<String>, len: usize) -> Self {
        Self { name: name.into(), array: Some(len), actor_state: None }
    }

    pub fn actor_type(state: impl Into<String>) -> Self {
        Self { name: word::ACTOR_TYPE.to_string(), array: None, actor_state: Some(state.into()) }
    }

    pub fn is_actor_type(&self) -> bool {
        self.name == word::ACTOR_TYPE && self.array.is_none() && self.actor_state.is_some()
    }

    pub fn to_sil(&self) -> String {
        if self.is_actor_type() {
            return "byte[32]".to_string();
        }
        match self.array {
            Some(len) => format!("{}[{}]", self.name, len),
            None => self.name.clone(),
        }
    }
}

impl Program {
    pub fn states(&self) -> impl Iterator<Item = &StateDecl> {
        self.modules.iter().flat_map(|module| module.states.iter())
    }

    pub fn actors(&self) -> impl Iterator<Item = &ActorDecl> {
        self.modules.iter().flat_map(|module| module.actors.iter())
    }

    pub fn actor_enums(&self) -> impl Iterator<Item = &ActorEnumDecl> {
        self.modules.iter().flat_map(|module| module.actor_enums.iter())
    }

    pub fn apps(&self) -> impl Iterator<Item = &AppDecl> {
        self.modules.iter().flat_map(|module| module.apps.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::TypeRef;

    #[test]
    fn actor_type_requires_the_canonical_type_name() {
        let mut ty = TypeRef::actor_type("State");
        assert!(ty.is_actor_type());

        ty.name = "other".to_string();
        assert!(!ty.is_actor_type());
    }
}
