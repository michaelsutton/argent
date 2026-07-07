use std::path::PathBuf;

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
}

#[derive(Debug, Clone)]
pub struct FieldDecl {
    pub ty: TypeRef,
    pub name: String,
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
pub struct EntryDecl {
    pub kind: EntryKind,
    pub name: String,
    pub params: Vec<ParamDecl>,
    pub consumes: Vec<ConsumeDecl>,
    pub emits: EmitSpec,
    pub body: String,
    pub routes: Vec<RouteCall>,
    pub terminal_route_sets: Vec<Vec<RouteCall>>,
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
    pub route_groups: Vec<RouteGroupDecl>,
}

#[derive(Debug, Clone)]
pub struct RouteGroupDecl {
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
}

impl TypeRef {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), array: None }
    }

    pub fn array(name: impl Into<String>, len: usize) -> Self {
        Self { name: name.into(), array: Some(len) }
    }

    pub fn to_sil(&self) -> String {
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

    pub fn apps(&self) -> impl Iterator<Item = &AppDecl> {
        self.modules.iter().flat_map(|module| module.apps.iter())
    }
}
