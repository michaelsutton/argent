use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod sil_abi;

pub use sil_abi::{
    CompiledActorArtifact, CompiledTemplateArtifact, RuntimeFieldArtifact, RuntimeFieldRoleArtifact, RuntimeStateArtifact,
    SIL_ABI_SCHEMA_VERSION, SilAbiArtifact, SilActorArtifact, SilEntryArtifact, StateSpanArtifact,
};

pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub schema_version: u32,
    pub generator: GeneratorArtifact,
    pub app: String,
    pub root: String,
    pub modules: Vec<String>,
    pub argent: ArgentArtifact,
    pub sil_abi: SilAbiArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgentArtifact {
    pub templates: Vec<TemplateRefArtifact>,
    pub states: Vec<StateArtifact>,
    pub actors: Vec<ActorArtifact>,
}

impl Artifact {
    pub fn check_schema_version(&self) -> std::result::Result<(), ArtifactVersionError> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION {
            return Err(ArtifactVersionError {
                artifact: "Argent artifact",
                supported: ARTIFACT_SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        self.sil_abi.check_schema_version()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unsupported {artifact} schema version {found}; expected {supported}")]
pub struct ArtifactVersionError {
    pub artifact: &'static str,
    pub supported: u32,
    pub found: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorArtifact {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRefArtifact {
    pub actor: String,
    pub symbol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateArtifact {
    pub name: String,
    pub fields: Vec<FieldArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorArtifact {
    pub name: String,
    pub state: String,
    pub abi: ActorAbiRefArtifact,
    pub entries: Vec<EntryArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorAbiRefArtifact {
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryArtifact {
    pub name: String,
    pub kind: EntryKindArtifact,
    pub abi: EntryAbiRefArtifact,
    #[serde(default)]
    pub route_plan: EntryRoutePlanArtifact,
    pub witnesses: Vec<WitnessArtifact>,
    pub consumes: Vec<ConsumeArtifact>,
    pub emits: EmitArtifact,
    pub routes: Vec<RouteArtifact>,
    pub terminal_paths: Vec<TerminalPathArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryAbiRefArtifact {
    pub actor: String,
    pub entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessArtifact {
    pub param: String,
    pub actor: String,
    pub purpose: HiddenParamPurposeArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKindArtifact {
    Leader,
    Delegate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenParamArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
    pub actor: String,
    pub purpose: HiddenParamPurposeArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenParamPurposeArtifact {
    TemplatePrefixBytes,
    TemplateSuffixBytes,
    TemplatePrefixLen,
    TemplateSuffixLen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumeArtifact {
    pub name: String,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmitArtifact {
    None,
    One { actors: Vec<String> },
    Outputs { outputs: Vec<EmitOutputArtifact> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitOutputArtifact {
    pub name: String,
    pub auth_index: usize,
    pub actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EntryRoutePlanArtifact {
    pub active_input: Option<RouteInputArtifact>,
    pub leader_input: Option<RouteInputArtifact>,
    pub consumes: Vec<RouteInputArtifact>,
    pub outputs: Vec<RouteOutputHandleArtifact>,
    pub terminal_paths: Vec<PlannedTerminalPathArtifact>,
    pub witnesses: Vec<WitnessArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInputArtifact {
    pub name: String,
    pub actor: String,
    pub cov_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteOutputHandleArtifact {
    pub name: Option<String>,
    pub auth_index: usize,
    pub actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedTerminalPathArtifact {
    pub routes: Vec<PlannedRouteArtifact>,
    pub witnesses: Vec<WitnessArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRouteArtifact {
    pub output: Option<String>,
    pub auth_index: usize,
    pub actor: String,
    pub state_expr: String,
    pub witnesses: Vec<WitnessArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteArtifact {
    pub output: Option<String>,
    pub actor: String,
    pub state_expr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalPathArtifact {
    pub routes: Vec<RouteArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeArtifact {
    Int,
    Bool,
    Byte,
    Bytes,
    #[serde(rename = "string")]
    Text,
    Pubkey,
    Sig,
    Datasig,
    FixedBytes {
        len: usize,
    },
    FixedArray {
        item: Box<TypeArtifact>,
        len: usize,
    },
    DynamicArray {
        item: Box<TypeArtifact>,
    },
    Struct {
        name: String,
    },
}

impl TypeArtifact {
    pub fn from_parts(name: &str, array_len: Option<usize>) -> Self {
        match (name, array_len) {
            ("byte", Some(len)) => Self::FixedBytes { len },
            (_, Some(len)) => Self::FixedArray { item: Box::new(Self::scalar(name)), len },
            (_, None) => Self::scalar(name),
        }
    }

    pub fn dynamic_array(item: Self) -> Self {
        Self::DynamicArray { item: Box::new(item) }
    }

    fn scalar(name: &str) -> Self {
        match name {
            "int" => Self::Int,
            "bool" => Self::Bool,
            "byte" => Self::Byte,
            "bytes" => Self::Bytes,
            "string" => Self::Text,
            "pubkey" => Self::Pubkey,
            "sig" => Self::Sig,
            "datasig" => Self::Datasig,
            _ => Self::Struct { name: name.to_string() },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowers_fixed_bytes_as_structural_type() {
        assert_eq!(TypeArtifact::from_parts("byte", Some(32)), TypeArtifact::FixedBytes { len: 32 });
    }

    #[test]
    fn lowers_fixed_non_byte_arrays_as_structural_type() {
        assert_eq!(TypeArtifact::from_parts("int", Some(3)), TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Int), len: 3 });
    }

    #[test]
    fn deserializes_portable_artifact_without_compiler_ast_values() {
        let json = r#"
        {
          "schema_version": 1,
          "generator": { "name": "argentc", "version": "0.1.0" },
          "app": "Tiny",
          "root": "examples/tiny.ag",
          "modules": ["examples/tiny.ag"],
          "argent": {
            "templates": [{ "actor": "Foo", "symbol": "gen__template_foo" }],
            "states": [
              {
                "name": "FooState",
                "fields": [{ "name": "owner", "type": { "kind": "fixed_bytes", "len": 32 } }]
              }
            ],
            "actors": [
              {
                "name": "Foo",
                "state": "FooState",
                "abi": { "actor": "Foo" },
                "entries": []
              }
            ]
          },
          "sil_abi": {
            "schema_version": 1,
            "states": [
              {
                "name": "FooState",
                "fields": [{ "name": "owner", "type": { "kind": "fixed_bytes", "len": 32 } }]
              }
            ],
            "actors": [
              {
                "name": "Foo",
                "source_path": "sil/Foo.sil",
                "runtime_state": {
                  "source": "FooState",
                  "fields": [
                    {
                      "name": "gen__template_foo",
                      "type": { "kind": "fixed_bytes", "len": 32 },
                      "role": { "kind": "template", "actor": "Foo" }
                    },
                    {
                      "name": "owner",
                      "type": { "kind": "fixed_bytes", "len": 32 },
                      "role": { "kind": "source" }
                    }
                  ]
                },
                "entries": [],
                "compiled": {
                  "script_hex": "",
                  "template": { "prefix_hex": "", "suffix_hex": "", "hash_hex": "" },
                  "state_span": { "offset": 0, "len": 0 }
                }
              }
            ]
          }
        }
        "#;

        let artifact: Artifact = serde_json::from_str(json).expect("artifact should deserialize");
        artifact.check_schema_version().expect("schema version should be supported");
        assert_eq!(artifact.argent.actors[0].abi.actor, "Foo");
        assert_eq!(artifact.sil_abi.actors[0].compiled.script_hex, "");
    }

    #[test]
    fn rejects_unknown_argent_schema_version() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION + 1,
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact { templates: Vec::new(), states: Vec::new(), actors: Vec::new() },
            sil_abi: SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION, states: Vec::new(), actors: Vec::new() },
        };

        let err = artifact.check_schema_version().expect_err("future schema must be rejected");
        assert_eq!(err.artifact, "Argent artifact");
        assert_eq!(err.found, ARTIFACT_SCHEMA_VERSION + 1);
    }

    #[test]
    fn rejects_unknown_sil_abi_schema_version() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact { templates: Vec::new(), states: Vec::new(), actors: Vec::new() },
            sil_abi: SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION + 1, states: Vec::new(), actors: Vec::new() },
        };

        let err = artifact.check_schema_version().expect_err("future Sil ABI schema must be rejected");
        assert_eq!(err.artifact, "Sil ABI artifact");
        assert_eq!(err.found, SIL_ABI_SCHEMA_VERSION + 1);
    }
}
