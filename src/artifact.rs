use std::fmt;

use serde::{Deserialize, Serialize};

pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub schema_version: u32,
    pub generator: GeneratorArtifact,
    pub app: String,
    pub root: String,
    pub modules: Vec<String>,
    pub templates: Vec<TemplateRefArtifact>,
    pub states: Vec<StateArtifact>,
    pub actors: Vec<ActorArtifact>,
}

impl Artifact {
    pub fn check_schema_version(&self) -> std::result::Result<(), ArtifactVersionError> {
        if self.schema_version == ARTIFACT_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ArtifactVersionError { supported: ARTIFACT_SCHEMA_VERSION, found: self.schema_version })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactVersionError {
    pub supported: u32,
    pub found: u32,
}

impl fmt::Display for ArtifactVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported Argent artifact schema version {}; expected {}", self.found, self.supported)
    }
}

impl std::error::Error for ArtifactVersionError {}

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
    pub sil: String,
    pub runtime_state: RuntimeStateArtifact,
    pub entries: Vec<EntryArtifact>,
    pub compiled: Option<CompiledActorArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateArtifact {
    pub source: String,
    pub fields: Vec<RuntimeFieldArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFieldArtifact {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
    pub role: RuntimeFieldRoleArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeFieldRoleArtifact {
    Template { actor: String },
    Source,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryArtifact {
    pub name: String,
    pub kind: EntryKindArtifact,
    #[serde(default)]
    pub selector: Option<i64>,
    pub user_params: Vec<ParamArtifact>,
    pub hidden_params: Vec<HiddenParamArtifact>,
    pub consumes: Vec<ConsumeArtifact>,
    pub emits: EmitArtifact,
    pub routes: Vec<RouteArtifact>,
    pub terminal_paths: Vec<TerminalPathArtifact>,
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
    pub purpose: HiddenParamPurposeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenParamPurposeArtifact {
    TemplatePrefix { actor: String },
    TemplateSuffix { actor: String },
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
pub struct CompiledActorArtifact {
    pub script_hex: String,
    pub template: CompiledTemplateArtifact,
    pub state_span: StateSpanArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledTemplateArtifact {
    pub prefix_hex: String,
    pub suffix_hex: String,
    pub hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSpanArtifact {
    pub offset: usize,
    pub len: usize,
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
              "sil": "sil/Foo.sil",
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
              "compiled": null
            }
          ]
        }
        "#;

        let artifact: Artifact = serde_json::from_str(json).expect("artifact should deserialize");
        artifact.check_schema_version().expect("schema version should be supported");
        assert_eq!(artifact.actors[0].compiled, None);
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION + 1,
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            templates: Vec::new(),
            states: Vec::new(),
            actors: Vec::new(),
        };

        let err = artifact.check_schema_version().expect_err("future schema must be rejected");
        assert_eq!(err.found, ARTIFACT_SCHEMA_VERSION + 1);
    }
}
