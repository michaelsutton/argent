use serde::{Deserialize, Serialize};

use super::{ArtifactVersionError, HiddenParamArtifact, ParamArtifact, StateArtifact, TypeArtifact};

pub const SIL_ABI_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilAbiArtifact {
    pub schema_version: u32,
    pub states: Vec<StateArtifact>,
    pub actors: Vec<SilActorArtifact>,
}

impl SilAbiArtifact {
    pub fn check_schema_version(&self) -> std::result::Result<(), ArtifactVersionError> {
        if self.schema_version == SIL_ABI_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ArtifactVersionError { artifact: "Sil ABI artifact", supported: SIL_ABI_SCHEMA_VERSION, found: self.schema_version })
        }
    }

    pub fn actor(&self, name: &str) -> Option<&SilActorArtifact> {
        self.actors.iter().find(|actor| actor.name == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilActorArtifact {
    pub name: String,
    pub source_path: String,
    pub runtime_state: RuntimeStateArtifact,
    pub entries: Vec<SilEntryArtifact>,
    pub compiled: CompiledActorArtifact,
}

impl SilActorArtifact {
    pub fn entry(&self, name: &str) -> Option<&SilEntryArtifact> {
        self.entries.iter().find(|entry| entry.name == name)
    }
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
pub struct SilEntryArtifact {
    pub name: String,
    #[serde(default)]
    pub selector: Option<i64>,
    pub user_params: Vec<ParamArtifact>,
    pub hidden_params: Vec<HiddenParamArtifact>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_sil_abi_artifact_without_argent_coordination_metadata() {
        let json = r#"
        {
          "schema_version": 1,
          "states": [
            {
              "name": "FooState",
              "fields": [{ "name": "count", "type": { "kind": "int" } }]
            }
          ],
          "actors": [
            {
              "name": "Foo",
              "source_path": "sil/Foo.sil",
              "runtime_state": {
                "source": "FooState",
                "fields": [{ "name": "count", "type": { "kind": "int" }, "role": { "kind": "source" } }]
              },
              "entries": [
                {
                  "name": "step",
                  "selector": 0,
                  "user_params": [{ "name": "amount", "type": { "kind": "int" } }],
                  "hidden_params": []
                }
              ],
              "compiled": {
                "script_hex": "00",
                "template": { "prefix_hex": "", "suffix_hex": "", "hash_hex": "00" },
                "state_span": { "offset": 0, "len": 1 }
              }
            }
          ]
        }
        "#;

        let abi: SilAbiArtifact = serde_json::from_str(json).expect("sil abi should deserialize");
        abi.check_schema_version().expect("sil abi schema version should be supported");
        assert_eq!(abi.actor("Foo").and_then(|actor| actor.entry("step")).and_then(|entry| entry.selector), Some(0));
    }
}
