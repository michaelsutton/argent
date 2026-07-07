use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use silverscript_abi::{
    ArtifactVersionError, CompiledContractArtifact, CompiledTemplateArtifact, FieldArtifact, ParamArtifact, RuntimeFieldArtifact,
    RuntimeFieldRoleArtifact, RuntimeStateArtifact, SIL_ABI_SCHEMA_VERSION, SilAbiArtifact, SilContractArtifact, SilEntryArtifact,
    StateArtifact, StateSpanArtifact, TypeArtifact,
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
    #[serde(default)]
    pub template_plan: TemplatePlanArtifact,
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

    pub fn verify_template_plan(&self) -> std::result::Result<(), TemplatePlanError> {
        self.argent.template_plan.verify(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorArtifact {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateRefArtifact {
    pub id: String,
    pub actor: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePlanArtifact {
    pub templates: Vec<TemplatePlanTemplateArtifact>,
    pub witness_recipes: Vec<TemplateWitnessRecipeArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePlanTemplateArtifact {
    pub id: String,
    pub actor: String,
    pub contract: String,
    pub symbol: String,
    pub hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateWitnessRecipeArtifact {
    pub id: String,
    pub template_id: String,
    pub actor: String,
    pub param: String,
    pub purpose: HiddenParamPurposeArtifact,
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
    #[serde(default)]
    pub hidden_params: Vec<HiddenParamArtifact>,
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
    pub recipe_id: String,
    pub param: String,
    pub actor: String,
    pub purpose: HiddenParamPurposeArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenParamArtifact {
    pub recipe_id: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKindArtifact {
    Leader,
    Delegate,
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
    pub witness_recipe_ids: Vec<String>,
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
    pub witness_recipe_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedRouteArtifact {
    pub output: Option<String>,
    pub auth_index: usize,
    pub actor: String,
    pub template_id: String,
    pub state_expr: String,
    pub witness_recipe_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteArtifact {
    pub output: Option<String>,
    pub actor: String,
    pub template_id: String,
    pub state_expr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalPathArtifact {
    pub routes: Vec<RouteArtifact>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TemplatePlanError {
    #[error("duplicate template receipt id `{0}`")]
    DuplicateTemplateId(String),
    #[error("duplicate witness recipe id `{0}`")]
    DuplicateWitnessRecipeId(String),
    #[error("template ref `{actor}` points at missing receipt `{id}`")]
    MissingTemplateReceipt { actor: String, id: String },
    #[error("unknown Sil contract `{0}` in template plan")]
    UnknownContract(String),
    #[error("template receipt `{id}` actor `{actor}` does not match contract `{contract}`")]
    TemplateContractMismatch { id: String, actor: String, contract: String },
    #[error("template receipt `{id}` does not match template ref for actor `{actor}`")]
    TemplateRefMismatch { id: String, actor: String },
    #[error("template receipt `{id}` is not referenced by an Argent template ref")]
    UnreferencedTemplateReceipt { id: String },
    #[error("template receipt `{id}` hash mismatch: expected `{expected}`, found `{found}`")]
    TemplateHashMismatch { id: String, expected: String, found: String },
    #[error("invalid hex in template receipt `{id}`: {message}")]
    InvalidHex { id: String, message: String },
    #[error("witness recipe `{id}` references missing template receipt `{template_id}`")]
    MissingWitnessTemplate { id: String, template_id: String },
    #[error("witness recipe `{id}` actor `{actor}` does not match template receipt actor `{template_actor}`")]
    WitnessTemplateMismatch { id: String, actor: String, template_actor: String },
    #[error("hidden param `{entry}::{param}` points at missing witness recipe `{recipe_id}`")]
    MissingHiddenParamRecipe { entry: String, param: String, recipe_id: String },
    #[error("hidden param `{entry}::{param}` does not match witness recipe `{recipe_id}`")]
    HiddenParamRecipeMismatch { entry: String, param: String, recipe_id: String },
    #[error("entry witness `{entry}::{param}` points at missing witness recipe `{recipe_id}`")]
    MissingEntryWitnessRecipe { entry: String, param: String, recipe_id: String },
    #[error("entry witness `{entry}::{param}` does not match witness recipe `{recipe_id}`")]
    EntryWitnessRecipeMismatch { entry: String, param: String, recipe_id: String },
    #[error("route `{entry}` to actor `{actor}` points at missing template receipt `{template_id}`")]
    MissingRouteTemplate { entry: String, actor: String, template_id: String },
    #[error("route `{entry}` to actor `{actor}` points at template receipt `{template_id}` for actor `{template_actor}`")]
    RouteTemplateMismatch { entry: String, actor: String, template_id: String, template_actor: String },
    #[error("route plan for `{entry}` points at witness recipe `{recipe_id}` that is not exposed by the entry")]
    RoutePlanRecipeNotExposed { entry: String, recipe_id: String },
    #[error("route plan for `{entry}` points at missing witness recipe `{recipe_id}`")]
    MissingRoutePlanRecipe { entry: String, recipe_id: String },
}

impl TemplatePlanArtifact {
    pub fn verify(&self, artifact: &Artifact) -> std::result::Result<(), TemplatePlanError> {
        use std::collections::{BTreeMap, BTreeSet};

        let mut template_ids = BTreeSet::new();
        let mut templates_by_id = BTreeMap::new();
        for template in &self.templates {
            if !template_ids.insert(template.id.as_str()) {
                return Err(TemplatePlanError::DuplicateTemplateId(template.id.clone()));
            }
            let contract = artifact
                .sil_abi
                .contract(&template.contract)
                .ok_or_else(|| TemplatePlanError::UnknownContract(template.contract.clone()))?;
            if template.actor != contract.name || template.contract != contract.name {
                return Err(TemplatePlanError::TemplateContractMismatch {
                    id: template.id.clone(),
                    actor: template.actor.clone(),
                    contract: template.contract.clone(),
                });
            }
            let expected_hash =
                template_hash_hex(&template.id, &contract.compiled.template.prefix_hex, &contract.compiled.template.suffix_hex)?;
            if contract.compiled.template.hash_hex != expected_hash {
                return Err(TemplatePlanError::TemplateHashMismatch {
                    id: template.id.clone(),
                    expected: expected_hash,
                    found: contract.compiled.template.hash_hex.clone(),
                });
            }
            if template.hash_hex != expected_hash {
                return Err(TemplatePlanError::TemplateHashMismatch {
                    id: template.id.clone(),
                    expected: expected_hash,
                    found: template.hash_hex.clone(),
                });
            }
            templates_by_id.insert(template.id.as_str(), template);
        }

        let mut referenced_template_ids = BTreeSet::new();
        for template_ref in &artifact.argent.templates {
            let Some(template) = templates_by_id.get(template_ref.id.as_str()) else {
                return Err(TemplatePlanError::MissingTemplateReceipt {
                    actor: template_ref.actor.clone(),
                    id: template_ref.id.clone(),
                });
            };
            referenced_template_ids.insert(template_ref.id.as_str());
            if template.actor != template_ref.actor || template.symbol != template_ref.symbol {
                return Err(TemplatePlanError::TemplateRefMismatch { id: template.id.clone(), actor: template_ref.actor.clone() });
            }
        }
        for template in &self.templates {
            if !referenced_template_ids.contains(template.id.as_str()) {
                return Err(TemplatePlanError::UnreferencedTemplateReceipt { id: template.id.clone() });
            }
        }

        let mut recipe_ids = BTreeSet::new();
        let mut recipes_by_id = BTreeMap::new();
        for recipe in &self.witness_recipes {
            if !recipe_ids.insert(recipe.id.as_str()) {
                return Err(TemplatePlanError::DuplicateWitnessRecipeId(recipe.id.clone()));
            }
            let Some(template) = templates_by_id.get(recipe.template_id.as_str()) else {
                return Err(TemplatePlanError::MissingWitnessTemplate {
                    id: recipe.id.clone(),
                    template_id: recipe.template_id.clone(),
                });
            };
            if recipe.actor != template.actor {
                return Err(TemplatePlanError::WitnessTemplateMismatch {
                    id: recipe.id.clone(),
                    actor: recipe.actor.clone(),
                    template_actor: template.actor.clone(),
                });
            }
            recipes_by_id.insert(recipe.id.as_str(), recipe);
        }

        for actor in &artifact.argent.actors {
            for entry in &actor.entries {
                let entry_id = format!("{}::{}", actor.name, entry.name);
                let entry_recipe_ids = entry.hidden_params.iter().map(|param| param.recipe_id.as_str()).collect::<BTreeSet<_>>();

                for param in &entry.hidden_params {
                    let Some(recipe) = recipes_by_id.get(param.recipe_id.as_str()) else {
                        return Err(TemplatePlanError::MissingHiddenParamRecipe {
                            entry: entry_id.clone(),
                            param: param.name.clone(),
                            recipe_id: param.recipe_id.clone(),
                        });
                    };
                    if recipe.param != param.name || recipe.actor != param.actor || recipe.purpose != param.purpose {
                        return Err(TemplatePlanError::HiddenParamRecipeMismatch {
                            entry: entry_id.clone(),
                            param: param.name.clone(),
                            recipe_id: param.recipe_id.clone(),
                        });
                    }
                }

                for witness in &entry.witnesses {
                    let Some(recipe) = recipes_by_id.get(witness.recipe_id.as_str()) else {
                        return Err(TemplatePlanError::MissingEntryWitnessRecipe {
                            entry: entry_id.clone(),
                            param: witness.param.clone(),
                            recipe_id: witness.recipe_id.clone(),
                        });
                    };
                    if recipe.param != witness.param || recipe.actor != witness.actor || recipe.purpose != witness.purpose {
                        return Err(TemplatePlanError::EntryWitnessRecipeMismatch {
                            entry: entry_id.clone(),
                            param: witness.param.clone(),
                            recipe_id: witness.recipe_id.clone(),
                        });
                    }
                }

                self.verify_route_recipe_ids(&entry_id, &entry.route_plan.witness_recipe_ids, &entry_recipe_ids, &recipes_by_id)?;
                for path in &entry.route_plan.terminal_paths {
                    self.verify_route_recipe_ids(&entry_id, &path.witness_recipe_ids, &entry_recipe_ids, &recipes_by_id)?;
                    for route in &path.routes {
                        self.verify_route_template(&entry_id, route.actor.as_str(), route.template_id.as_str(), &templates_by_id)?;
                        self.verify_route_recipe_ids(&entry_id, &route.witness_recipe_ids, &entry_recipe_ids, &recipes_by_id)?;
                    }
                }
                for route in &entry.routes {
                    self.verify_route_template(&entry_id, route.actor.as_str(), route.template_id.as_str(), &templates_by_id)?;
                }
                for path in &entry.terminal_paths {
                    for route in &path.routes {
                        self.verify_route_template(&entry_id, route.actor.as_str(), route.template_id.as_str(), &templates_by_id)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn verify_route_template(
        &self,
        entry: &str,
        actor: &str,
        template_id: &str,
        templates_by_id: &std::collections::BTreeMap<&str, &TemplatePlanTemplateArtifact>,
    ) -> std::result::Result<(), TemplatePlanError> {
        let Some(template) = templates_by_id.get(template_id) else {
            return Err(TemplatePlanError::MissingRouteTemplate {
                entry: entry.to_string(),
                actor: actor.to_string(),
                template_id: template_id.to_string(),
            });
        };
        if template.actor != actor {
            return Err(TemplatePlanError::RouteTemplateMismatch {
                entry: entry.to_string(),
                actor: actor.to_string(),
                template_id: template_id.to_string(),
                template_actor: template.actor.clone(),
            });
        }
        Ok(())
    }

    fn verify_route_recipe_ids(
        &self,
        entry: &str,
        recipe_ids: &[String],
        entry_recipe_ids: &std::collections::BTreeSet<&str>,
        recipes_by_id: &std::collections::BTreeMap<&str, &TemplateWitnessRecipeArtifact>,
    ) -> std::result::Result<(), TemplatePlanError> {
        for recipe_id in recipe_ids {
            if !recipes_by_id.contains_key(recipe_id.as_str()) {
                return Err(TemplatePlanError::MissingRoutePlanRecipe { entry: entry.to_string(), recipe_id: recipe_id.clone() });
            }
            if !entry_recipe_ids.contains(recipe_id.as_str()) {
                return Err(TemplatePlanError::RoutePlanRecipeNotExposed { entry: entry.to_string(), recipe_id: recipe_id.clone() });
            }
        }
        Ok(())
    }
}

fn template_hash_hex(id: &str, prefix_hex: &str, suffix_hex: &str) -> std::result::Result<String, TemplatePlanError> {
    let prefix = decode_hex_for_template(id, prefix_hex)?;
    let suffix = decode_hex_for_template(id, suffix_hex)?;
    let hash = blake2b_simd::Params::new().hash_length(32).to_state().update(&prefix).update(&suffix).finalize();
    Ok(encode_hex(hash.as_bytes()))
}

fn decode_hex_for_template(id: &str, hex: &str) -> std::result::Result<Vec<u8>, TemplatePlanError> {
    let mut out = vec![0; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut out)
        .map_err(|err| TemplatePlanError::InvalidHex { id: id.to_string(), message: err.to_string() })?;
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = vec![0; bytes.len() * 2];
    faster_hex::hex_encode(bytes, &mut out).expect("hex output buffer has exact length");
    String::from_utf8(out).expect("faster-hex emits ASCII")
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
            "templates": [{ "id": "template/foo", "actor": "Foo", "symbol": "gen__template_foo" }],
            "template_plan": {
              "templates": [],
              "witness_recipes": []
            },
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
            "contracts": [
              {
                "name": "Foo",
                "source_path": "sil/Foo.sil",
                "runtime_state": {
                  "source": "FooState",
                  "fields": [
                    {
                      "name": "gen__template_foo",
                      "type": { "kind": "fixed_bytes", "len": 32 },
                      "role": { "kind": "template", "contract": "Foo" }
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
        assert_eq!(artifact.sil_abi.contracts[0].compiled.script_hex, "");
    }

    #[test]
    fn rejects_unknown_argent_schema_version() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION + 1,
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                states: Vec::new(),
                actors: Vec::new(),
            },
            sil_abi: SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION, states: Vec::new(), contracts: Vec::new() },
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
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                states: Vec::new(),
                actors: Vec::new(),
            },
            sil_abi: SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION + 1, states: Vec::new(), contracts: Vec::new() },
        };

        let err = artifact.check_schema_version().expect_err("future Sil ABI schema must be rejected");
        assert_eq!(err.artifact, "Sil ABI artifact");
        assert_eq!(err.found, SIL_ABI_SCHEMA_VERSION + 1);
    }
}
