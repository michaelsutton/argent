//! Argent coordination artifact layered around a portable Silverscript ABI.
//!
//! `silverscript-abi` describes how to call and serialize generated contracts.
//! This crate describes why Argent generated particular fields and witnesses:
//! actor/template identities, route plans, template receipts, runtime hidden
//! field roles, observed covenant subjects, and builder witness recipes.
//!
//! Boundary rule: do not push Argent meanings such as template tables, route
//! families, or hidden-field roles into `silverscript-abi`. Store them here as
//! metadata that points at Sil ABI contract and field names.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use silverscript_abi::{
    ArtifactVersionError, CompiledContractArtifact, CompiledTemplateArtifact, FieldArtifact, ParamArtifact, RuntimeFieldArtifact,
    RuntimeStateArtifact, SIL_ABI_SCHEMA_VERSION, SilAbiArtifact, SilContractArtifact, SilEntryArtifact, StateArtifact,
    StateSpanArtifact, TypeArtifact,
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
    #[serde(default)]
    pub runtime_states: Vec<RuntimeStatePlanArtifact>,
    #[serde(default)]
    pub route_tables: Vec<RouteTemplateTableArtifact>,
    #[serde(default)]
    pub route_trees: Vec<RouteTemplateTreeArtifact>,
    #[serde(default)]
    pub route_families: Vec<RouteTemplateFamilyArtifact>,
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
pub struct RuntimeStatePlanArtifact {
    pub contract: String,
    pub source: String,
    pub field_roles: Vec<RuntimeFieldRolePlanArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFieldRolePlanArtifact {
    pub name: String,
    pub role: RuntimeFieldRoleArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeFieldRoleArtifact {
    Template { contract: String },
    TemplateTable { contracts: Vec<String> },
    TemplateDigest { id: String },
    TemplateRoot { leaves: Vec<RuntimeRouteLeafArtifact> },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeRouteLeafArtifact {
    Contract { contract: String },
    Digest { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateTableArtifact {
    pub id: String,
    pub state: String,
    pub field: String,
    pub byte_len: usize,
    pub entries: Vec<RouteTemplateTableEntryArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateTableEntryArtifact {
    pub index: usize,
    pub offset: usize,
    #[serde(flatten)]
    pub leaf: RouteTemplateLeafArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateTreeArtifact {
    pub id: String,
    pub table_id: String,
    pub state: String,
    pub field: String,
    pub root_hex: String,
    pub leaves: Vec<RouteTemplateTreeLeafArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateTreeLeafArtifact {
    pub index: usize,
    #[serde(flatten)]
    pub leaf: RouteTemplateLeafArtifact,
    pub hash_hex: String,
    pub opening: Vec<RouteTemplateTreeOpeningStepArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteTemplateLeafArtifact {
    Template { actor: String, template_id: String },
    RouteFamily { family_id: String, tree_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateFamilyArtifact {
    pub id: String,
    pub state: String,
    pub anchor_actor: String,
    pub entry_actors: Vec<String>,
    pub table_id: String,
    pub actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateTreeOpeningStepArtifact {
    pub side: RouteTemplateTreeOpeningSideArtifact,
    pub hash_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTemplateTreeOpeningSideArtifact {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateWitnessRecipeArtifact {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    pub subject: HiddenParamSubjectArtifact,
    pub param: String,
    pub purpose: HiddenParamPurposeArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tree_id: Option<String>,
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
    pub subject: HiddenParamSubjectArtifact,
    pub purpose: HiddenParamPurposeArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tree_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenParamArtifact {
    pub recipe_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
    pub subject: HiddenParamSubjectArtifact,
    pub purpose: HiddenParamPurposeArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_tree_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenParamSubjectArtifact {
    Actor { actor: String },
    RouteFamily { family_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenParamPurposeArtifact {
    TemplatePrefixBytes,
    TemplateSuffixBytes,
    TemplatePrefixLen,
    TemplateSuffixLen,
    RouteTemplateLeaf,
    RouteTemplateOpening,
    RouteFamilyTable,
    RouteFamilyOpening,
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
    #[error("duplicate route template table id `{0}`")]
    DuplicateRouteTableId(String),
    #[error("duplicate route template tree id `{0}`")]
    DuplicateRouteTreeId(String),
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
    #[error("route template table `{id}` has byte_len `{byte_len}`, expected `{expected}`")]
    RouteTableLenMismatch { id: String, byte_len: usize, expected: usize },
    #[error("route template table `{id}` entry for actor `{actor}` points at missing template receipt `{template_id}`")]
    MissingRouteTableTemplate { id: String, actor: String, template_id: String },
    #[error(
        "route template table `{id}` entry for actor `{actor}` points at template receipt `{template_id}` for actor `{template_actor}`"
    )]
    RouteTableTemplateMismatch { id: String, actor: String, template_id: String, template_actor: String },
    #[error("route template table `{id}` entry points at missing route family `{family_id}`")]
    MissingRouteTableFamily { id: String, family_id: String },
    #[error("route template table `{id}` entry for route family `{family_id}` points at tree `{tree_id}`, expected `{expected}`")]
    RouteTableFamilyTreeMismatch { id: String, family_id: String, tree_id: String, expected: String },
    #[error("route template table `{id}` entry {index} has offset `{offset}`, expected `{expected}`")]
    RouteTableOffsetMismatch { id: String, index: usize, offset: usize, expected: usize },
    #[error("runtime state `{contract}` field `{field}` points at missing route template table `{id}`")]
    MissingRuntimeRouteTable { contract: String, field: String, id: String },
    #[error("runtime state `{contract}` field `{field}` route table `{id}` has contracts that do not match the field role")]
    RuntimeRouteTableMismatch { contract: String, field: String, id: String },
    #[error("duplicate runtime state plan for contract `{0}`")]
    DuplicateRuntimeStatePlan(String),
    #[error("runtime state plan for contract `{contract}` is invalid: {message}")]
    RuntimeStatePlanMismatch { contract: String, message: String },
    #[error("route template table `{id}` is not referenced by any runtime state field")]
    UnreferencedRouteTable { id: String },
    #[error("route template tree `{id}` points at missing route template table `{table_id}`")]
    MissingRouteTreeTable { id: String, table_id: String },
    #[error("route template table `{table_id}` has no route template tree receipt")]
    MissingRouteTree { table_id: String },
    #[error("route template tree `{id}` does not match route template table `{table_id}`")]
    RouteTreeTableMismatch { id: String, table_id: String },
    #[error("route template tree `{id}` leaf {index} hash mismatch: expected `{expected}`, found `{found}`")]
    RouteTreeLeafHashMismatch { id: String, index: usize, expected: String, found: String },
    #[error("route template tree `{id}` root mismatch: expected `{expected}`, found `{found}`")]
    RouteTreeRootMismatch { id: String, expected: String, found: String },
    #[error("route template tree `{id}` leaf {index} opening resolves to `{found}`, expected root `{expected}`")]
    RouteTreeOpeningMismatch { id: String, index: usize, expected: String, found: String },
    #[error("route template tree `{id}` contains a recursive route family leaf `{family_id}`")]
    RecursiveRouteFamilyLeaf { id: String, family_id: String },
    #[error("duplicate route template family receipt `{0}`")]
    DuplicateRouteFamilyId(String),
    #[error("route template family `{id}` must contain at least two actors")]
    RouteFamilyTooSmall { id: String },
    #[error("route template family `{id}` repeats actor `{actor}`")]
    DuplicateRouteFamilyActor { id: String, actor: String },
    #[error("route template family `{id}` references unknown actor `{actor}`")]
    MissingRouteFamilyActor { id: String, actor: String },
    #[error("route template family `{id}` anchor actor `{anchor}` should be `{expected}`")]
    RouteFamilyAnchorMismatch { id: String, anchor: String, expected: String },
    #[error("route template family `{id}` repeats entry actor `{actor}`")]
    DuplicateRouteFamilyEntryActor { id: String, actor: String },
    #[error("route template family `{id}` entry actor `{actor}` is not in the family")]
    MissingRouteFamilyEntryActor { id: String, actor: String },
    #[error("route template family `{id}` actor `{actor}` owns state `{found}`, expected `{expected}`")]
    RouteFamilyStateMismatch { id: String, actor: String, expected: String, found: String },
    #[error("route template family `{id}` points at missing tree `{tree_id}`")]
    MissingRouteFamilyTree { id: String, tree_id: String },
    #[error("route template family `{id}` points at tree `{tree_id}`, expected `{expected}`")]
    RouteFamilyTreeMismatch { id: String, tree_id: String, expected: String },
    #[error("witness recipe `{id}` references missing template receipt `{template_id}`")]
    MissingWitnessTemplate { id: String, template_id: String },
    #[error("witness recipe `{id}` references missing route family `{family_id}`")]
    MissingWitnessRouteFamily { id: String, family_id: String },
    #[error("witness recipe `{id}` references missing route tree receipt `{route_tree_id}`")]
    MissingWitnessRouteTree { id: String, route_tree_id: String },
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

        let actor_states =
            artifact.argent.actors.iter().map(|actor| (actor.name.as_str(), actor.state.as_str())).collect::<BTreeMap<_, _>>();
        let mut route_family_ids = BTreeSet::new();
        let mut route_families_by_id = BTreeMap::new();
        for family in &self.route_families {
            if !route_family_ids.insert(family.id.as_str()) {
                return Err(TemplatePlanError::DuplicateRouteFamilyId(family.id.clone()));
            }
            if family.actors.len() < 2 {
                return Err(TemplatePlanError::RouteFamilyTooSmall { id: family.id.clone() });
            }
            let mut family_actors = BTreeSet::new();
            for actor in &family.actors {
                if !family_actors.insert(actor.as_str()) {
                    return Err(TemplatePlanError::DuplicateRouteFamilyActor { id: family.id.clone(), actor: actor.clone() });
                }
            }
            let mut entry_actors = BTreeSet::new();
            for actor in &family.entry_actors {
                if !entry_actors.insert(actor.as_str()) {
                    return Err(TemplatePlanError::DuplicateRouteFamilyEntryActor { id: family.id.clone(), actor: actor.clone() });
                }
                if !family_actors.contains(actor.as_str()) {
                    return Err(TemplatePlanError::MissingRouteFamilyEntryActor { id: family.id.clone(), actor: actor.clone() });
                }
            }
            let expected_anchor =
                family.entry_actors.first().or_else(|| family.actors.first()).expect("family has at least two actors");
            if family.anchor_actor != *expected_anchor {
                return Err(TemplatePlanError::RouteFamilyAnchorMismatch {
                    id: family.id.clone(),
                    anchor: family.anchor_actor.clone(),
                    expected: expected_anchor.clone(),
                });
            }
            for actor in &family.actors {
                let Some(found_state) = actor_states.get(actor.as_str()) else {
                    return Err(TemplatePlanError::MissingRouteFamilyActor { id: family.id.clone(), actor: actor.clone() });
                };
                if *found_state != family.state {
                    return Err(TemplatePlanError::RouteFamilyStateMismatch {
                        id: family.id.clone(),
                        actor: actor.clone(),
                        expected: family.state.clone(),
                        found: (*found_state).to_string(),
                    });
                }
            }
            route_families_by_id.insert(family.id.as_str(), family);
        }

        let sil_contracts_by_name =
            artifact.sil_abi.contracts.iter().map(|contract| (contract.name.as_str(), contract)).collect::<BTreeMap<_, _>>();
        let mut runtime_states_by_contract = BTreeMap::new();
        for runtime_state in &self.runtime_states {
            if runtime_states_by_contract.insert(runtime_state.contract.as_str(), runtime_state).is_some() {
                return Err(TemplatePlanError::DuplicateRuntimeStatePlan(runtime_state.contract.clone()));
            }
            let Some(contract) = sil_contracts_by_name.get(runtime_state.contract.as_str()) else {
                return Err(TemplatePlanError::UnknownContract(runtime_state.contract.clone()));
            };
            if runtime_state.source != contract.runtime_state.source {
                return Err(TemplatePlanError::RuntimeStatePlanMismatch {
                    contract: runtime_state.contract.clone(),
                    message: format!(
                        "source `{}` does not match Sil ABI source `{}`",
                        runtime_state.source, contract.runtime_state.source
                    ),
                });
            }
            let sil_fields_by_name =
                contract.runtime_state.fields.iter().map(|field| (field.name.as_str(), field)).collect::<BTreeMap<_, _>>();
            let mut field_role_names = BTreeSet::new();
            for plan_field in &runtime_state.field_roles {
                if !field_role_names.insert(plan_field.name.as_str()) {
                    return Err(TemplatePlanError::RuntimeStatePlanMismatch {
                        contract: runtime_state.contract.clone(),
                        message: format!("field role `{}` is duplicated", plan_field.name),
                    });
                }
                if !sil_fields_by_name.contains_key(plan_field.name.as_str()) {
                    return Err(TemplatePlanError::RuntimeStatePlanMismatch {
                        contract: runtime_state.contract.clone(),
                        message: format!("field role `{}` does not match any Sil ABI runtime field", plan_field.name),
                    });
                }
            }
        }

        let mut route_table_ids = BTreeSet::new();
        let mut route_tables_by_id = BTreeMap::new();
        for table in &self.route_tables {
            if !route_table_ids.insert(table.id.as_str()) {
                return Err(TemplatePlanError::DuplicateRouteTableId(table.id.clone()));
            }
            let expected_byte_len = table.entries.len() * 32;
            if table.byte_len != expected_byte_len {
                return Err(TemplatePlanError::RouteTableLenMismatch {
                    id: table.id.clone(),
                    byte_len: table.byte_len,
                    expected: expected_byte_len,
                });
            }
            for (expected_index, entry) in table.entries.iter().enumerate() {
                let expected_offset = expected_index * 32;
                if entry.index != expected_index || entry.offset != expected_offset {
                    return Err(TemplatePlanError::RouteTableOffsetMismatch {
                        id: table.id.clone(),
                        index: entry.index,
                        offset: entry.offset,
                        expected: expected_offset,
                    });
                }
                match &entry.leaf {
                    RouteTemplateLeafArtifact::Template { actor, template_id } => {
                        let Some(template) = templates_by_id.get(template_id.as_str()) else {
                            return Err(TemplatePlanError::MissingRouteTableTemplate {
                                id: table.id.clone(),
                                actor: actor.clone(),
                                template_id: template_id.clone(),
                            });
                        };
                        if template.actor != *actor {
                            return Err(TemplatePlanError::RouteTableTemplateMismatch {
                                id: table.id.clone(),
                                actor: actor.clone(),
                                template_id: template_id.clone(),
                                template_actor: template.actor.clone(),
                            });
                        }
                    }
                    RouteTemplateLeafArtifact::RouteFamily { family_id, tree_id } => {
                        let Some(family) = route_families_by_id.get(family_id.as_str()) else {
                            return Err(TemplatePlanError::MissingRouteTableFamily {
                                id: table.id.clone(),
                                family_id: family_id.clone(),
                            });
                        };
                        if tree_id != &family.table_id {
                            return Err(TemplatePlanError::RouteTableFamilyTreeMismatch {
                                id: table.id.clone(),
                                family_id: family_id.clone(),
                                tree_id: tree_id.clone(),
                                expected: family.table_id.clone(),
                            });
                        }
                    }
                }
            }
            route_tables_by_id.insert(table.id.as_str(), table);
        }

        let mut referenced_route_table_ids = BTreeSet::new();
        for runtime_state in &self.runtime_states {
            let contract = sil_contracts_by_name
                .get(runtime_state.contract.as_str())
                .expect("runtime state contract existence was checked when indexing runtime plans");
            let sil_fields_by_name =
                contract.runtime_state.fields.iter().map(|field| (field.name.as_str(), field)).collect::<BTreeMap<_, _>>();
            for field in &runtime_state.field_roles {
                let sil_field = sil_fields_by_name
                    .get(field.name.as_str())
                    .expect("runtime state field role existence was checked when indexing runtime plans");
                let (role_leaves, expected_field_ty) = match &field.role {
                    RuntimeFieldRoleArtifact::TemplateTable { contracts } => {
                        let leaves = contracts
                            .iter()
                            .map(|contract| RuntimeRouteLeafArtifact::Contract { contract: contract.clone() })
                            .collect();
                        (leaves, TypeArtifact::FixedBytes { len: contracts.len() * 32 })
                    }
                    RuntimeFieldRoleArtifact::TemplateDigest { id } => {
                        if !route_families_by_id.contains_key(id.as_str()) {
                            return Err(TemplatePlanError::MissingWitnessRouteFamily {
                                id: field.name.clone(),
                                family_id: id.clone(),
                            });
                        }
                        if sil_field.ty != (TypeArtifact::FixedBytes { len: 32 }) {
                            return Err(TemplatePlanError::RuntimeRouteTableMismatch {
                                contract: runtime_state.contract.clone(),
                                field: field.name.clone(),
                                id: id.clone(),
                            });
                        }
                        continue;
                    }
                    RuntimeFieldRoleArtifact::TemplateRoot { leaves } => (leaves.clone(), TypeArtifact::FixedBytes { len: 32 }),
                    RuntimeFieldRoleArtifact::Template { .. } => continue,
                };
                let id = route_template_table_receipt_id(&runtime_state.source, &field.name);
                let Some(table) = route_tables_by_id.get(id.as_str()) else {
                    return Err(TemplatePlanError::MissingRuntimeRouteTable {
                        contract: runtime_state.contract.clone(),
                        field: field.name.clone(),
                        id,
                    });
                };
                referenced_route_table_ids.insert(table.id.as_str());
                let table_leaves = table.entries.iter().map(|entry| runtime_leaf_for_route_leaf(&entry.leaf)).collect::<Vec<_>>();
                if table.state != runtime_state.source
                    || table.field != field.name
                    || table_leaves != role_leaves
                    || table.byte_len != role_leaves.len() * 32
                    || sil_field.ty != expected_field_ty
                {
                    return Err(TemplatePlanError::RuntimeRouteTableMismatch {
                        contract: runtime_state.contract.clone(),
                        field: field.name.clone(),
                        id: table.id.clone(),
                    });
                }
            }
        }
        for table in &self.route_tables {
            if !referenced_route_table_ids.contains(table.id.as_str()) {
                return Err(TemplatePlanError::UnreferencedRouteTable { id: table.id.clone() });
            }
        }

        let mut route_tree_ids = BTreeSet::new();
        let mut route_trees_by_id = BTreeMap::new();
        for tree in &self.route_trees {
            if !route_tree_ids.insert(tree.id.as_str()) {
                return Err(TemplatePlanError::DuplicateRouteTreeId(tree.id.clone()));
            }
            if !route_tables_by_id.contains_key(tree.table_id.as_str()) {
                return Err(TemplatePlanError::MissingRouteTreeTable { id: tree.id.clone(), table_id: tree.table_id.clone() });
            }
            route_trees_by_id.insert(tree.id.as_str(), tree);
        }
        for tree in &self.route_trees {
            let table = route_tables_by_id
                .get(tree.table_id.as_str())
                .expect("route tree table existence was checked when indexing route trees");
            verify_route_template_tree(tree, table, &templates_by_id, &route_trees_by_id)?;
        }
        for table in &self.route_tables {
            let expected_tree_id = route_template_tree_receipt_id(&table.state, &table.field);
            if !route_tree_ids.contains(expected_tree_id.as_str()) {
                return Err(TemplatePlanError::MissingRouteTree { table_id: table.id.clone() });
            }
        }
        for family in &self.route_families {
            let Some(table) = route_tables_by_id.get(family.table_id.as_str()) else {
                return Err(TemplatePlanError::MissingRouteFamilyTree { id: family.id.clone(), tree_id: family.table_id.clone() });
            };
            let table_actors = table
                .entries
                .iter()
                .filter_map(|entry| match &entry.leaf {
                    RouteTemplateLeafArtifact::Template { actor, .. } => Some(actor.clone()),
                    RouteTemplateLeafArtifact::RouteFamily { .. } => None,
                })
                .collect::<Vec<_>>();
            let direct_template_actors = if family.entry_actors.is_empty() {
                vec![family.anchor_actor.as_str()]
            } else {
                family.entry_actors.iter().map(String::as_str).collect::<Vec<_>>()
            };
            let direct_template_actor_set = direct_template_actors.into_iter().collect::<BTreeSet<_>>();
            let expected_table_actors =
                family.actors.iter().filter(|actor| !direct_template_actor_set.contains(actor.as_str())).cloned().collect::<Vec<_>>();
            if table.state != family.state || table_actors != expected_table_actors {
                return Err(TemplatePlanError::RouteFamilyTreeMismatch {
                    id: family.id.clone(),
                    tree_id: family.table_id.clone(),
                    expected: format!("state {} table actors {:?}", family.state, expected_table_actors),
                });
            }
        }

        let mut recipe_ids = BTreeSet::new();
        let mut recipes_by_id = BTreeMap::new();
        for recipe in &self.witness_recipes {
            if !recipe_ids.insert(recipe.id.as_str()) {
                return Err(TemplatePlanError::DuplicateWitnessRecipeId(recipe.id.clone()));
            }
            match &recipe.subject {
                HiddenParamSubjectArtifact::Actor { actor } => {
                    let Some(template_id) = &recipe.template_id else {
                        return Err(TemplatePlanError::MissingWitnessTemplate { id: recipe.id.clone(), template_id: String::new() });
                    };
                    let Some(template) = templates_by_id.get(template_id.as_str()) else {
                        return Err(TemplatePlanError::MissingWitnessTemplate {
                            id: recipe.id.clone(),
                            template_id: template_id.clone(),
                        });
                    };
                    if *actor != template.actor {
                        return Err(TemplatePlanError::WitnessTemplateMismatch {
                            id: recipe.id.clone(),
                            actor: actor.clone(),
                            template_actor: template.actor.clone(),
                        });
                    }
                }
                HiddenParamSubjectArtifact::RouteFamily { family_id } => {
                    if !route_families_by_id.contains_key(family_id.as_str()) {
                        return Err(TemplatePlanError::MissingWitnessRouteFamily {
                            id: recipe.id.clone(),
                            family_id: family_id.clone(),
                        });
                    }
                }
            }
            if let Some(route_tree_id) = &recipe.route_tree_id
                && !route_tree_ids.contains(route_tree_id.as_str())
            {
                return Err(TemplatePlanError::MissingWitnessRouteTree {
                    id: recipe.id.clone(),
                    route_tree_id: route_tree_id.clone(),
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
                    if recipe.param != param.name
                        || recipe.subject != param.subject
                        || recipe.purpose != param.purpose
                        || recipe.route_tree_id != param.route_tree_id
                    {
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
                    if recipe.param != witness.param
                        || recipe.subject != witness.subject
                        || recipe.purpose != witness.purpose
                        || recipe.route_tree_id != witness.route_tree_id
                    {
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

pub fn route_template_table_receipt_id(state: &str, field: &str) -> String {
    format!("route_table/{state}/{field}")
}

pub fn route_template_tree_receipt_id(state: &str, field: &str) -> String {
    format!("route_tree/{state}/{field}")
}

fn runtime_leaf_for_route_leaf(leaf: &RouteTemplateLeafArtifact) -> RuntimeRouteLeafArtifact {
    match leaf {
        RouteTemplateLeafArtifact::Template { actor, .. } => RuntimeRouteLeafArtifact::Contract { contract: actor.clone() },
        RouteTemplateLeafArtifact::RouteFamily { family_id, .. } => RuntimeRouteLeafArtifact::Digest { id: family_id.clone() },
    }
}

fn route_template_leaf_hash(
    table_id: &str,
    leaf: &RouteTemplateLeafArtifact,
    templates_by_id: &std::collections::BTreeMap<&str, &TemplatePlanTemplateArtifact>,
    digest_roots: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<[u8; 32], TemplatePlanError> {
    match leaf {
        RouteTemplateLeafArtifact::Template { actor, template_id } => {
            let Some(template) = templates_by_id.get(template_id.as_str()) else {
                return Err(TemplatePlanError::MissingRouteTableTemplate {
                    id: table_id.to_string(),
                    actor: actor.clone(),
                    template_id: template_id.clone(),
                });
            };
            if template.actor != *actor {
                return Err(TemplatePlanError::RouteTableTemplateMismatch {
                    id: table_id.to_string(),
                    actor: actor.clone(),
                    template_id: template_id.clone(),
                    template_actor: template.actor.clone(),
                });
            }
            decode_hash_hex(&template.id, &template.hash_hex)
        }
        RouteTemplateLeafArtifact::RouteFamily { family_id, tree_id } => {
            let Some(root_hex) = digest_roots.get(tree_id) else {
                return Err(TemplatePlanError::RouteTableFamilyTreeMismatch {
                    id: table_id.to_string(),
                    family_id: family_id.clone(),
                    tree_id: tree_id.clone(),
                    expected: String::new(),
                });
            };
            decode_hash_hex(tree_id, root_hex)
        }
    }
}

pub fn route_template_tree_from_table(
    table: &RouteTemplateTableArtifact,
    templates: &[TemplatePlanTemplateArtifact],
    digest_roots: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<RouteTemplateTreeArtifact, TemplatePlanError> {
    let templates_by_id =
        templates.iter().map(|template| (template.id.as_str(), template)).collect::<std::collections::BTreeMap<_, _>>();
    let mut leaf_hashes = Vec::with_capacity(table.entries.len());
    let mut leaves = Vec::with_capacity(table.entries.len());
    for entry in &table.entries {
        let leaf_hash = route_template_leaf_hash(&table.id, &entry.leaf, &templates_by_id, digest_roots)?;
        leaf_hashes.push(leaf_hash);
    }

    let layers = route_template_tree_layers(&leaf_hashes);
    let root_hex = route_template_tree_root_hex(&layers);
    for (position, (entry, template_hash)) in table.entries.iter().zip(leaf_hashes.iter()).enumerate() {
        leaves.push(RouteTemplateTreeLeafArtifact {
            index: entry.index,
            leaf: entry.leaf.clone(),
            hash_hex: encode_hex(template_hash),
            opening: route_template_tree_opening(&layers, position),
        });
    }

    Ok(RouteTemplateTreeArtifact {
        id: route_template_tree_receipt_id(&table.state, &table.field),
        table_id: table.id.clone(),
        state: table.state.clone(),
        field: table.field.clone(),
        root_hex,
        leaves,
    })
}

fn verify_route_template_tree(
    tree: &RouteTemplateTreeArtifact,
    table: &RouteTemplateTableArtifact,
    templates_by_id: &std::collections::BTreeMap<&str, &TemplatePlanTemplateArtifact>,
    route_trees_by_id: &std::collections::BTreeMap<&str, &RouteTemplateTreeArtifact>,
) -> std::result::Result<(), TemplatePlanError> {
    let expected_id = route_template_tree_receipt_id(&table.state, &table.field);
    if tree.id != expected_id
        || tree.table_id != table.id
        || tree.state != table.state
        || tree.field != table.field
        || tree.leaves.len() != table.entries.len()
    {
        return Err(TemplatePlanError::RouteTreeTableMismatch { id: tree.id.clone(), table_id: tree.table_id.clone() });
    }

    let digest_roots = route_trees_by_id
        .iter()
        .map(|(id, tree)| ((*id).to_string(), tree.root_hex.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut expected_leaf_hashes = Vec::with_capacity(table.entries.len());
    for entry in &table.entries {
        expected_leaf_hashes.push(route_template_leaf_hash(&table.id, &entry.leaf, templates_by_id, &digest_roots)?);
    }
    let expected_layers = route_template_tree_layers(&expected_leaf_hashes);
    let expected_root_hex = route_template_tree_root_hex(&expected_layers);
    if tree.root_hex != expected_root_hex {
        return Err(TemplatePlanError::RouteTreeRootMismatch {
            id: tree.id.clone(),
            expected: expected_root_hex,
            found: tree.root_hex.clone(),
        });
    }

    let root = decode_hash_hex(&tree.id, &tree.root_hex)?;
    for (index, (leaf, entry)) in tree.leaves.iter().zip(table.entries.iter()).enumerate() {
        if leaf.index != entry.index || leaf.leaf != entry.leaf {
            return Err(TemplatePlanError::RouteTreeTableMismatch { id: tree.id.clone(), table_id: tree.table_id.clone() });
        }
        if let RouteTemplateLeafArtifact::RouteFamily { family_id, tree_id } = &leaf.leaf
            && tree_id == &tree.id
        {
            return Err(TemplatePlanError::RecursiveRouteFamilyLeaf { id: tree.id.clone(), family_id: family_id.clone() });
        }
        let expected_hash_hex = encode_hex(&expected_leaf_hashes[index]);
        if leaf.hash_hex != expected_hash_hex {
            return Err(TemplatePlanError::RouteTreeLeafHashMismatch {
                id: tree.id.clone(),
                index,
                expected: expected_hash_hex,
                found: leaf.hash_hex.clone(),
            });
        }
        let expected_opening = route_template_tree_opening(&expected_layers, index);
        if leaf.opening != expected_opening {
            let resolved = route_template_tree_opening_root(&tree.id, &leaf.hash_hex, &leaf.opening)?;
            return Err(TemplatePlanError::RouteTreeOpeningMismatch {
                id: tree.id.clone(),
                index,
                expected: encode_hex(&root),
                found: encode_hex(&resolved),
            });
        }
        let resolved = route_template_tree_opening_root(&tree.id, &leaf.hash_hex, &leaf.opening)?;
        if resolved != root {
            return Err(TemplatePlanError::RouteTreeOpeningMismatch {
                id: tree.id.clone(),
                index,
                expected: encode_hex(&root),
                found: encode_hex(&resolved),
            });
        }
    }

    Ok(())
}

fn route_template_tree_layers(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Vec::new();
    }

    let mut layers = vec![leaves.to_vec()];
    while layers.last().expect("layers is non-empty").len() > 1 {
        let current = layers.last().expect("layers is non-empty");
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(route_template_tree_parent(&left, &right));
        }
        layers.push(next);
    }
    layers
}

fn route_template_tree_root_hex(layers: &[Vec<[u8; 32]>]) -> String {
    layers.last().and_then(|layer| layer.first()).map(|hash| encode_hex(hash)).unwrap_or_else(route_template_empty_tree_root_hex)
}

fn route_template_empty_tree_root_hex() -> String {
    let hash = blake2b_simd::Params::new().hash_length(32).to_state().finalize();
    encode_hex(hash.as_bytes())
}

fn route_template_tree_opening(layers: &[Vec<[u8; 32]>], mut index: usize) -> Vec<RouteTemplateTreeOpeningStepArtifact> {
    let mut opening = Vec::new();
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        let is_left_child = index.is_multiple_of(2);
        let sibling_index = if is_left_child { (index + 1).min(layer.len() - 1) } else { index - 1 };
        opening.push(RouteTemplateTreeOpeningStepArtifact {
            side: if is_left_child { RouteTemplateTreeOpeningSideArtifact::Right } else { RouteTemplateTreeOpeningSideArtifact::Left },
            hash_hex: encode_hex(&layer[sibling_index]),
        });
        index /= 2;
    }
    opening
}

fn route_template_tree_opening_root(
    id: &str,
    leaf_hash_hex: &str,
    opening: &[RouteTemplateTreeOpeningStepArtifact],
) -> std::result::Result<[u8; 32], TemplatePlanError> {
    let mut resolved = decode_hash_hex(id, leaf_hash_hex)?;
    for step in opening {
        let sibling = decode_hash_hex(id, &step.hash_hex)?;
        resolved = match step.side {
            RouteTemplateTreeOpeningSideArtifact::Left => route_template_tree_parent(&sibling, &resolved),
            RouteTemplateTreeOpeningSideArtifact::Right => route_template_tree_parent(&resolved, &sibling),
        };
    }
    Ok(resolved)
}

fn route_template_tree_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).to_state().update(left).update(right).finalize();
    hash.as_bytes().try_into().expect("hash length is fixed at 32 bytes")
}

fn decode_hash_hex(id: &str, hex: &str) -> std::result::Result<[u8; 32], TemplatePlanError> {
    let bytes = decode_hex_for_template(id, hex)?;
    if bytes.len() != 32 {
        return Err(TemplatePlanError::InvalidHex {
            id: id.to_string(),
            message: format!("expected 32-byte hash, found {} bytes", bytes.len()),
        });
    }
    Ok(bytes.try_into().expect("checked hash byte length"))
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
            "templates": [{ "id": "template/foo", "actor": "Foo", "symbol": "gen__foo_template" }],
            "template_plan": {
              "templates": [],
              "runtime_states": [
                {
                  "contract": "Foo",
                  "source": "FooState",
                  "field_roles": [
                    {
                      "name": "gen__foo_template",
                      "role": { "kind": "template", "contract": "Foo" }
                    }
                  ]
                }
              ],
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
                      "name": "gen__foo_template",
                      "type": { "kind": "fixed_bytes", "len": 32 }
                    },
                    {
                      "name": "owner",
                      "type": { "kind": "fixed_bytes", "len": 32 }
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
        assert_eq!(artifact.argent.template_plan.runtime_states[0].field_roles[0].name, "gen__foo_template");
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

    #[test]
    fn accepts_sil_contract_without_runtime_state_plan() {
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
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                states: Vec::new(),
                contracts: vec![SilContractArtifact {
                    name: "Foo".to_string(),
                    source_path: "sil/Foo.sil".to_string(),
                    runtime_state: RuntimeStateArtifact { source: "FooState".to_string(), fields: Vec::new() },
                    entries: Vec::new(),
                    compiled: CompiledContractArtifact {
                        script_hex: String::new(),
                        template: CompiledTemplateArtifact {
                            prefix_hex: String::new(),
                            suffix_hex: String::new(),
                            hash_hex: String::new(),
                        },
                        state_span: StateSpanArtifact { offset: 0, len: 0 },
                    },
                }],
            },
        };

        artifact.verify_template_plan().expect("missing runtime state plan means all fields are source");
    }

    #[test]
    fn rejects_duplicate_actor_in_route_family_receipt() {
        let artifact = artifact_with_route_families(vec![RouteTemplateFamilyArtifact {
            id: "route_family/BoardState/mux".to_string(),
            state: "BoardState".to_string(),
            anchor_actor: "Mux".to_string(),
            entry_actors: vec!["Mux".to_string()],
            table_id: "route_table/BoardState/gen__mux_routes".to_string(),
            actors: vec!["Mux".to_string(), "Mux".to_string()],
        }]);

        let err = artifact.verify_template_plan().expect_err("duplicate actor must be rejected");
        assert_eq!(
            err,
            TemplatePlanError::DuplicateRouteFamilyActor { id: "route_family/BoardState/mux".to_string(), actor: "Mux".to_string() }
        );
    }

    #[test]
    fn rejects_route_family_state_mismatch() {
        let artifact = artifact_with_route_families(vec![RouteTemplateFamilyArtifact {
            id: "route_family/BoardState/mux".to_string(),
            state: "BoardState".to_string(),
            anchor_actor: "Mux".to_string(),
            entry_actors: vec!["Mux".to_string()],
            table_id: "route_table/BoardState/gen__mux_routes".to_string(),
            actors: vec!["Mux".to_string(), "Player".to_string()],
        }]);

        let err = artifact.verify_template_plan().expect_err("state mismatch must be rejected");
        assert_eq!(
            err,
            TemplatePlanError::RouteFamilyStateMismatch {
                id: "route_family/BoardState/mux".to_string(),
                actor: "Player".to_string(),
                expected: "BoardState".to_string(),
                found: "PlayerState".to_string()
            }
        );
    }

    fn artifact_with_route_families(route_families: Vec<RouteTemplateFamilyArtifact>) -> Artifact {
        Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact { route_families, ..TemplatePlanArtifact::default() },
                states: Vec::new(),
                actors: vec![
                    ActorArtifact {
                        name: "Mux".to_string(),
                        state: "BoardState".to_string(),
                        abi: ActorAbiRefArtifact { actor: "Mux".to_string() },
                        entries: Vec::new(),
                    },
                    ActorArtifact {
                        name: "Player".to_string(),
                        state: "PlayerState".to_string(),
                        abi: ActorAbiRefArtifact { actor: "Player".to_string() },
                        entries: Vec::new(),
                    },
                ],
            },
            sil_abi: SilAbiArtifact { schema_version: SIL_ABI_SCHEMA_VERSION, states: Vec::new(), contracts: Vec::new() },
        }
    }
}
