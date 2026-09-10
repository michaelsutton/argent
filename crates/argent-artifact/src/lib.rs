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

mod template_frames;
mod verify_spawns;

pub use template_frames::{TemplateFrameLengths, TemplateFrameVerificationError};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use silverscript_abi::{
    ArtifactVersionError, CompiledContractArtifact, DispatchTag, DispatchTagParseError, FieldArtifact, ParamArtifact,
    RuntimeFieldArtifact, RuntimeStateArtifact, SIL_ABI_SCHEMA_VERSION, SilAbiArtifact, SilAbiVerificationError, SilContractArtifact,
    SilEntryArtifact, StateSpanArtifact, StructArtifact, TypeArtifact,
};

pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub schema_version: u32,
    #[serde(default)]
    pub id: String,
    pub generator: GeneratorArtifact,
    pub app: String,
    pub dependencies: Vec<AppDependencyArtifact>,
    pub root: String,
    pub modules: Vec<String>,
    pub argent: ArgentArtifact,
    pub sil_abi: SilAbiArtifact,
}

#[derive(Debug, Error)]
pub enum ArtifactVerificationError {
    #[error(transparent)]
    Version(#[from] ArtifactVersionError),
    #[error(transparent)]
    SilAbi(#[from] SilAbiVerificationError),
    #[error(transparent)]
    TemplateFrames(#[from] TemplateFrameVerificationError),
    #[error(transparent)]
    TemplatePlan(#[from] TemplatePlanError),
    #[error(transparent)]
    Identity(#[from] ArtifactIdentityError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppDependencyArtifact {
    pub app: String,
    pub artifact_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgentArtifact {
    pub templates: Vec<TemplateRefArtifact>,
    #[serde(default)]
    pub template_plan: TemplatePlanArtifact,
    #[serde(default)]
    pub interfaces: InterfaceSetArtifact,
    pub states: Vec<ArgentStateArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_expansions: Vec<StateExpansionArtifact>,
    #[serde(default)]
    pub actor_enums: Vec<ActorEnumArtifact>,
    pub actors: Vec<ActorArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgentStateArtifact {
    pub name: String,
    pub fields: Vec<ArgentFieldArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgentFieldArtifact {
    pub name: String,
    /// Lowered Sil type used for layout and runtime encoding.
    #[serde(rename = "type")]
    pub ty: TypeArtifact,
    /// Source type when lowering removes Argent meaning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<SourceTypeArtifact>,
    #[serde(rename = "virtual", default, skip_serializing_if = "is_false")]
    pub virtual_slot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceTypeArtifact {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array: Option<SourceArrayArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "len", rename_all = "snake_case")]
pub enum SourceArrayArtifact {
    Dynamic,
    Fixed(usize),
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Artifact {
    /// Checks the complete portable Argent artifact for internal consistency.
    ///
    /// The check compares the artifact's schema, ABI, template plan, compiled
    /// frames, and declared identity. It assumes the artifact was produced by
    /// supported Argent and Silverscript compilers and may rely on their
    /// representation invariants.
    ///
    /// This method does not prove that the embedded bytecode was generated from
    /// the recorded source or make an attacker-supplied artifact trustworthy.
    /// Consumers must obtain the artifact from a trusted build or compare its
    /// computed identity with a separately trusted identity.
    pub fn check_consistency(&self) -> std::result::Result<(), ArtifactVerificationError> {
        self.check_schema_version()?;
        self.check_sil_abi_consistency()?;
        self.verify_template_frames()?;
        self.check_template_plan_consistency()?;
        self.verify_id()?;
        Ok(())
    }

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

    pub fn check_template_plan_consistency(&self) -> std::result::Result<(), TemplatePlanError> {
        self.argent.template_plan.check_consistency(self)
    }

    pub fn check_sil_abi_consistency(&self) -> std::result::Result<(), SilAbiVerificationError> {
        self.sil_abi.check_consistency()
    }

    /// Verifies that local actor frames are unambiguous under Argent's
    /// conservative frame rule.
    ///
    /// Frames are derived only from each actor's referenced embedded Sil
    /// contract. Linked-app actors are not part of this artifact's local actor
    /// set and are therefore not compared here.
    pub fn verify_template_frames(&self) -> std::result::Result<(), TemplateFrameVerificationError> {
        template_frames::verify(self)
    }

    pub fn computed_id_hex(&self) -> std::result::Result<String, ArtifactIdentityError> {
        let mut artifact = self.clone();
        artifact.id.clear();
        // Source paths are informational and must not make artifact ids
        // dependent on the checkout location.
        artifact.root.clear();
        artifact.modules.clear();
        hash_json("argent/artifact/v1", &artifact)
    }

    pub fn verify_id(&self) -> std::result::Result<(), ArtifactIdentityError> {
        if self.id.is_empty() {
            return Err(ArtifactIdentityError::MissingArtifactId { app: self.app.clone() });
        }
        let expected = self.computed_id_hex()?;
        if self.id != expected {
            return Err(ArtifactIdentityError::ArtifactIdMismatch { app: self.app.clone(), expected, found: self.id.clone() });
        }
        Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorEnumArtifact {
    pub name: String,
    pub state: String,
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceSetArtifact {
    #[serde(default)]
    pub exports: Vec<ActorInterfaceArtifact>,
    #[serde(default)]
    pub imports: Vec<ActorInterfaceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorInterfaceArtifact {
    pub id: String,
    pub app: String,
    pub actor: String,
    pub state: String,
    pub fingerprint_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateExpansionArtifact {
    pub state: String,
    pub base: String,
    pub digests: Vec<StateDigestExpansionArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDigestExpansionArtifact {
    pub field: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatePlanArtifact {
    pub templates: Vec<TemplateReceiptArtifact>,
    #[serde(default)]
    pub runtime_states: Vec<RuntimeStatePlanArtifact>,
    #[serde(default)]
    pub route_tables: Vec<RouteTemplateTableArtifact>,
    #[serde(default)]
    pub route_proofs: Vec<RouteTemplateProofArtifact>,
    #[serde(default)]
    pub route_families: Vec<RouteTemplateFamilyArtifact>,
    pub witness_recipes: Vec<WitnessRecipeArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateReceiptArtifact {
    pub id: String,
    pub actor: String,
    pub contract: String,
    pub symbol: String,
    /// Hash of the full physical Sil state cut used inside the defining app.
    #[serde(with = "serde_bytes")]
    pub sil_template_hash: [u8; 32],
    /// Required source-state view used by static linking and `actor_type<State>`.
    pub actor_type_handle: ActorTypeHandleArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorTypeHandleArtifact {
    /// Argent state layout left open between the handle's template prefix and
    /// suffix.
    ///
    /// This is normally the actor's owned state. For an expanded state, it is
    /// the expansion base. The base and expanded authored views use the same
    /// handle.
    pub state: String,
    /// Ordered names of the leading compiler-owned runtime fields fixed in the
    /// handle's template prefix.
    ///
    /// Each name refers to a field in the Silverscript contract's runtime
    /// state. The matching `RuntimeStatePlanArtifact::field_roles` entry tells
    /// verification and runtime construction how to derive its canonical value
    /// from the template plan.
    pub context_fields: Vec<String>,
    /// External template frame after the compiler-owned context has been moved
    /// into its fixed prefix, leaving `state` open.
    pub template: ActorTemplateArtifact,
}

/// Compiled template material retained by Argent actor-type handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorTemplateArtifact {
    #[serde(with = "serde_bytes")]
    pub prefix: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub suffix: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub hash: [u8; 32],
}

/// Read-only template hash data used while a template plan is built and
/// verified.
#[derive(Debug, Clone, Copy)]
pub struct TemplateHashRef<'a> {
    pub id: &'a str,
    pub actor: &'a str,
    pub hash: &'a [u8; 32],
}

/// Supplies Sil template hashes without requiring a completed artifact.
pub trait TemplateHashLookup {
    fn template_hash_by_id(&self, id: &str) -> Option<TemplateHashRef<'_>>;
    fn template_hash_by_actor(&self, actor: &str) -> Option<TemplateHashRef<'_>>;
}

/// Supplies the completed route commitments that fix compiler-owned context.
pub trait TemplatePlanLookup: TemplateHashLookup {
    fn route_tables(&self) -> &[RouteTemplateTableArtifact];
    fn route_proofs(&self) -> &[RouteTemplateProofArtifact];
    fn route_families(&self) -> &[RouteTemplateFamilyArtifact];
}

impl TemplateHashLookup for [TemplateReceiptArtifact] {
    fn template_hash_by_id(&self, id: &str) -> Option<TemplateHashRef<'_>> {
        self.iter().find(|template| template.id == id).map(|template| TemplateHashRef {
            id: &template.id,
            actor: &template.actor,
            hash: &template.sil_template_hash,
        })
    }

    fn template_hash_by_actor(&self, actor: &str) -> Option<TemplateHashRef<'_>> {
        self.iter().find(|template| template.actor == actor).map(|template| TemplateHashRef {
            id: &template.id,
            actor: &template.actor,
            hash: &template.sil_template_hash,
        })
    }
}

impl TemplateHashLookup for std::collections::BTreeMap<&str, &TemplateReceiptArtifact> {
    fn template_hash_by_id(&self, id: &str) -> Option<TemplateHashRef<'_>> {
        self.get(id).map(|template| TemplateHashRef { id: &template.id, actor: &template.actor, hash: &template.sil_template_hash })
    }

    fn template_hash_by_actor(&self, actor: &str) -> Option<TemplateHashRef<'_>> {
        self.values().find(|template| template.actor == actor).map(|template| TemplateHashRef {
            id: &template.id,
            actor: &template.actor,
            hash: &template.sil_template_hash,
        })
    }
}

impl TemplateHashLookup for TemplatePlanArtifact {
    fn template_hash_by_id(&self, id: &str) -> Option<TemplateHashRef<'_>> {
        self.templates.as_slice().template_hash_by_id(id)
    }

    fn template_hash_by_actor(&self, actor: &str) -> Option<TemplateHashRef<'_>> {
        self.templates.as_slice().template_hash_by_actor(actor)
    }
}

impl TemplatePlanLookup for TemplatePlanArtifact {
    fn route_tables(&self) -> &[RouteTemplateTableArtifact] {
        &self.route_tables
    }

    fn route_proofs(&self) -> &[RouteTemplateProofArtifact] {
        &self.route_proofs
    }

    fn route_families(&self) -> &[RouteTemplateFamilyArtifact] {
        &self.route_families
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStatePlanArtifact {
    /// Silverscript contract whose runtime `State` this plan describes.
    ///
    /// This name joins the plan to the contract ABI and its Argent actor.
    pub contract: String,
    /// State type declared as owned by the Argent actor, before storage and
    /// physical layout lowering.
    ///
    /// Runtime construction uses this name to interpret authored values and
    /// apply state expansions before producing the contract's physical state.
    pub source: String,
    /// Ordered descriptions of the compiler-owned fields in the contract's
    /// physical runtime state.
    ///
    /// Each entry names a runtime ABI field and defines how its value is
    /// derived from the canonical route and template plan.
    pub field_roles: Vec<RuntimeFieldRolePlanArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFieldRolePlanArtifact {
    pub name: String,
    pub role: RuntimeFieldRoleArtifact,
}

/// Describes how the template plan derives one compiler-owned runtime field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeFieldRoleArtifact {
    /// Stores the compiled template hash of one contract.
    Template {
        /// Contract whose template hash supplies the field value.
        contract: String,
    },
    /// Stores the concatenated template hashes of an ordered route table.
    TemplateTable {
        /// Contracts whose template hashes appear in table order.
        contracts: Vec<String>,
    },
    /// Stores the Blake3 digest of a route family's template table.
    TemplateDigest {
        /// Route-family ID used to locate the table and derive its digest.
        id: String,
    },
    /// Stores the root commitment of a route-template proof.
    TemplateRoot {
        /// Ordered contract or digest leaves committed by the proof.
        leaves: Vec<RuntimeRouteLeafArtifact>,
    },
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
pub struct RouteTemplateProofArtifact {
    pub id: String,
    pub table_id: String,
    pub state: String,
    pub field: String,
    pub root_hex: String,
    pub leaves: Vec<RouteTemplateProofLeafArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateProofLeafArtifact {
    pub index: usize,
    #[serde(flatten)]
    pub leaf: RouteTemplateLeafArtifact,
    pub hash_hex: String,
    pub proof: Vec<RouteTemplateProofStepArtifact>,
}

/// One 32-byte commitment leaf in a route-template table and its proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteTemplateLeafArtifact {
    /// Commits directly to one actor's compiled template hash.
    Template {
        /// Actor represented by this leaf.
        actor: String,
        /// Template receipt that supplies the committed hash.
        template_id: String,
    },
    /// Commits to the proof root of another route family.
    RouteFamily {
        /// Route family represented by this leaf.
        family_id: String,
        /// Proof receipt whose root supplies the committed hash.
        proof_id: String,
    },
}

/// One state-local family represented by direct templates and one route table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateFamilyArtifact {
    /// Stable ID used to reference this family from fields and witnesses.
    pub id: String,
    /// Argent state type owned by every actor in the family.
    pub state: String,
    /// Family member used to derive stable family identity and generated names.
    ///
    /// The representative has no special position in the route table.
    pub representative_actor: String,
    /// Family actors kept as direct template commitments rather than entries
    /// in `table_id`.
    pub entry_actors: Vec<String>,
    /// Route-template table containing the remaining family actors.
    pub table_id: String,
    /// Complete family membership.
    pub actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteTemplateProofStepArtifact {
    pub side: RouteTemplateProofSideArtifact,
    pub hash_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTemplateProofSideArtifact {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRecipeArtifact {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    pub subject: HiddenParamSubjectArtifact,
    pub param: String,
    pub purpose: HiddenParamPurposeArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_proof_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorArtifact {
    pub name: String,
    pub state: String,
    pub abi: ActorAbiRefArtifact,
    /// Delegate entries that trust this actor's contract at covenant input
    /// zero. A nonempty list makes this a leader actor, so every leader
    /// entry must constrain its complete same-covenant input group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leader_for: Vec<EntryRefArtifact>,
    pub entries: Vec<EntryArtifact>,
}

/// Identifies an entry by its declaring actor and source-level name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntryRefArtifact {
    pub actor: String,
    pub entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorAbiRefArtifact {
    pub contract: String,
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
    #[serde(default)]
    pub template_selectors: Vec<TemplateSelectorArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observes: Vec<ObserveArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spawns: Vec<SpawnArtifact>,
    pub witnesses: Vec<WitnessArtifact>,
    pub consumes: Vec<ConsumeArtifact>,
    pub emits: EmitArtifact,
    pub routes: Vec<RouteArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnArtifact {
    pub name: String,
    pub covenant: String,
    pub outputs: Vec<SpawnOutputArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnOutputArtifact {
    pub name: String,
    /// Source actor expression; dynamic targets use it for actor-type lookup.
    pub actor: String,
    pub state: String,
    pub group_index: usize,
    #[serde(default, skip_serializing_if = "CardinalityArtifact::is_one")]
    pub cardinality: CardinalityArtifact,
    /// Canonical dependency target for a statically linked actor.
    ///
    /// Selected-app actors and dynamic actor-type values retain their existing
    /// artifact-local inference when this field is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ActorTargetArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateSelectorArtifact {
    pub name: String,
    pub actor_enum: String,
    pub state: String,
    pub variants: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveArtifact {
    pub name: String,
    pub covenant_expr: String,
    pub covenant_id_source: CovenantIdSourceArtifact,
    pub inputs: Vec<ObservedActorArtifact>,
    pub outputs: Vec<ObservedActorArtifact>,
}

/// Machine-readable source of the covenant id selected by an `observes` clause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CovenantIdSourceArtifact {
    /// A field in the actor's source state.
    StateField { field: String },
    /// A user-visible entry argument, indexed in source declaration order.
    EntryArgument { index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedActorArtifact {
    pub name: String,
    pub target: ObservedTargetArtifact,
    #[serde(default, skip_serializing_if = "CardinalityArtifact::is_one")]
    pub cardinality: CardinalityArtifact,
}

pub type ObservedTargetArtifact = ActorTargetArtifact;

/// A statically resolved actor or a runtime-selected actor state domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActorTargetArtifact {
    StaticActor { app: String, actor: String },
    DynamicActor { state: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryAbiRefArtifact {
    pub contract: String,
    pub entry: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessArtifact {
    pub recipe_id: String,
    pub param: String,
    pub subject: HiddenParamSubjectArtifact,
    pub purpose: HiddenParamPurposeArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_proof_id: Option<String>,
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
    pub route_proof_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenParamSubjectArtifact {
    Actor { actor: String },
    ObservedActor { observe: String, side: ObservedActorSideArtifact, handle: String, actor: String },
    SpawnActor { spawn: String, handle: String, actor: String },
    ObservedOutputField { observe: String, handle: String, state: String, field: String },
    RouteFamily { family_id: String },
    TemplateSelector { selector: String },
    StateExpansion { state: String, field: String, memory_state: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedActorSideArtifact {
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HiddenParamPurposeArtifact {
    SpawnOutputIndex,
    TemplatePrefixBytes,
    TemplateSuffixBytes,
    TemplatePrefixLen,
    TemplateSuffixLen,
    /// Hash of a runtime-selected actor template, resolved from its artifact.
    TemplateHash,
    RouteTemplateLeaf,
    RouteTemplateProof,
    RouteFamilyTable,
    RouteFamilyProof,
    StateExpansionPreimage,
    ObservedOutputFieldValue,
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
    #[serde(default, skip_serializing_if = "CardinalityArtifact::is_one")]
    pub cardinality: CardinalityArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmitArtifact {
    None,
    Outputs { outputs: Vec<EmitOutputArtifact> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmitOutputArtifact {
    pub name: String,
    /// Exact authorized-output index when it does not depend on a preceding range length.
    pub auth_index: Option<usize>,
    pub actors: Vec<String>,
    #[serde(default, skip_serializing_if = "CardinalityArtifact::is_one")]
    pub cardinality: CardinalityArtifact,
}

/// Maximum range cardinality accepted by Argent compilers and runtimes.
///
/// Keeping the limit in the portable artifact layer prevents compiler and
/// consumer implementations from drifting on generated-loop resource bounds.
pub const MAX_ENTRY_RANGE_CARDINALITY: i64 = 512;

/// Resolved transaction cardinality of one named interaction handle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CardinalityArtifact {
    #[default]
    One,
    Range {
        minimum: i64,
        maximum: i64,
    },
}

impl CardinalityArtifact {
    pub fn is_one(&self) -> bool {
        matches!(self, Self::One)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EntryRoutePlanArtifact {
    pub active_input: Option<RouteInputArtifact>,
    pub leader_input: Option<RouteInputArtifact>,
    pub consumes: Vec<RouteInputArtifact>,
    pub outputs: Vec<RouteOutputHandleArtifact>,
    pub witness_recipe_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInputArtifact {
    pub name: String,
    pub actor: String,
    /// Exact covenant-input index when it does not depend on a preceding range length.
    pub cov_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteOutputHandleArtifact {
    pub name: String,
    /// Exact authorized-output index when it does not depend on a preceding range length.
    pub auth_index: Option<usize>,
    pub actors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteArtifact {
    pub output: String,
    pub successor: RouteSuccessorArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteSuccessorArtifact {
    ExactSelf,
    Constructed { actor: String, template_id: String, state_expr: String },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TemplatePlanError {
    #[error("duplicate template receipt id `{0}`")]
    DuplicateTemplateId(String),
    #[error("duplicate route template table id `{0}`")]
    DuplicateRouteTableId(String),
    #[error("duplicate route template proof id `{0}`")]
    DuplicateRouteProofId(String),
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
    #[error("template receipt `{id}` Sil template hash mismatch: expected `{expected}`, found `{found}`")]
    TemplateHashMismatch { id: String, expected: String, found: String },
    #[error("template receipt `{id}` actor_type handle is invalid: {message}")]
    ActorTypeHandleMismatch { id: String, message: String },
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
    #[error("route template table `{id}` entry for route family `{family_id}` points at proof `{proof_id}`, expected `{expected}`")]
    RouteTableFamilyProofMismatch { id: String, family_id: String, proof_id: String, expected: String },
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
    #[error("route template proof `{id}` points at missing route template table `{table_id}`")]
    MissingRouteProofTable { id: String, table_id: String },
    #[error("route template table `{table_id}` has no route template proof receipt")]
    MissingRouteProof { table_id: String },
    #[error("route template proof `{id}` does not match route template table `{table_id}`")]
    RouteProofTableMismatch { id: String, table_id: String },
    #[error("route template proof `{id}` leaf {index} hash mismatch: expected `{expected}`, found `{found}`")]
    RouteProofLeafHashMismatch { id: String, index: usize, expected: String, found: String },
    #[error("route template proof `{id}` root mismatch: expected `{expected}`, found `{found}`")]
    RouteProofRootMismatch { id: String, expected: String, found: String },
    #[error("route template proof `{id}` leaf {index} proof resolves to `{found}`, expected root `{expected}`")]
    RouteProofMismatch { id: String, index: usize, expected: String, found: String },
    #[error("route template proof `{id}` contains a recursive route family leaf `{family_id}`")]
    RecursiveRouteFamilyLeaf { id: String, family_id: String },
    #[error("route template family `{id}` table `{table_id}` contains nested route family leaf `{family_id}`")]
    NestedRouteFamilyLeaf { id: String, table_id: String, family_id: String },
    #[error("duplicate route template family receipt `{0}`")]
    DuplicateRouteFamilyId(String),
    #[error("route template family `{id}` must contain at least two actors")]
    RouteFamilyTooSmall { id: String },
    #[error("route template family `{id}` repeats actor `{actor}`")]
    DuplicateRouteFamilyActor { id: String, actor: String },
    #[error("route template family `{id}` references unknown actor `{actor}`")]
    MissingRouteFamilyActor { id: String, actor: String },
    #[error("route template family `{id}` representative actor `{representative}` is not in the family")]
    RouteFamilyRepresentativeOutsideFamily { id: String, representative: String },
    #[error("route template family `{id}` repeats entry actor `{actor}`")]
    DuplicateRouteFamilyEntryActor { id: String, actor: String },
    #[error("route template family `{id}` entry actor `{actor}` is not in the family")]
    MissingRouteFamilyEntryActor { id: String, actor: String },
    #[error("route template family `{id}` actor `{actor}` owns state `{found}`, expected `{expected}`")]
    RouteFamilyStateMismatch { id: String, actor: String, expected: String, found: String },
    #[error("route template family `{id}` points at missing route template table `{table_id}`")]
    MissingRouteFamilyTable { id: String, table_id: String },
    #[error("route template family `{id}` points at table `{table_id}`, expected `{expected}`")]
    RouteFamilyTableMismatch { id: String, table_id: String, expected: String },
    #[error("witness recipe `{id}` references missing template receipt `{template_id}`")]
    MissingWitnessTemplate { id: String, template_id: String },
    #[error("witness recipe `{id}` references missing imported actor template `{actor}`")]
    MissingWitnessImportedTemplate { id: String, actor: String },
    #[error("witness recipe `{id}` references missing route family `{family_id}`")]
    MissingWitnessRouteFamily { id: String, family_id: String },
    #[error("witness recipe `{id}` references missing route proof receipt `{route_proof_id}`")]
    MissingWitnessRouteProof { id: String, route_proof_id: String },
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
    #[error("spawn metadata for `{entry}` is invalid: {message}")]
    InvalidSpawnMetadata { entry: String, message: String },
    #[error("route `{entry}` to actor `{actor}` points at missing template receipt `{template_id}`")]
    MissingRouteTemplate { entry: String, actor: String, template_id: String },
    #[error("route `{entry}` to actor `{actor}` points at template receipt `{template_id}` for actor `{template_actor}`")]
    RouteTemplateMismatch { entry: String, actor: String, template_id: String, template_actor: String },
    #[error("route plan for `{entry}` points at witness recipe `{recipe_id}` that is not exposed by the entry")]
    RoutePlanRecipeNotExposed { entry: String, recipe_id: String },
    #[error("route plan for `{entry}` points at missing witness recipe `{recipe_id}`")]
    MissingRoutePlanRecipe { entry: String, recipe_id: String },
}

#[derive(Debug, Error)]
pub enum ArtifactIdentityError {
    #[error("artifact `{app}` is missing an artifact id")]
    MissingArtifactId { app: String },
    #[error("artifact `{app}` id mismatch: expected {expected}, found {found}")]
    ArtifactIdMismatch { app: String, expected: String, found: String },
    #[error("failed to serialize {subject} for hashing: {source}")]
    Serialize { subject: &'static str, source: serde_json::Error },
}

impl TemplatePlanArtifact {
    /// Checks that this template plan is a complete and internally consistent
    /// coordination view of the containing artifact.
    ///
    /// Within supported compiler output, the embedded Silverscript ABI is the
    /// reference for compiled templates and runtime layouts. This method verifies
    /// that template receipts, actor-type handles, route metadata, spawn groups,
    /// and witness recipes agree with that ABI and with each other.
    ///
    /// Like `Artifact::check_consistency`, this check may rely on
    /// compiler-enforced invariants. It does not attest compilation provenance or
    /// validate arbitrary attacker-supplied bytecode.
    pub fn check_consistency(&self, artifact: &Artifact) -> std::result::Result<(), TemplatePlanError> {
        use std::collections::{BTreeMap, BTreeSet};

        // TODO: Extract template receipt and actor-type handle verification into dedicated helpers.
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
            if template.actor != template.contract {
                return Err(TemplatePlanError::TemplateContractMismatch {
                    id: template.id.clone(),
                    actor: template.actor.clone(),
                    contract: template.contract.clone(),
                });
            }
            // The plan carries a denormalized copy for route-proof leaves. Keep
            // that receipt consistent with the authoritative Sil ABI value.
            let expected_hash = contract.compiled.template_hash;
            if template.sil_template_hash != expected_hash {
                return Err(TemplatePlanError::TemplateHashMismatch {
                    id: template.id.clone(),
                    expected: encode_hex(&expected_hash),
                    found: encode_hex(&template.sil_template_hash),
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
        // TODO: Extract route-family membership verification into dedicated helpers.
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
            if !family_actors.contains(family.representative_actor.as_str()) {
                return Err(TemplatePlanError::RouteFamilyRepresentativeOutsideFamily {
                    id: family.id.clone(),
                    representative: family.representative_actor.clone(),
                });
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

        let sil_contracts_by_name = &artifact.sil_abi.contracts;
        // TODO: Extract runtime-state field-role verification into dedicated helpers.
        let mut runtime_states_by_contract = BTreeMap::new();
        for runtime_state in &self.runtime_states {
            if runtime_states_by_contract.insert(runtime_state.contract.as_str(), runtime_state).is_some() {
                return Err(TemplatePlanError::DuplicateRuntimeStatePlan(runtime_state.contract.clone()));
            }
            let Some(contract) = sil_contracts_by_name.get(&runtime_state.contract) else {
                return Err(TemplatePlanError::UnknownContract(runtime_state.contract.clone()));
            };
            let actor_state =
                actor_states.get(runtime_state.contract.as_str()).ok_or_else(|| TemplatePlanError::RuntimeStatePlanMismatch {
                    contract: runtime_state.contract.clone(),
                    message: "contract has no matching Argent actor".to_string(),
                })?;
            if runtime_state.source != *actor_state {
                return Err(TemplatePlanError::RuntimeStatePlanMismatch {
                    contract: runtime_state.contract.clone(),
                    message: format!("source `{}` does not match actor state `{}`", runtime_state.source, actor_state),
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

        // TODO: Extract route-table structure and template-reference verification into dedicated helpers.
        let mut route_table_ids = BTreeSet::new();
        let mut route_tables_by_id = BTreeMap::new();
        for table in &self.route_tables {
            if !route_table_ids.insert(table.id.as_str()) {
                return Err(TemplatePlanError::DuplicateRouteTableId(table.id.clone()));
            }
            route_tables_by_id.insert(table.id.as_str(), table);
        }

        for table in &self.route_tables {
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
                    RouteTemplateLeafArtifact::RouteFamily { family_id, proof_id } => {
                        let Some(family) = route_families_by_id.get(family_id.as_str()) else {
                            return Err(TemplatePlanError::MissingRouteTableFamily {
                                id: table.id.clone(),
                                family_id: family_id.clone(),
                            });
                        };
                        let Some(family_table) = route_tables_by_id.get(family.table_id.as_str()) else {
                            return Err(TemplatePlanError::MissingRouteFamilyTable {
                                id: family.id.clone(),
                                table_id: family.table_id.clone(),
                            });
                        };
                        let expected_proof_id = route_template_proof_receipt_id(&family_table.state, &family_table.field);
                        if proof_id != &expected_proof_id {
                            return Err(TemplatePlanError::RouteTableFamilyProofMismatch {
                                id: table.id.clone(),
                                family_id: family_id.clone(),
                                proof_id: proof_id.clone(),
                                expected: expected_proof_id,
                            });
                        }
                    }
                }
            }
        }

        // TODO: Extract runtime-state-to-route-table binding verification into dedicated helpers.
        let mut referenced_route_table_ids = BTreeSet::new();
        let imported_templates = artifact
            .argent
            .interfaces
            .imports
            .iter()
            .map(|interface| (interface.app.as_str(), interface.actor.as_str()))
            .collect::<BTreeSet<_>>();
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
                    RuntimeFieldRoleArtifact::Template { .. } => {
                        if sil_field.ty != (TypeArtifact::FixedBytes { len: 32 }) {
                            return Err(TemplatePlanError::RuntimeStatePlanMismatch {
                                contract: runtime_state.contract.clone(),
                                message: format!("template field `{}` must have type `byte[32]`", field.name),
                            });
                        }
                        continue;
                    }
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

        // TODO: Extract route-proof and route-family table verification into dedicated helpers.
        let mut route_proof_ids = BTreeSet::new();
        let mut route_proofs_by_id = BTreeMap::new();
        for proof in &self.route_proofs {
            if !route_proof_ids.insert(proof.id.as_str()) {
                return Err(TemplatePlanError::DuplicateRouteProofId(proof.id.clone()));
            }
            if !route_tables_by_id.contains_key(proof.table_id.as_str()) {
                return Err(TemplatePlanError::MissingRouteProofTable { id: proof.id.clone(), table_id: proof.table_id.clone() });
            }
            route_proofs_by_id.insert(proof.id.as_str(), proof);
        }
        for proof in &self.route_proofs {
            let table = route_tables_by_id
                .get(proof.table_id.as_str())
                .expect("route proof table existence was checked when indexing route proofs");
            verify_route_template_proof(proof, table, &templates_by_id, &route_proofs_by_id)?;
        }
        for table in &self.route_tables {
            let expected_proof_id = route_template_proof_receipt_id(&table.state, &table.field);
            if !route_proof_ids.contains(expected_proof_id.as_str()) {
                return Err(TemplatePlanError::MissingRouteProof { table_id: table.id.clone() });
            }
        }
        for family in &self.route_families {
            let Some(table) = route_tables_by_id.get(family.table_id.as_str()) else {
                return Err(TemplatePlanError::MissingRouteFamilyTable { id: family.id.clone(), table_id: family.table_id.clone() });
            };
            for entry in &table.entries {
                if let RouteTemplateLeafArtifact::RouteFamily { family_id, .. } = &entry.leaf {
                    return Err(TemplatePlanError::NestedRouteFamilyLeaf {
                        id: family.id.clone(),
                        table_id: family.table_id.clone(),
                        family_id: family_id.clone(),
                    });
                }
            }
            let table_actors = table
                .entries
                .iter()
                .filter_map(|entry| match &entry.leaf {
                    RouteTemplateLeafArtifact::Template { actor, .. } => Some(actor.clone()),
                    RouteTemplateLeafArtifact::RouteFamily { .. } => None,
                })
                .collect::<Vec<_>>();
            let direct_template_actor_set = family.entry_actors.iter().map(String::as_str).collect::<BTreeSet<_>>();
            let expected_table_actors =
                family.actors.iter().filter(|actor| !direct_template_actor_set.contains(actor.as_str())).cloned().collect::<Vec<_>>();
            let expected_table_actor_set = expected_table_actors.iter().map(String::as_str).collect::<BTreeSet<_>>();
            let table_actor_set = table_actors.iter().map(String::as_str).collect::<BTreeSet<_>>();
            if table.state != family.state
                || table_actors.len() != expected_table_actor_set.len()
                || table_actor_set != expected_table_actor_set
            {
                return Err(TemplatePlanError::RouteFamilyTableMismatch {
                    id: family.id.clone(),
                    table_id: family.table_id.clone(),
                    expected: format!("state {} table actors {:?}", family.state, expected_table_actors),
                });
            }
        }

        // Handle verification depends on the complete route plan. Validate it
        // only after all fixed compiler context has been checked.
        for template in &self.templates {
            let contract = sil_contracts_by_name
                .get(template.contract.as_str())
                .expect("template contract existence was checked when indexing template receipts");
            verify_actor_type_handle(self, artifact, template, &template.contract, contract)?;
        }

        // TODO: Extract witness recipe registry verification into dedicated helpers.
        let mut recipe_ids = BTreeSet::new();
        let mut recipes_by_id = BTreeMap::new();
        for recipe in &self.witness_recipes {
            if !recipe_ids.insert(recipe.id.as_str()) {
                return Err(TemplatePlanError::DuplicateWitnessRecipeId(recipe.id.clone()));
            }
            match &recipe.subject {
                HiddenParamSubjectArtifact::Actor { actor } => {
                    if let Some(template_id) = &recipe.template_id {
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
                    } else {
                        let imported =
                            actor.split_once("::").is_some_and(|(app, contract)| imported_templates.contains(&(app, contract)));
                        if !imported {
                            return Err(TemplatePlanError::MissingWitnessImportedTemplate {
                                id: recipe.id.clone(),
                                actor: actor.clone(),
                            });
                        }
                    }
                }
                HiddenParamSubjectArtifact::ObservedActor { .. } => {}
                HiddenParamSubjectArtifact::SpawnActor { .. } => {}
                HiddenParamSubjectArtifact::ObservedOutputField { .. } => {}
                HiddenParamSubjectArtifact::RouteFamily { family_id } => {
                    if !route_families_by_id.contains_key(family_id.as_str()) {
                        return Err(TemplatePlanError::MissingWitnessRouteFamily {
                            id: recipe.id.clone(),
                            family_id: family_id.clone(),
                        });
                    }
                }
                HiddenParamSubjectArtifact::TemplateSelector { .. } => {}
                HiddenParamSubjectArtifact::StateExpansion { .. } => {}
            }
            if let Some(route_proof_id) = &recipe.route_proof_id
                && !route_proof_ids.contains(route_proof_id.as_str())
            {
                return Err(TemplatePlanError::MissingWitnessRouteProof {
                    id: recipe.id.clone(),
                    route_proof_id: route_proof_id.clone(),
                });
            }
            recipes_by_id.insert(recipe.id.as_str(), recipe);
        }

        // TODO: Extract generic per-entry recipe, witness, and route verification into dedicated helpers.
        for actor in &artifact.argent.actors {
            for entry in &actor.entries {
                let entry_id = format!("{}::{}", actor.name, entry.name);
                let entry_recipe_ids = entry.hidden_params.iter().map(|param| param.recipe_id.as_str()).collect::<BTreeSet<_>>();

                verify_spawns::verify_entry_spawns(&entry_id, entry)?;

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
                        || recipe.route_proof_id != param.route_proof_id
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
                        || recipe.route_proof_id != witness.route_proof_id
                    {
                        return Err(TemplatePlanError::EntryWitnessRecipeMismatch {
                            entry: entry_id.clone(),
                            param: witness.param.clone(),
                            recipe_id: witness.recipe_id.clone(),
                        });
                    }
                }

                self.verify_route_recipe_ids(&entry_id, &entry.route_plan.witness_recipe_ids, &entry_recipe_ids, &recipes_by_id)?;
                for route in &entry.routes {
                    if let RouteSuccessorArtifact::Constructed { actor, template_id, .. } = &route.successor {
                        self.verify_route_template(&entry_id, actor, template_id, &templates_by_id)?;
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
        templates_by_id: &std::collections::BTreeMap<&str, &TemplateReceiptArtifact>,
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
        recipes_by_id: &std::collections::BTreeMap<&str, &WitnessRecipeArtifact>,
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

/// Verifies one exported actor-type handle against its actor, physical layout,
/// compiled template, and compiler-planned route context.
fn verify_actor_type_handle(
    plan: &TemplatePlanArtifact,
    artifact: &Artifact,
    template: &TemplateReceiptArtifact,
    contract_name: &str,
    contract: &SilContractArtifact,
) -> std::result::Result<(), TemplatePlanError> {
    let mismatch = |message| TemplatePlanError::ActorTypeHandleMismatch { id: template.id.clone(), message };

    // An expanded actor exposes its base state through the external handle.
    // Other actors expose their owned state directly.
    let actor = artifact
        .argent
        .actors
        .iter()
        .find(|actor| actor.name == template.actor)
        .ok_or_else(|| mismatch(format!("missing actor `{}`", template.actor)))?;
    let expanded_base = artifact
        .argent
        .state_expansions
        .iter()
        .find(|expansion| expansion.state == actor.state)
        .map(|expansion| expansion.base.as_str());
    let source_state = expanded_base.unwrap_or(&actor.state);

    let handle = &template.actor_type_handle;
    if source_state != handle.state {
        return Err(mismatch(format!(
            "handle state `{}` does not match actor `{}` (base) state `{source_state}`",
            handle.state, actor.name,
        )));
    }

    // Split the physical state into leading compiler-owned context and the
    // source state that remains open in the handle.
    let runtime_plan = plan.runtime_states.iter().find(|runtime_state| runtime_state.contract == contract_name);
    let expected_context_fields = runtime_plan
        .map(|runtime_state| runtime_state.field_roles.iter().map(|field| field.name.clone()).collect::<Vec<_>>())
        .unwrap_or_default();
    if handle.context_fields != expected_context_fields {
        return Err(mismatch(format!(
            "context fields {:?} do not match compiler-owned runtime fields {:?}",
            handle.context_fields, expected_context_fields
        )));
    }
    let leading_runtime_fields = contract.runtime_state.fields.iter().take(handle.context_fields.len()).collect::<Vec<_>>();
    if leading_runtime_fields.len() != handle.context_fields.len()
        || leading_runtime_fields.iter().zip(&handle.context_fields).any(|(field, expected_name)| field.name != *expected_name)
    {
        return Err(mismatch("context fields are not the leading physical runtime fields".to_string()));
    }
    let handle_state = artifact
        .argent
        .states
        .iter()
        .find(|state| state.name == handle.state)
        .ok_or_else(|| mismatch(format!("missing Argent state layout `{}`", handle.state)))?;
    let open_runtime_fields = &contract.runtime_state.fields[handle.context_fields.len()..];
    if open_runtime_fields.len() != handle_state.fields.len()
        || open_runtime_fields
            .iter()
            .zip(&handle_state.fields)
            .any(|(runtime, source)| runtime.name != source.name || runtime.ty != source.ty)
    {
        return Err(mismatch(format!("runtime fields after the fixed context do not match Argent state layout `{}`", handle.state)));
    }

    // The handle keeps the compiled suffix and extends only the compiled
    // prefix. Its hash must commit to this new template cut.
    let (sil_prefix, _, sil_suffix) = contract
        .compiled
        .script_parts(&contract.compiled.bytecode)
        .ok_or_else(|| mismatch("Sil state span is outside the compiled contract script".to_string()))?;
    let handle_prefix = &handle.template.prefix;
    let handle_suffix = &handle.template.suffix;
    let handle_hash = handle.template.hash;
    if !handle_prefix.starts_with(sil_prefix) {
        return Err(mismatch("prefix does not extend the Sil template prefix".to_string()));
    }
    if handle_suffix != sil_suffix {
        return Err(mismatch("suffix differs from the Sil template suffix".to_string()));
    }
    let expected_handle_hash = silverscript_abi::template_hash(handle_prefix, handle_suffix);
    if handle_hash != expected_handle_hash {
        return Err(mismatch(format!(
            "template hash does not match its prefix and suffix: expected `{}`, found `{}`",
            encode_hex(&expected_handle_hash),
            encode_hex(&handle.template.hash)
        )));
    }

    let context_state =
        RuntimeStateArtifact { source: handle.state.clone(), fields: leading_runtime_fields.into_iter().cloned().collect() };
    let context_script = &handle_prefix[sil_prefix.len()..];

    // Round-trip the prefix context through its typed layout to reject invalid
    // or noncanonical bytes; the template hash commits to this exact encoding.
    let decoded_context = silverscript_abi::decode_runtime_state_script(&artifact.sil_abi, &context_state, context_script)
        .map_err(|err| mismatch(format!("prefix context does not decode according to its runtime fields: {err}")))?;
    let canonical_context = silverscript_abi::encode_runtime_state_script(&artifact.sil_abi, &context_state, &decoded_context)
        .map_err(|err| mismatch(format!("prefix context cannot be canonically encoded: {err}")))?;
    if canonical_context != context_script {
        return Err(mismatch("prefix context is not canonically encoded".to_string()));
    }
    // Finally, compare the actual commitments with the planned routes.
    if let Some(runtime_plan) = runtime_plan {
        for field in &runtime_plan.field_roles {
            let expected = fixed_runtime_context_value(plan, runtime_plan, field)?;
            if decoded_context.get(&field.name) != Some(&silverscript_abi::ArtifactValue::Bytes(expected)) {
                return Err(mismatch(format!("context field `{}` does not contain its canonical commitment", field.name)));
            }
        }
    }
    Ok(())
}

/// Resolve one compiler-owned runtime field whose value is fixed by the
/// artifact's canonical route plan.
pub fn fixed_runtime_context_value(
    plan: &(impl TemplatePlanLookup + ?Sized),
    runtime_state: &RuntimeStatePlanArtifact,
    field: &RuntimeFieldRolePlanArtifact,
) -> std::result::Result<Vec<u8>, TemplatePlanError> {
    let invalid = |message| TemplatePlanError::RuntimeStatePlanMismatch {
        contract: runtime_state.contract.clone(),
        message: format!("field `{}` cannot be fixed as template context: {message}", field.name),
    };
    match &field.role {
        RuntimeFieldRoleArtifact::Template { contract } => sil_template_hash_bytes(plan, contract),
        RuntimeFieldRoleArtifact::TemplateTable { contracts } => {
            let mut table = Vec::with_capacity(contracts.len() * 32);
            for contract in contracts {
                table.extend_from_slice(&sil_template_hash_bytes(plan, contract)?);
            }
            Ok(table)
        }
        RuntimeFieldRoleArtifact::TemplateDigest { id } => {
            let family = plan
                .route_families()
                .iter()
                .find(|family| family.id == *id)
                .ok_or_else(|| invalid(format!("missing route family `{id}`")))?;
            let table = plan
                .route_tables()
                .iter()
                .find(|table| table.id == family.table_id)
                .ok_or_else(|| invalid(format!("missing route table `{}`", family.table_id)))?;
            let bytes = fixed_route_table_bytes(plan, runtime_state, table)?;
            Ok(blake3::hash(&bytes).as_bytes().to_vec())
        }
        RuntimeFieldRoleArtifact::TemplateRoot { .. } => {
            let proof_id = route_template_proof_receipt_id(&runtime_state.source, &field.name);
            let proof = plan
                .route_proofs()
                .iter()
                .find(|proof| proof.id == proof_id)
                .ok_or_else(|| invalid(format!("missing route proof `{proof_id}`")))?;
            Ok(decode_hash_hex(&proof_id, &proof.root_hex)?.to_vec())
        }
    }
}

fn fixed_route_table_bytes(
    plan: &(impl TemplatePlanLookup + ?Sized),
    runtime_state: &RuntimeStatePlanArtifact,
    table: &RouteTemplateTableArtifact,
) -> std::result::Result<Vec<u8>, TemplatePlanError> {
    let mut bytes = Vec::with_capacity(table.byte_len);
    for entry in &table.entries {
        match &entry.leaf {
            RouteTemplateLeafArtifact::Template { actor, .. } => {
                bytes.extend_from_slice(&sil_template_hash_bytes(plan, actor)?);
            }
            RouteTemplateLeafArtifact::RouteFamily { family_id, .. } => {
                return Err(TemplatePlanError::RuntimeStatePlanMismatch {
                    contract: runtime_state.contract.clone(),
                    message: format!("field `{}` route table `{}` contains nested family `{family_id}`", table.field, table.id),
                });
            }
        }
    }
    Ok(bytes)
}

fn sil_template_hash_bytes(plan: &(impl TemplateHashLookup + ?Sized), actor: &str) -> std::result::Result<Vec<u8>, TemplatePlanError> {
    let template = plan.template_hash_by_actor(actor).ok_or_else(|| TemplatePlanError::UnknownContract(actor.to_string()))?;
    Ok(template.hash.to_vec())
}

pub fn actor_interface_id(actor: &str) -> String {
    format!("interface/actor/{actor}")
}

pub fn actor_interface_fingerprint_hex(
    actor: &str,
    state: &str,
    runtime_fields: &[RuntimeFieldArtifact],
) -> std::result::Result<String, ArtifactIdentityError> {
    #[derive(Serialize)]
    struct ActorInterfaceFingerprint<'a> {
        kind: &'static str,
        actor: &'a str,
        state: &'a str,
        runtime_fields: &'a [RuntimeFieldArtifact],
    }

    hash_json("argent/interface/actor/v1", &ActorInterfaceFingerprint { kind: "actor", actor, state, runtime_fields })
}

fn hash_json<T: Serialize>(domain: &'static str, value: &T) -> std::result::Result<String, ArtifactIdentityError> {
    let json = serde_json::to_vec(value).map_err(|source| ArtifactIdentityError::Serialize { subject: domain, source })?;
    let hash = blake2b_simd::Params::new().hash_length(32).to_state().update(domain.as_bytes()).update(&json).finalize();
    Ok(encode_hex(hash.as_bytes()))
}

pub fn route_template_table_receipt_id(state: &str, field: &str) -> String {
    format!("route_table/{state}/{field}")
}

pub fn route_template_proof_receipt_id(state: &str, field: &str) -> String {
    format!("route_proof/{state}/{field}")
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
    templates: &(impl TemplateHashLookup + ?Sized),
    digest_roots: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<[u8; 32], TemplatePlanError> {
    match leaf {
        RouteTemplateLeafArtifact::Template { actor, template_id } => {
            let Some(template) = templates.template_hash_by_id(template_id) else {
                return Err(TemplatePlanError::MissingRouteTableTemplate {
                    id: table_id.to_string(),
                    actor: actor.clone(),
                    template_id: template_id.clone(),
                });
            };
            if template.actor != actor {
                return Err(TemplatePlanError::RouteTableTemplateMismatch {
                    id: table_id.to_string(),
                    actor: actor.clone(),
                    template_id: template_id.clone(),
                    template_actor: template.actor.to_string(),
                });
            }
            Ok(*template.hash)
        }
        RouteTemplateLeafArtifact::RouteFamily { family_id, proof_id } => {
            let Some(root_hex) = digest_roots.get(proof_id) else {
                return Err(TemplatePlanError::RouteTableFamilyProofMismatch {
                    id: table_id.to_string(),
                    family_id: family_id.clone(),
                    proof_id: proof_id.clone(),
                    expected: String::new(),
                });
            };
            decode_hash_hex(proof_id, root_hex)
        }
    }
}

pub fn route_template_proof_from_table(
    table: &RouteTemplateTableArtifact,
    templates: &(impl TemplateHashLookup + ?Sized),
    digest_roots: &std::collections::BTreeMap<String, String>,
) -> std::result::Result<RouteTemplateProofArtifact, TemplatePlanError> {
    let mut leaf_hashes = Vec::with_capacity(table.entries.len());
    let mut leaves = Vec::with_capacity(table.entries.len());
    for entry in &table.entries {
        let leaf_hash = route_template_leaf_hash(&table.id, &entry.leaf, templates, digest_roots)?;
        leaf_hashes.push(leaf_hash);
    }

    let layers = route_template_merkle_layers(&leaf_hashes);
    let root_hex = route_template_merkle_root_hex(&layers);
    for (position, (entry, template_hash)) in table.entries.iter().zip(leaf_hashes.iter()).enumerate() {
        leaves.push(RouteTemplateProofLeafArtifact {
            index: entry.index,
            leaf: entry.leaf.clone(),
            hash_hex: encode_hex(template_hash),
            proof: route_template_merkle_proof(&layers, position),
        });
    }

    Ok(RouteTemplateProofArtifact {
        id: route_template_proof_receipt_id(&table.state, &table.field),
        table_id: table.id.clone(),
        state: table.state.clone(),
        field: table.field.clone(),
        root_hex,
        leaves,
    })
}

fn verify_route_template_proof(
    proof: &RouteTemplateProofArtifact,
    table: &RouteTemplateTableArtifact,
    templates: &(impl TemplateHashLookup + ?Sized),
    route_proofs_by_id: &std::collections::BTreeMap<&str, &RouteTemplateProofArtifact>,
) -> std::result::Result<(), TemplatePlanError> {
    let expected_id = route_template_proof_receipt_id(&table.state, &table.field);
    if proof.id != expected_id
        || proof.table_id != table.id
        || proof.state != table.state
        || proof.field != table.field
        || proof.leaves.len() != table.entries.len()
    {
        return Err(TemplatePlanError::RouteProofTableMismatch { id: proof.id.clone(), table_id: proof.table_id.clone() });
    }

    let digest_roots = route_proofs_by_id
        .iter()
        .map(|(id, proof)| ((*id).to_string(), proof.root_hex.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut expected_leaf_hashes = Vec::with_capacity(table.entries.len());
    for entry in &table.entries {
        expected_leaf_hashes.push(route_template_leaf_hash(&table.id, &entry.leaf, templates, &digest_roots)?);
    }
    let expected_layers = route_template_merkle_layers(&expected_leaf_hashes);
    let expected_root_hex = route_template_merkle_root_hex(&expected_layers);
    if proof.root_hex != expected_root_hex {
        return Err(TemplatePlanError::RouteProofRootMismatch {
            id: proof.id.clone(),
            expected: expected_root_hex,
            found: proof.root_hex.clone(),
        });
    }

    let root = decode_hash_hex(&proof.id, &proof.root_hex)?;
    for (index, (leaf, entry)) in proof.leaves.iter().zip(table.entries.iter()).enumerate() {
        if leaf.index != entry.index || leaf.leaf != entry.leaf {
            return Err(TemplatePlanError::RouteProofTableMismatch { id: proof.id.clone(), table_id: proof.table_id.clone() });
        }
        if let RouteTemplateLeafArtifact::RouteFamily { family_id, proof_id } = &leaf.leaf
            && proof_id == &proof.id
        {
            return Err(TemplatePlanError::RecursiveRouteFamilyLeaf { id: proof.id.clone(), family_id: family_id.clone() });
        }
        let expected_hash_hex = encode_hex(&expected_leaf_hashes[index]);
        if leaf.hash_hex != expected_hash_hex {
            return Err(TemplatePlanError::RouteProofLeafHashMismatch {
                id: proof.id.clone(),
                index,
                expected: expected_hash_hex,
                found: leaf.hash_hex.clone(),
            });
        }
        let expected_proof = route_template_merkle_proof(&expected_layers, index);
        if leaf.proof != expected_proof {
            let resolved = route_template_merkle_proof_root(&proof.id, &leaf.hash_hex, &leaf.proof)?;
            return Err(TemplatePlanError::RouteProofMismatch {
                id: proof.id.clone(),
                index,
                expected: encode_hex(&root),
                found: encode_hex(&resolved),
            });
        }
        let resolved = route_template_merkle_proof_root(&proof.id, &leaf.hash_hex, &leaf.proof)?;
        if resolved != root {
            return Err(TemplatePlanError::RouteProofMismatch {
                id: proof.id.clone(),
                index,
                expected: encode_hex(&root),
                found: encode_hex(&resolved),
            });
        }
    }

    Ok(())
}

fn route_template_merkle_layers(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
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
            next.push(route_template_merkle_parent(&left, &right));
        }
        layers.push(next);
    }
    layers
}

fn route_template_merkle_root_hex(layers: &[Vec<[u8; 32]>]) -> String {
    layers.last().and_then(|layer| layer.first()).map(|hash| encode_hex(hash)).unwrap_or_else(route_template_empty_merkle_root_hex)
}

fn route_template_empty_merkle_root_hex() -> String {
    encode_hex(blake3::hash(&[]).as_bytes())
}

fn route_template_merkle_proof(layers: &[Vec<[u8; 32]>], mut index: usize) -> Vec<RouteTemplateProofStepArtifact> {
    let mut proof = Vec::new();
    for layer in layers.iter().take(layers.len().saturating_sub(1)) {
        let is_left_child = index.is_multiple_of(2);
        let sibling_index = if is_left_child { (index + 1).min(layer.len() - 1) } else { index - 1 };
        proof.push(RouteTemplateProofStepArtifact {
            side: if is_left_child { RouteTemplateProofSideArtifact::Right } else { RouteTemplateProofSideArtifact::Left },
            hash_hex: encode_hex(&layer[sibling_index]),
        });
        index /= 2;
    }
    proof
}

fn route_template_merkle_proof_root(
    id: &str,
    leaf_hash_hex: &str,
    proof: &[RouteTemplateProofStepArtifact],
) -> std::result::Result<[u8; 32], TemplatePlanError> {
    let mut resolved = decode_hash_hex(id, leaf_hash_hex)?;
    for step in proof {
        let sibling = decode_hash_hex(id, &step.hash_hex)?;
        resolved = match step.side {
            RouteTemplateProofSideArtifact::Left => route_template_merkle_parent(&sibling, &resolved),
            RouteTemplateProofSideArtifact::Right => route_template_merkle_parent(&resolved, &sibling),
        };
    }
    Ok(resolved)
}

fn route_template_merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    blake3::Hasher::new().update(left).update(right).finalize().into()
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
    fn route_commitments_use_blake3() {
        assert_eq!(route_template_empty_merkle_root_hex(), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

        let left = [0x11; 32];
        let right = [0x22; 32];
        let expected = blake3::Hasher::new().update(&left).update(&right).finalize();
        assert_eq!(route_template_merkle_parent(&left, &right), *expected.as_bytes());
    }

    #[test]
    fn interaction_cardinality_defaults_to_one_and_serializes_ranges() {
        let singleton =
            ConsumeArtifact { name: "owner".to_string(), actor: "Account".to_string(), cardinality: CardinalityArtifact::One };
        let singleton_json = serde_json::to_value(&singleton).expect("singleton serializes");
        assert!(singleton_json.get("cardinality").is_none());

        let legacy: ConsumeArtifact = serde_json::from_value(serde_json::json!({
            "name": "owner",
            "actor": "Account"
        }))
        .expect("artifact without cardinality deserializes");
        assert_eq!(legacy.cardinality, CardinalityArtifact::One);

        let range = ConsumeArtifact {
            name: "accounts".to_string(),
            actor: "Account".to_string(),
            cardinality: CardinalityArtifact::Range { minimum: 1, maximum: 3 },
        };
        let range_json = serde_json::to_value(&range).expect("range serializes");
        assert_eq!(
            range_json["cardinality"],
            serde_json::json!({
                "kind": "range",
                "minimum": 1,
                "maximum": 3
            })
        );
        assert_eq!(serde_json::from_value::<ConsumeArtifact>(range_json).expect("range round trips"), range);
    }

    #[test]
    fn lowers_fixed_bytes_as_structural_type() {
        assert_eq!(TypeArtifact::from_parts("byte", Some(32)), TypeArtifact::FixedBytes { len: 32 });
    }

    #[test]
    fn lowers_fixed_non_byte_arrays_as_structural_type() {
        assert_eq!(TypeArtifact::from_parts("int", Some(3)), TypeArtifact::FixedArray { item: Box::new(TypeArtifact::Int), len: 3 });
    }

    #[test]
    fn formats_argent_template_bytes_compactly() {
        let template = ActorTemplateArtifact { prefix: vec![1, 2, 3], suffix: Vec::new(), hash: [4; 32] };
        let json = silverscript_abi::to_pretty_json(&template).expect("template serializes");

        assert!(json.contains(r#""prefix": [1, 2, 3]"#));
        assert!(json.contains(r#""suffix": []"#));
        assert!(
            json.contains(
                r#""hash": [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]"#
            )
        );
    }

    #[test]
    fn route_successor_artifacts_keep_constructed_only_fields_nested() {
        let exact = RouteArtifact { output: "next".to_string(), successor: RouteSuccessorArtifact::ExactSelf };
        let exact_json = serde_json::to_value(exact).expect("exact route serializes");
        assert_eq!(exact_json["successor"]["kind"], "exact_self");
        assert!(exact_json["successor"].get("actor").is_none());
        assert!(exact_json["successor"].get("template_id").is_none());
        assert!(exact_json["successor"].get("state_expr").is_none());

        let constructed = RouteArtifact {
            output: "next".to_string(),
            successor: RouteSuccessorArtifact::Constructed {
                actor: "Peer".to_string(),
                template_id: "template/peer".to_string(),
                state_expr: "next_peer".to_string(),
            },
        };
        let constructed_json = serde_json::to_value(constructed).expect("constructed route serializes");
        assert_eq!(constructed_json["successor"]["kind"], "constructed");
        assert_eq!(constructed_json["successor"]["actor"], "Peer");
        assert!(constructed_json.get("actor").is_none());
    }

    #[test]
    fn deserializes_portable_artifact_without_compiler_ast_values() {
        let json = r#"
        {
          "schema_version": 1,
          "generator": { "name": "argentc", "version": "0.1.0" },
          "app": "Tiny",
          "dependencies": [],
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
                "abi": { "contract": "Foo" },
                "entries": []
              }
            ]
          },
          "sil_abi": {
            "schema_version": 1,
            "compiler_version": "test",
            "structs": {
              "FooState": {
                "fields": [{ "name": "owner", "type": { "kind": "fixed_bytes", "len": 32 } }]
              }
            },
            "contracts": {
              "Foo": {
                "source_path": "sil/Foo.sil",
                "runtime_state": {
                  "source": "State",
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
                "entries": {},
                "cov_decl_to_abi": {},
                "delegate_entry_abi": null,
                "compiled": {
                  "bytecode": [],
                  "template_hash": [
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0
                  ],
                  "state_span": { "offset": 0, "len": 0 }
                }
              }
            }
          }
        }
        "#;

        let artifact: Artifact = serde_json::from_str(json).expect("artifact should deserialize");
        artifact.check_schema_version().expect("schema version should be supported");
        assert_eq!(artifact.argent.actors[0].abi.contract, "Foo");
        assert_eq!(artifact.argent.template_plan.runtime_states[0].field_roles[0].name, "gen__foo_template");
        assert!(artifact.sil_abi.contract("Foo").expect("Foo contract exists").compiled.bytecode.is_empty());
    }

    #[test]
    fn artifact_id_is_independent_of_root_and_module_paths() {
        let mut first = artifact_with_route_families(Vec::new());
        first.root = "checkout-a/app.ag".to_string();
        first.modules = vec!["checkout-a/app.ag".to_string(), "checkout-a/types.ag".to_string()];

        let mut second = first.clone();
        second.root = "/workspace/checkout-b/app.ag".to_string();
        second.modules = vec!["/workspace/checkout-b/app.ag".to_string(), "/workspace/checkout-b/types.ag".to_string()];

        assert_ne!(first.root, second.root);
        assert_ne!(first.modules, second.modules);
        assert_eq!(first.computed_id_hex().expect("first id computes"), second.computed_id_hex().expect("second id computes"));
    }

    #[test]
    fn artifact_id_binds_direct_dependency_ids() {
        let first = artifact_with_route_families(Vec::new());
        let mut second = first.clone();
        second.dependencies.push(AppDependencyArtifact { app: "Dependency".to_string(), artifact_id: "11".repeat(32) });

        assert_ne!(first.computed_id_hex().expect("first id computes"), second.computed_id_hex().expect("second id computes"));
    }

    #[test]
    fn aggregate_verification_accepts_a_valid_artifact() {
        let mut artifact = empty_artifact();
        artifact.id = artifact.computed_id_hex().expect("artifact id computes");

        artifact.check_consistency().expect("complete artifact is consistent");
    }

    #[test]
    fn aggregate_verification_checks_template_plan_before_identity() {
        let mut artifact = empty_artifact();
        artifact.argent.template_plan.templates.push(TemplateReceiptArtifact {
            id: "template/missing".to_string(),
            actor: "Missing".to_string(),
            contract: "Missing".to_string(),
            symbol: "gen__missing_template".to_string(),
            sil_template_hash: [0; 32],
            actor_type_handle: ActorTypeHandleArtifact {
                state: "MissingState".to_string(),
                context_fields: Vec::new(),
                template: ActorTemplateArtifact { prefix: Vec::new(), suffix: Vec::new(), hash: [0; 32] },
            },
        });

        assert!(matches!(
            artifact.check_consistency(),
            Err(ArtifactVerificationError::TemplatePlan(TemplatePlanError::UnknownContract(contract)))
                if contract == "Missing"
        ));
    }

    #[test]
    fn aggregate_verification_checks_identity_last() {
        let artifact = empty_artifact();

        assert!(matches!(
            artifact.check_consistency(),
            Err(ArtifactVerificationError::Identity(ArtifactIdentityError::MissingArtifactId { app }))
                if app == "Tiny"
        ));
    }

    #[test]
    fn rejects_unknown_argent_schema_version() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION + 1,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            dependencies: Vec::new(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: Vec::new(),
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                compiler_version: "test".to_string(),
                structs: std::collections::BTreeMap::new(),
                contracts: std::collections::BTreeMap::new(),
            },
        };

        let err = artifact.check_schema_version().expect_err("future schema must be rejected");
        assert_eq!(err.artifact, "Argent artifact");
        assert_eq!(err.found, ARTIFACT_SCHEMA_VERSION + 1);
    }

    #[test]
    fn rejects_unknown_sil_abi_schema_version() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            dependencies: Vec::new(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: Vec::new(),
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION + 1,
                compiler_version: "test".to_string(),
                structs: std::collections::BTreeMap::new(),
                contracts: std::collections::BTreeMap::new(),
            },
        };

        let err = artifact.check_schema_version().expect_err("future Sil ABI schema must be rejected");
        assert_eq!(err.artifact, "Sil ABI artifact");
        assert_eq!(err.found, SIL_ABI_SCHEMA_VERSION + 1);
    }

    #[test]
    fn accepts_sil_contract_without_runtime_state_plan() {
        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            dependencies: Vec::new(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: Vec::new(),
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                compiler_version: "test".to_string(),
                structs: std::collections::BTreeMap::new(),
                contracts: std::collections::BTreeMap::from([(
                    "Foo".to_string(),
                    SilContractArtifact {
                        source_path: "sil/Foo.sil".to_string(),
                        runtime_state: RuntimeStateArtifact { source: "State".to_string(), fields: Vec::new() },
                        entries: std::collections::BTreeMap::new(),
                        cov_decl_to_abi: std::collections::BTreeMap::new(),
                        delegate_entry_abi: None,
                        compiled: CompiledContractArtifact {
                            bytecode: Vec::new(),
                            template_hash: [0; 32],
                            state_span: StateSpanArtifact { offset: 0, len: 0 },
                        },
                    },
                )]),
            },
        };

        artifact.check_template_plan_consistency().expect("missing runtime state plan means all fields are source");
    }

    #[test]
    fn rejects_duplicate_actor_in_route_family_receipt() {
        let artifact = artifact_with_route_families(vec![RouteTemplateFamilyArtifact {
            id: "route_family/BoardState/mux".to_string(),
            state: "BoardState".to_string(),
            representative_actor: "Mux".to_string(),
            entry_actors: vec!["Mux".to_string()],
            table_id: "route_table/BoardState/gen__mux_routes".to_string(),
            actors: vec!["Mux".to_string(), "Mux".to_string()],
        }]);

        let err = artifact.check_template_plan_consistency().expect_err("duplicate actor must be rejected");
        assert_eq!(
            err,
            TemplatePlanError::DuplicateRouteFamilyActor { id: "route_family/BoardState/mux".to_string(), actor: "Mux".to_string() }
        );
    }

    #[test]
    fn rejects_route_family_representative_outside_the_family() {
        let artifact = artifact_with_route_families(vec![RouteTemplateFamilyArtifact {
            id: "route_family/BoardState/unknown".to_string(),
            state: "BoardState".to_string(),
            representative_actor: "Unknown".to_string(),
            entry_actors: Vec::new(),
            table_id: "route_table/BoardState/gen__unknown_routes".to_string(),
            actors: vec!["Mux".to_string(), "Player".to_string()],
        }]);

        let err = artifact.check_template_plan_consistency().expect_err("foreign representative must be rejected");
        assert_eq!(
            err,
            TemplatePlanError::RouteFamilyRepresentativeOutsideFamily {
                id: "route_family/BoardState/unknown".to_string(),
                representative: "Unknown".to_string(),
            }
        );
    }

    #[test]
    fn rejects_route_family_state_mismatch() {
        let artifact = artifact_with_route_families(vec![RouteTemplateFamilyArtifact {
            id: "route_family/BoardState/mux".to_string(),
            state: "BoardState".to_string(),
            representative_actor: "Mux".to_string(),
            entry_actors: vec!["Mux".to_string()],
            table_id: "route_table/BoardState/gen__mux_routes".to_string(),
            actors: vec!["Mux".to_string(), "Player".to_string()],
        }]);

        let err = artifact.check_template_plan_consistency().expect_err("state mismatch must be rejected");
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

    #[test]
    fn rejects_nested_route_family_table_leaf() {
        let template_hash_hex = "00".repeat(32);
        let templates = ["Mux", "Pawn", "Knight", "Bishop"]
            .into_iter()
            .map(|actor| TemplateReceiptArtifact {
                id: test_template_receipt_id(actor),
                actor: actor.to_string(),
                contract: actor.to_string(),
                symbol: format!("gen__{}_template", actor.to_ascii_lowercase()),
                sil_template_hash: [0; 32],
                actor_type_handle: ActorTypeHandleArtifact {
                    state: "BoardState".to_string(),
                    context_fields: Vec::new(),
                    template: ActorTemplateArtifact { prefix: Vec::new(), suffix: Vec::new(), hash: [0; 32] },
                },
            })
            .collect::<Vec<_>>();

        let inner_family_id = "route_family/BoardState/knight".to_string();
        let inner_table = RouteTemplateTableArtifact {
            id: route_template_table_receipt_id("BoardState", "gen__knight_routes"),
            state: "BoardState".to_string(),
            field: "gen__knight_routes".to_string(),
            byte_len: 32,
            entries: vec![RouteTemplateTableEntryArtifact {
                index: 0,
                offset: 0,
                leaf: RouteTemplateLeafArtifact::Template {
                    actor: "Bishop".to_string(),
                    template_id: test_template_receipt_id("Bishop"),
                },
            }],
        };
        let inner_proof = route_template_proof_from_table(&inner_table, templates.as_slice(), &std::collections::BTreeMap::new())
            .expect("inner proof is valid");

        let outer_table = RouteTemplateTableArtifact {
            id: route_template_table_receipt_id("BoardState", "gen__mux_routes"),
            state: "BoardState".to_string(),
            field: "gen__mux_routes".to_string(),
            byte_len: 64,
            entries: vec![
                RouteTemplateTableEntryArtifact {
                    index: 0,
                    offset: 0,
                    leaf: RouteTemplateLeafArtifact::Template {
                        actor: "Pawn".to_string(),
                        template_id: test_template_receipt_id("Pawn"),
                    },
                },
                RouteTemplateTableEntryArtifact {
                    index: 1,
                    offset: 32,
                    leaf: RouteTemplateLeafArtifact::RouteFamily {
                        family_id: inner_family_id.clone(),
                        proof_id: inner_proof.id.clone(),
                    },
                },
            ],
        };
        let digest_roots = std::collections::BTreeMap::from([(inner_proof.id.clone(), inner_proof.root_hex.clone())]);
        let outer_proof =
            route_template_proof_from_table(&outer_table, templates.as_slice(), &digest_roots).expect("outer proof is valid");

        let artifact = Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "NestedFamily".to_string(),
            dependencies: Vec::new(),
            root: "nested.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: templates
                    .iter()
                    .map(|template| TemplateRefArtifact {
                        id: template.id.clone(),
                        actor: template.actor.clone(),
                        symbol: template.symbol.clone(),
                    })
                    .collect(),
                interfaces: InterfaceSetArtifact::default(),
                template_plan: TemplatePlanArtifact {
                    templates,
                    runtime_states: vec![
                        RuntimeStatePlanArtifact {
                            contract: "Mux".to_string(),
                            source: "BoardState".to_string(),
                            field_roles: vec![RuntimeFieldRolePlanArtifact {
                                name: "gen__mux_routes".to_string(),
                                role: RuntimeFieldRoleArtifact::TemplateRoot {
                                    leaves: vec![
                                        RuntimeRouteLeafArtifact::Contract { contract: "Pawn".to_string() },
                                        RuntimeRouteLeafArtifact::Digest { id: inner_family_id.clone() },
                                    ],
                                },
                            }],
                        },
                        RuntimeStatePlanArtifact {
                            contract: "Knight".to_string(),
                            source: "BoardState".to_string(),
                            field_roles: vec![RuntimeFieldRolePlanArtifact {
                                name: "gen__knight_routes".to_string(),
                                role: RuntimeFieldRoleArtifact::TemplateTable { contracts: vec!["Bishop".to_string()] },
                            }],
                        },
                    ],
                    route_tables: vec![outer_table, inner_table],
                    route_proofs: vec![outer_proof, inner_proof],
                    route_families: vec![
                        RouteTemplateFamilyArtifact {
                            id: "route_family/BoardState/mux".to_string(),
                            state: "BoardState".to_string(),
                            representative_actor: "Mux".to_string(),
                            entry_actors: vec!["Mux".to_string()],
                            table_id: route_template_table_receipt_id("BoardState", "gen__mux_routes"),
                            actors: vec!["Mux".to_string(), "Pawn".to_string()],
                        },
                        RouteTemplateFamilyArtifact {
                            id: inner_family_id.clone(),
                            state: "BoardState".to_string(),
                            representative_actor: "Knight".to_string(),
                            entry_actors: vec!["Knight".to_string()],
                            table_id: route_template_table_receipt_id("BoardState", "gen__knight_routes"),
                            actors: vec!["Knight".to_string(), "Bishop".to_string()],
                        },
                    ],
                    witness_recipes: Vec::new(),
                },
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: ["Mux", "Pawn", "Knight", "Bishop"]
                    .into_iter()
                    .map(|actor| ActorArtifact {
                        name: actor.to_string(),
                        state: "BoardState".to_string(),
                        abi: ActorAbiRefArtifact { contract: actor.to_string() },
                        leader_for: Vec::new(),
                        entries: Vec::new(),
                    })
                    .collect(),
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                compiler_version: "test".to_string(),
                structs: std::collections::BTreeMap::new(),
                contracts: std::collections::BTreeMap::from([
                    (
                        "Mux".to_string(),
                        test_contract(
                            "Mux",
                            "BoardState",
                            vec![RuntimeFieldArtifact {
                                name: "gen__mux_routes".to_string(),
                                ty: TypeArtifact::FixedBytes { len: 32 },
                            }],
                            &template_hash_hex,
                        ),
                    ),
                    ("Pawn".to_string(), test_contract("Pawn", "BoardState", Vec::new(), &template_hash_hex)),
                    (
                        "Knight".to_string(),
                        test_contract(
                            "Knight",
                            "BoardState",
                            vec![RuntimeFieldArtifact {
                                name: "gen__knight_routes".to_string(),
                                ty: TypeArtifact::FixedBytes { len: 32 },
                            }],
                            &template_hash_hex,
                        ),
                    ),
                    ("Bishop".to_string(), test_contract("Bishop", "BoardState", Vec::new(), &template_hash_hex)),
                ]),
            },
        };

        let err = artifact.check_template_plan_consistency().expect_err("nested family tables must be rejected");
        assert_eq!(
            err,
            TemplatePlanError::NestedRouteFamilyLeaf {
                id: "route_family/BoardState/mux".to_string(),
                table_id: "route_table/BoardState/gen__mux_routes".to_string(),
                family_id: inner_family_id
            }
        );
    }

    fn artifact_with_route_families(route_families: Vec<RouteTemplateFamilyArtifact>) -> Artifact {
        Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            dependencies: Vec::new(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact { route_families, ..TemplatePlanArtifact::default() },
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: vec![
                    ActorArtifact {
                        name: "Mux".to_string(),
                        state: "BoardState".to_string(),
                        abi: ActorAbiRefArtifact { contract: "Mux".to_string() },
                        leader_for: Vec::new(),
                        entries: Vec::new(),
                    },
                    ActorArtifact {
                        name: "Player".to_string(),
                        state: "PlayerState".to_string(),
                        abi: ActorAbiRefArtifact { contract: "Player".to_string() },
                        leader_for: Vec::new(),
                        entries: Vec::new(),
                    },
                ],
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                compiler_version: "test".to_string(),
                structs: std::collections::BTreeMap::new(),
                contracts: std::collections::BTreeMap::new(),
            },
        }
    }

    fn empty_artifact() -> Artifact {
        Artifact {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            id: String::new(),
            generator: GeneratorArtifact { name: "argentc".to_string(), version: "0.1.0".to_string() },
            app: "Tiny".to_string(),
            dependencies: Vec::new(),
            root: "tiny.ag".to_string(),
            modules: Vec::new(),
            argent: ArgentArtifact {
                templates: Vec::new(),
                template_plan: TemplatePlanArtifact::default(),
                interfaces: InterfaceSetArtifact::default(),
                states: Vec::new(),
                state_expansions: Vec::new(),
                actor_enums: Vec::new(),
                actors: Vec::new(),
            },
            sil_abi: SilAbiArtifact {
                schema_version: SIL_ABI_SCHEMA_VERSION,
                compiler_version: "test".to_string(),
                structs: std::collections::BTreeMap::new(),
                contracts: std::collections::BTreeMap::new(),
            },
        }
    }

    fn test_contract(name: &str, state: &str, fields: Vec<RuntimeFieldArtifact>, template_hash: &str) -> SilContractArtifact {
        SilContractArtifact {
            source_path: format!("sil/{name}.sil"),
            runtime_state: RuntimeStateArtifact { source: state.to_string(), fields },
            entries: std::collections::BTreeMap::new(),
            cov_decl_to_abi: std::collections::BTreeMap::new(),
            delegate_entry_abi: None,
            compiled: CompiledContractArtifact {
                bytecode: Vec::new(),
                template_hash: decode_hash_hex(name, template_hash).expect("test template hash is valid"),
                state_span: StateSpanArtifact { offset: 0, len: 0 },
            },
        }
    }

    fn test_template_receipt_id(actor: &str) -> String {
        format!("template/{}", actor.to_ascii_lowercase())
    }
}
