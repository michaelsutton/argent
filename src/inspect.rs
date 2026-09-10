//! Human-readable inspection of compiled Argent build directories.
//!
//! Reports combine Argent artifact metadata with compiled Sil contract metrics.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

use colored::Colorize;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::parse_script;
use kaspa_txscript::script_builder::ScriptBuilder;

use crate::artifact::{
    Artifact, CardinalityArtifact, EmitArtifact, EntryArtifact, EntryKindArtifact, HiddenParamArtifact, HiddenParamPurposeArtifact,
    HiddenParamSubjectArtifact, ParamArtifact, RouteSuccessorArtifact, SilContractArtifact, SilEntryArtifact, TypeArtifact,
};
use crate::{ArgentError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeEstimate {
    pub min: usize,
    pub max: Option<usize>,
}

impl SizeEstimate {
    fn exact(size: usize) -> Self {
        Self { min: size, max: Some(size) }
    }

    fn range(min: usize, max: usize) -> Self {
        Self { min, max: Some(max) }
    }

    fn variable(min: usize) -> Self {
        Self { min, max: None }
    }

    fn plus(self, other: Self) -> Self {
        Self {
            min: self.min.saturating_add(other.min),
            max: self.max.zip(other.max).and_then(|(left, right)| left.checked_add(right)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionReport {
    pub app: String,
    pub artifact_id: String,
    pub actors: Vec<ActorInspection>,
    pub route_families: usize,
    pub route_tables: usize,
    pub route_proofs: usize,
    pub witness_recipes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorInspection {
    pub name: String,
    pub script_bytes: usize,
    pub state_bytes: usize,
    pub template_bytes: usize,
    pub opcode_count: usize,
    pub entries: Vec<EntryInspection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInspection {
    pub actor: String,
    pub name: String,
    pub kind: EntryKindArtifact,
    pub arguments: Vec<String>,
    pub generated_arguments: Vec<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub routes: Vec<String>,
    pub signature_script_bytes: SizeEstimate,
}

pub fn inspect_path(input: impl AsRef<Path>) -> Result<InspectionReport> {
    let artifact_path = artifact_path(input.as_ref());
    let json = fs::read_to_string(&artifact_path).map_err(|err| ArgentError::at(&artifact_path, err.to_string()))?;
    let artifact =
        serde_json::from_str::<Artifact>(&json).map_err(|err| ArgentError::at(&artifact_path, format!("invalid artifact: {err}")))?;
    inspect_artifact(&artifact).map_err(|err| if err.path.is_none() { ArgentError::at(&artifact_path, err.message) } else { err })
}

pub fn inspect_artifact(artifact: &Artifact) -> Result<InspectionReport> {
    artifact.check_consistency().map_err(|err| ArgentError::new(format!("invalid artifact: {err}")))?;

    let mut actors = Vec::with_capacity(artifact.argent.actors.len());
    for actor in &artifact.argent.actors {
        let contract = artifact.sil_abi.contract(&actor.abi.contract).ok_or_else(|| {
            ArgentError::new(format!("actor `{}` references missing ABI contract `{}`", actor.name, actor.abi.contract))
        })?;
        let script = &contract.compiled.bytecode;
        let opcode_count = opcode_count(&actor.name, script)?;

        let mut entries = Vec::with_capacity(actor.entries.len());
        for entry in &actor.entries {
            let sil_entry = contract.entry(&entry.abi.entry).ok_or_else(|| {
                ArgentError::new(format!(
                    "entry `{}::{}` references missing ABI entry `{}::{}`",
                    actor.name, entry.name, entry.abi.contract, entry.abi.entry
                ))
            })?;
            entries.push(inspect_entry(artifact, &actor.name, contract, entry, sil_entry, script)?);
        }

        actors.push(ActorInspection {
            name: actor.name.clone(),
            script_bytes: script.len(),
            state_bytes: contract.compiled.state_span.len,
            template_bytes: script.len() - contract.compiled.state_span.len,
            opcode_count,
            entries,
        });
    }

    let template_plan = &artifact.argent.template_plan;
    Ok(InspectionReport {
        app: artifact.app.clone(),
        artifact_id: artifact.id.clone(),
        actors,
        route_families: template_plan.route_families.len(),
        route_tables: template_plan.route_tables.len(),
        route_proofs: template_plan.route_proofs.len(),
        witness_recipes: template_plan.witness_recipes.len(),
    })
}

pub fn render_report(report: &InspectionReport) -> String {
    let mut out = String::new();
    writeln!(out, "{} {}", "App".bold(), report.app.bright_cyan().bold()).unwrap();
    writeln!(out, "{} {}", "Artifact".bold(), report.artifact_id.dimmed()).unwrap();
    out.push('\n');
    writeln!(out, "{}", "Actors".bold().underline()).unwrap();

    let actor_width = report.actors.iter().map(|actor| actor.name.len()).max().unwrap_or(5).max(5);
    let heading = format!(
        "  {:<actor_width$}  {:>10}  {:>10}  {:>10}  {:>9}  {:>7}",
        "Actor", "Script", "State", "Template", "Opcodes", "Entries"
    );
    writeln!(out, "{}", heading.dimmed()).unwrap();
    for actor in &report.actors {
        let name = format!("{:<actor_width$}", actor.name).bright_cyan().bold();
        let script = format!("{:>8} B", actor.script_bytes).yellow();
        let state = format!("{:>8} B", actor.state_bytes).yellow();
        let template = format!("{:>8} B", actor.template_bytes).yellow();
        let opcodes = format!("{:>9}", actor.opcode_count).yellow();
        let entries = format!("{:>7}", actor.entries.len()).yellow();
        writeln!(out, "  {name}  {script}  {state}  {template}  {opcodes}  {entries}").unwrap();
    }

    let entries = report.actors.iter().flat_map(|actor| &actor.entries).collect::<Vec<_>>();
    if !entries.is_empty() {
        out.push('\n');
        writeln!(out, "{}", "Entries".bold().underline()).unwrap();
        for entry in entries {
            writeln!(
                out,
                "  {}::{} [{}]",
                entry.actor.bright_cyan().bold(),
                entry.name.bright_green().bold(),
                entry_kind_label(entry.kind).dimmed()
            )
            .unwrap();
            writeln!(out, "    {} {}", "arguments:".bold(), list_or_none(&entry.arguments)).unwrap();
            writeln!(out, "    {} {}", "generated arguments:".bold(), list_or_none(&entry.generated_arguments).dimmed()).unwrap();
            writeln!(out, "    {} {}", "inputs:".bold(), list_or_none(&entry.inputs)).unwrap();
            writeln!(out, "    {} {}", "outputs:".bold(), list_or_none(&entry.outputs)).unwrap();
            writeln!(out, "    {} {}", "routes:".bold(), list_or_none(&entry.routes)).unwrap();
            writeln!(out, "    {} {}", "signature script:".bold(), styled_size_estimate(entry.signature_script_bytes)).unwrap();
        }
    }

    out.push('\n');
    writeln!(out, "{}", "Route metadata".bold().underline()).unwrap();
    writeln!(out, "  {} {}", "families:".bold(), report.route_families.to_string().yellow()).unwrap();
    writeln!(out, "  {} {}", "tables:".bold(), report.route_tables.to_string().yellow()).unwrap();
    writeln!(out, "  {} {}", "proofs:".bold(), report.route_proofs.to_string().yellow()).unwrap();
    writeln!(out, "  {} {}", "witness recipes:".bold(), report.witness_recipes.to_string().yellow()).unwrap();
    out
}

fn artifact_path(input: &Path) -> PathBuf {
    if input.is_dir() { input.join("artifact.json") } else { input.to_path_buf() }
}

fn opcode_count(actor: &str, script: &[u8]) -> Result<usize> {
    let mut count = 0;
    for opcode in parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(script) {
        opcode.map_err(|err| ArgentError::new(format!("actor `{actor}` contains invalid compiled script: {err}")))?;
        count += 1;
    }
    Ok(count)
}

fn inspect_entry(
    artifact: &Artifact,
    actor: &str,
    contract: &SilContractArtifact,
    entry: &EntryArtifact,
    sil_entry: &SilEntryArtifact,
    script: &[u8],
) -> Result<EntryInspection> {
    let hidden_names = entry.hidden_params.iter().map(|hidden| hidden.name.as_str()).collect::<BTreeSet<_>>();
    let arguments = sil_entry.params.iter().filter(|param| !hidden_names.contains(param.name.as_str())).map(param_label).collect();
    let generated_arguments = entry
        .hidden_params
        .iter()
        .map(|hidden| format!("{}: {} ({})", hidden.name, type_label(&hidden.ty), hidden_purpose_label(hidden.purpose)))
        .collect();

    let mut inputs = Vec::new();
    if let Some(active) = &entry.route_plan.active_input {
        inputs.push(format!("{}: {}", active.name, active.actor));
    }
    inputs.extend(
        entry.consumes.iter().map(|input| format!("{}: {}{}", input.name, input.actor, cardinality_suffix(input.cardinality))),
    );

    let outputs = match &entry.emits {
        EmitArtifact::None => Vec::new(),
        EmitArtifact::Outputs { outputs } => outputs
            .iter()
            .map(|output| format!("{} -> {}{}", output.name, output.actors.join(" | "), cardinality_suffix(output.cardinality)))
            .collect(),
    };
    let routes = entry
        .routes
        .iter()
        .map(|route| match &route.successor {
            RouteSuccessorArtifact::ExactSelf => format!("{} -> self", route.output),
            RouteSuccessorArtifact::Constructed { actor, .. } => format!("{} -> {actor}", route.output),
        })
        .collect();

    let mut signature_script_bytes = SizeEstimate::exact(ScriptBuilder::canonical_data_size(script));
    for param in &sil_entry.params {
        let estimate = if let Some(hidden) = entry.hidden_params.iter().find(|hidden| hidden.name == param.name) {
            hidden_param_size(artifact, entry, hidden)?.unwrap_or_else(|| type_size(artifact, contract, &param.ty))
        } else {
            type_size(artifact, contract, &param.ty)
        };
        signature_script_bytes = signature_script_bytes.plus(estimate);
    }
    signature_script_bytes = signature_script_bytes.plus(SizeEstimate::exact(ScriptBuilder::canonical_data_size(&[0; 4])));

    Ok(EntryInspection {
        actor: actor.to_string(),
        name: entry.name.clone(),
        kind: entry.kind,
        arguments,
        generated_arguments,
        inputs,
        outputs,
        routes,
        signature_script_bytes,
    })
}

fn cardinality_suffix(cardinality: CardinalityArtifact) -> String {
    match cardinality {
        CardinalityArtifact::One => String::new(),
        CardinalityArtifact::Range { minimum, maximum } => format!("[{minimum}..={maximum}]"),
    }
}

fn hidden_param_size(artifact: &Artifact, entry: &EntryArtifact, hidden: &HiddenParamArtifact) -> Result<Option<SizeEstimate>> {
    match hidden.purpose {
        HiddenParamPurposeArtifact::TemplatePrefixBytes => estimate_template_parts(artifact, entry, hidden, TemplatePart::Prefix),
        HiddenParamPurposeArtifact::TemplateSuffixBytes => estimate_template_parts(artifact, entry, hidden, TemplatePart::Suffix),
        HiddenParamPurposeArtifact::TemplatePrefixLen => estimate_template_lengths(artifact, entry, hidden, TemplatePart::Prefix),
        HiddenParamPurposeArtifact::TemplateSuffixLen => estimate_template_lengths(artifact, entry, hidden, TemplatePart::Suffix),
        HiddenParamPurposeArtifact::TemplateHash | HiddenParamPurposeArtifact::RouteTemplateLeaf => {
            Ok(Some(SizeEstimate::exact(ScriptBuilder::canonical_data_size(&[0; 32]))))
        }
        HiddenParamPurposeArtifact::RouteTemplateProof => {
            let Some(proof_id) = hidden.route_proof_id.as_deref() else {
                return Ok(None);
            };
            let Some(actor) = concrete_subject_actor(&hidden.subject) else {
                return Ok(None);
            };
            let Some(proof) = artifact.argent.template_plan.route_proofs.iter().find(|proof| proof.id == proof_id) else {
                return Ok(None);
            };
            let Some(leaf) = proof.leaves.iter().find(|leaf| {
                matches!(&leaf.leaf, crate::artifact::RouteTemplateLeafArtifact::Template { actor: leaf_actor, .. } if leaf_actor == actor)
            }) else {
                return Ok(None);
            };
            Ok(Some(pushed_payload_size(leaf.proof.len().saturating_mul(32))))
        }
        HiddenParamPurposeArtifact::RouteFamilyTable => {
            let HiddenParamSubjectArtifact::RouteFamily { family_id } = &hidden.subject else {
                return Ok(None);
            };
            let Some(family) = artifact.argent.template_plan.route_families.iter().find(|family| family.id == *family_id) else {
                return Ok(None);
            };
            let Some(table) = artifact.argent.template_plan.route_tables.iter().find(|table| table.id == family.table_id) else {
                return Ok(None);
            };
            Ok(Some(pushed_payload_size(table.byte_len)))
        }
        HiddenParamPurposeArtifact::RouteFamilyProof => {
            let HiddenParamSubjectArtifact::RouteFamily { family_id } = &hidden.subject else {
                return Ok(None);
            };
            let Some(proof_id) = hidden.route_proof_id.as_deref() else {
                return Ok(None);
            };
            let Some(proof) = artifact.argent.template_plan.route_proofs.iter().find(|proof| proof.id == proof_id) else {
                return Ok(None);
            };
            let Some(leaf) = proof.leaves.iter().find(|leaf| {
                matches!(&leaf.leaf, crate::artifact::RouteTemplateLeafArtifact::RouteFamily {
                    family_id: leaf_family,
                    ..
                } if leaf_family == family_id)
            }) else {
                return Ok(None);
            };
            Ok(Some(pushed_payload_size(leaf.proof.len().saturating_mul(32))))
        }
        HiddenParamPurposeArtifact::StateExpansionPreimage => {
            let HiddenParamSubjectArtifact::StateExpansion { memory_state, .. } = &hidden.subject else {
                return Ok(None);
            };
            let Some(state) = artifact.sil_abi.structs.get(memory_state) else {
                return Ok(None);
            };
            let Some(payload_len) = state
                .fields
                .iter()
                .try_fold(0usize, |total, field| fixed_payload_len(&field.ty).and_then(|len| total.checked_add(len)))
            else {
                return Ok(None);
            };
            Ok(Some(pushed_payload_size(payload_len)))
        }
        HiddenParamPurposeArtifact::SpawnOutputIndex | HiddenParamPurposeArtifact::ObservedOutputFieldValue => Ok(None),
    }
}

#[derive(Clone, Copy)]
enum TemplatePart {
    Prefix,
    Suffix,
}

fn estimate_template_parts(
    artifact: &Artifact,
    entry: &EntryArtifact,
    hidden: &HiddenParamArtifact,
    part: TemplatePart,
) -> Result<Option<SizeEstimate>> {
    let templates = hidden_template_contracts(artifact, entry, &hidden.subject);
    if templates.is_empty() {
        return Ok(None);
    }
    let mut estimates = Vec::with_capacity(templates.len());
    for contract in templates {
        let bytes = template_part(contract, part)?;
        estimates.push(SizeEstimate::exact(ScriptBuilder::canonical_data_size(&bytes)));
    }
    Ok(merge_estimates(&estimates))
}

fn estimate_template_lengths(
    artifact: &Artifact,
    entry: &EntryArtifact,
    hidden: &HiddenParamArtifact,
    part: TemplatePart,
) -> Result<Option<SizeEstimate>> {
    let templates = hidden_template_contracts(artifact, entry, &hidden.subject);
    if templates.is_empty() {
        return Ok(None);
    }
    let mut estimates = Vec::with_capacity(templates.len());
    for contract in templates {
        let bytes = template_part(contract, part)?;
        estimates.push(SizeEstimate::exact(integer_size(bytes.len() as i64)?));
    }
    Ok(merge_estimates(&estimates))
}

fn template_part(contract: &SilContractArtifact, part: TemplatePart) -> Result<Vec<u8>> {
    let (prefix, _, suffix) = contract
        .compiled
        .script_parts(&contract.compiled.bytecode)
        .ok_or_else(|| ArgentError::new(format!("contract `{}` has an invalid state span", contract.source_path)))?;
    Ok(match part {
        TemplatePart::Prefix => prefix.to_vec(),
        TemplatePart::Suffix => suffix.to_vec(),
    })
}

fn hidden_template_contracts<'a>(
    artifact: &'a Artifact,
    entry: &EntryArtifact,
    subject: &HiddenParamSubjectArtifact,
) -> Vec<&'a SilContractArtifact> {
    let actors = match subject {
        HiddenParamSubjectArtifact::Actor { actor }
        | HiddenParamSubjectArtifact::ObservedActor { actor, .. }
        | HiddenParamSubjectArtifact::SpawnActor { actor, .. } => vec![actor.as_str()],
        HiddenParamSubjectArtifact::TemplateSelector { selector } => entry
            .template_selectors
            .iter()
            .find(|candidate| candidate.name == *selector)
            .map(|selector| {
                selector
                    .fixed_actor
                    .as_deref()
                    .map_or_else(|| selector.variants.iter().map(String::as_str).collect(), |actor| vec![actor])
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    actors.into_iter().filter_map(|actor| artifact.sil_abi.contract(actor)).collect()
}

fn concrete_subject_actor(subject: &HiddenParamSubjectArtifact) -> Option<&str> {
    match subject {
        HiddenParamSubjectArtifact::Actor { actor }
        | HiddenParamSubjectArtifact::ObservedActor { actor, .. }
        | HiddenParamSubjectArtifact::SpawnActor { actor, .. } => Some(actor),
        _ => None,
    }
}

fn merge_estimates(estimates: &[SizeEstimate]) -> Option<SizeEstimate> {
    let first = estimates.first()?;
    let min = estimates.iter().map(|estimate| estimate.min).min().unwrap_or(first.min);
    let max = estimates.iter().map(|estimate| estimate.max).collect::<Option<Vec<_>>>()?.into_iter().max();
    Some(SizeEstimate { min, max })
}

fn type_size(artifact: &Artifact, contract: &SilContractArtifact, ty: &TypeArtifact) -> SizeEstimate {
    match ty {
        TypeArtifact::Int | TypeArtifact::Temporal => SizeEstimate::range(1, 9),
        TypeArtifact::Bool => SizeEstimate::exact(1),
        TypeArtifact::Byte => SizeEstimate::range(1, 2),
        TypeArtifact::Bytes | TypeArtifact::Text | TypeArtifact::DynamicArray { .. } => SizeEstimate::variable(1),
        TypeArtifact::Pubkey => pushed_payload_size(32),
        TypeArtifact::Sig => pushed_payload_size(65),
        TypeArtifact::Datasig => pushed_payload_size(64),
        TypeArtifact::FixedBytes { len } => pushed_payload_size(*len),
        TypeArtifact::FixedArray { item, len } => {
            if matches!(item.as_ref(), TypeArtifact::Struct { .. }) {
                SizeEstimate::variable(0)
            } else if let Some(item_len) = fixed_payload_len(item) {
                pushed_payload_size(item_len.saturating_mul(*len))
            } else {
                SizeEstimate::variable(1)
            }
        }
        TypeArtifact::Struct { name } => {
            let fields = if name == "State" {
                contract.runtime_state.fields.iter().map(|field| &field.ty).collect::<Vec<_>>()
            } else {
                artifact
                    .sil_abi
                    .structs
                    .get(name)
                    .map(|state| state.fields.iter().map(|field| &field.ty).collect())
                    .unwrap_or_default()
            };
            if fields.is_empty() {
                SizeEstimate::variable(0)
            } else {
                fields.into_iter().fold(SizeEstimate::exact(0), |total, field| total.plus(type_size(artifact, contract, field)))
            }
        }
    }
}

fn fixed_payload_len(ty: &TypeArtifact) -> Option<usize> {
    match ty {
        TypeArtifact::Int | TypeArtifact::Temporal => Some(8),
        TypeArtifact::Bool | TypeArtifact::Byte => Some(1),
        TypeArtifact::Pubkey => Some(32),
        TypeArtifact::Sig => Some(65),
        TypeArtifact::Datasig => Some(64),
        TypeArtifact::FixedBytes { len } => Some(*len),
        TypeArtifact::FixedArray { item, len } => fixed_payload_len(item)?.checked_mul(*len),
        TypeArtifact::Bytes | TypeArtifact::Text | TypeArtifact::DynamicArray { .. } | TypeArtifact::Struct { .. } => None,
    }
}

fn pushed_payload_size(payload_len: usize) -> SizeEstimate {
    if payload_len == 1 { SizeEstimate::range(1, 2) } else { SizeEstimate::exact(canonical_payload_size(payload_len)) }
}

fn canonical_payload_size(payload_len: usize) -> usize {
    payload_len
        + if payload_len <= 75 {
            1
        } else if payload_len <= u8::MAX as usize {
            2
        } else if payload_len <= u16::MAX as usize {
            3
        } else {
            5
        }
}

fn integer_size(value: i64) -> Result<usize> {
    let mut builder = ScriptBuilder::new();
    builder.add_i64(value).map_err(|err| ArgentError::new(format!("cannot size integer argument `{value}`: {err}")))?;
    Ok(builder.script().len())
}

fn param_label(param: &ParamArtifact) -> String {
    format!("{}: {}", param.name, type_label(&param.ty))
}

fn type_label(ty: &TypeArtifact) -> String {
    match ty {
        TypeArtifact::Int => "int".to_string(),
        TypeArtifact::Temporal => "temporal".to_string(),
        TypeArtifact::Bool => "bool".to_string(),
        TypeArtifact::Byte => "byte".to_string(),
        TypeArtifact::Bytes => "bytes".to_string(),
        TypeArtifact::Text => "string".to_string(),
        TypeArtifact::Pubkey => "pubkey".to_string(),
        TypeArtifact::Sig => "sig".to_string(),
        TypeArtifact::Datasig => "datasig".to_string(),
        TypeArtifact::FixedBytes { len } => format!("byte[{len}]"),
        TypeArtifact::FixedArray { item, len } => format!("{}[{len}]", type_label(item)),
        TypeArtifact::DynamicArray { item } => format!("{}[]", type_label(item)),
        TypeArtifact::Struct { name } => name.clone(),
    }
}

fn hidden_purpose_label(purpose: HiddenParamPurposeArtifact) -> &'static str {
    match purpose {
        HiddenParamPurposeArtifact::SpawnOutputIndex => "spawn output index",
        HiddenParamPurposeArtifact::TemplatePrefixBytes => "template prefix bytes",
        HiddenParamPurposeArtifact::TemplateSuffixBytes => "template suffix bytes",
        HiddenParamPurposeArtifact::TemplatePrefixLen => "template prefix length",
        HiddenParamPurposeArtifact::TemplateSuffixLen => "template suffix length",
        HiddenParamPurposeArtifact::TemplateHash => "template hash",
        HiddenParamPurposeArtifact::RouteTemplateLeaf => "route template leaf",
        HiddenParamPurposeArtifact::RouteTemplateProof => "route template proof",
        HiddenParamPurposeArtifact::RouteFamilyTable => "route family table",
        HiddenParamPurposeArtifact::RouteFamilyProof => "route family proof",
        HiddenParamPurposeArtifact::StateExpansionPreimage => "state expansion preimage",
        HiddenParamPurposeArtifact::ObservedOutputFieldValue => "observed output field",
    }
}

fn entry_kind_label(kind: EntryKindArtifact) -> &'static str {
    match kind {
        EntryKindArtifact::Leader => "leader",
        EntryKindArtifact::Delegate => "delegate",
    }
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() { "none".to_string() } else { values.join(", ") }
}

fn styled_size_estimate(estimate: SizeEstimate) -> colored::ColoredString {
    match estimate.max {
        Some(max) if max == estimate.min => format!("{} B", estimate.min).bright_green(),
        Some(max) => format!("{}-{} B", estimate.min, max).yellow(),
        None => format!(">= {} B (variable)", estimate.min).yellow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSPECT_APP: &str = r#"
state EventState {
    int remaining;
}

state TicketState {
    pubkey owner;
}

actor Event owns EventState {
    entry buy(pubkey owner) emits {
        event: Event,
        ticket: Ticket,
    } {
        unrestricted(event.value);
        unrestricted(ticket.value);
        EventState next_event = {
            remaining: remaining - 1,
        };
        TicketState ticket_state = {
            owner: owner,
        };
        become {
            event <- Event(next_event),
            ticket <- Ticket(ticket_state),
        };
    }
}

actor Ticket owns TicketState {
    entry transfer(pubkey next_owner) emits next: Ticket {
        unrestricted(next.value);
        TicketState next_state = {
            owner: next_owner,
        };
        become next <- Ticket(next_state);
    }
}

app Show {
    actor Event;
    actor Ticket;
}
"#;

    #[test]
    fn inspects_compiled_actor_and_entry_metrics() {
        let out_dir = std::env::temp_dir().join(format!("argent-inspect-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out_dir);
        crate::build_inline("inspect.ag", INSPECT_APP, &out_dir).expect("fixture compiles");
        let report = inspect_path(&out_dir).expect("build directory inspects");

        let event = report.actors.iter().find(|actor| actor.name == "Event").expect("Event report");
        assert_eq!(event.script_bytes, event.state_bytes + event.template_bytes);
        assert!(event.opcode_count > 0);
        let buy = &event.entries[0];
        assert_eq!(buy.arguments, ["owner: pubkey"]);
        assert_eq!(buy.generated_arguments.len(), 2);
        assert_eq!(buy.outputs, ["event -> Event", "ticket -> Ticket"]);
        assert_eq!(buy.routes, ["event -> Event", "ticket -> Ticket"]);
        assert!(matches!(buy.signature_script_bytes.max, Some(max) if max == buy.signature_script_bytes.min));

        let _ = std::fs::remove_dir_all(out_dir);
    }

    #[test]
    fn reports_resolved_input_and_output_cardinality() {
        let artifact = crate::compile_inline(
            "inspect-ranges.ag",
            r#"
                state BatchState {
                    int marker;
                }

                state AccountState {
                    int balance;
                }

                actor Batch owns BatchState {
                    entry inspect(AccountState[] next_states)
                    consumes {
                        accounts: Account[0..=2],
                        tail: Account,
                    }
                    emits {
                        next: Account[1..=3],
                        tail_out: Account,
                    } {
                        unrestricted(next[0].value);
                        unrestricted(tail_out.value);
                        become {
                            next <- Account[](next_states),
                            tail_out <- Account(AccountState {
                                balance: 0,
                            }),
                        };
                    }
                }

                actor Account owns AccountState {
                    entry hold() emits none {
                        require(balance >= 0);
                    }
                }

                app Show {
                    actor Batch;
                    actor Account;
                }
            "#,
        )
        .expect("range fixture compiles");
        let report = inspect_artifact(&artifact).expect("range artifact inspects");
        let batch = report.actors.iter().find(|actor| actor.name == "Batch").expect("Batch report");
        let inspect = batch.entries.iter().find(|entry| entry.name == "inspect").expect("inspect entry");

        assert_eq!(inspect.inputs, ["self: Batch", "accounts: Account[0..=2]", "tail: Account"]);
        assert_eq!(inspect.outputs, ["next -> Account[1..=3]", "tail_out -> Account"]);
    }

    #[test]
    fn reports_variable_numeric_argument_sizes() {
        assert_eq!(type_size_for_test(&TypeArtifact::Int), SizeEstimate::range(1, 9));
        assert_eq!(type_size_for_test(&TypeArtifact::Temporal), SizeEstimate::range(1, 9));
    }

    fn type_size_for_test(ty: &TypeArtifact) -> SizeEstimate {
        let artifact = crate::compile_inline("inspect.ag", INSPECT_APP).expect("fixture compiles");
        let contract = artifact.sil_abi.contract("Event").expect("Event contract");
        type_size(&artifact, contract, ty)
    }
}
