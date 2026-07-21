//! Compiler-facing adaptation from route domains to commitment plans.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::commitment::{CommitmentConstraints, CommitmentPlan, ConstraintError, commitment_plan};
use super::graph::{RouteGraph, components};

/// One planned route family with compiler-ordered component metadata and a
/// canonical table order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyPlan {
    pub domain: String,
    pub rep: String,
    pub members: Vec<String>,
    pub gates: Vec<String>,
    pub table: Vec<String>,
}

/// One compiler requirement for an indexed route table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorRequirement {
    pub domain: String,
    pub source: String,
    pub variants: Vec<String>,
}

/// The inferred route families and their shared commitment plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub families: Vec<FamilyPlan>,
    pub commitments: CommitmentPlan,
}

/// Invalid compiler input or commitment constraints supplied to route planning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutePlanError {
    #[error(transparent)]
    Constraint(#[from] ConstraintError),
    #[error("selector requirement {selector_index} references unknown domain `{domain}`")]
    UnknownSelectorDomain { selector_index: usize, domain: String },
    #[error("selector requirement {selector_index} source `{source_actor}` does not belong to domain `{domain}`")]
    SelectorSourceOutsideDomain { selector_index: usize, domain: String, source_actor: String },
    #[error("selector requirement {selector_index} must contain at least two variants")]
    SelectorTooSmall { selector_index: usize },
    #[error("selector requirement {selector_index} repeats variant `{actor}`")]
    DuplicateSelectorVariant { selector_index: usize, actor: String },
    #[error("selector requirement {selector_index} variant `{actor}` does not belong to domain `{domain}`")]
    SelectorVariantOutsideDomain { selector_index: usize, domain: String, actor: String },
    #[error(
        "selector requirement {selector_index} variant `{actor}` is outside the `{domain}` component containing source `{source_actor}`"
    )]
    SelectorVariantOutsideComponent { selector_index: usize, domain: String, source_actor: String, actor: String },
    #[error(
        "selector requirement {selector_index} conflicts with requirement {first_selector_index} in the `{domain}` component containing `{source_actor}`"
    )]
    ConflictingSelectors { selector_index: usize, first_selector_index: usize, domain: String, source_actor: String },
}

/// Derive current route-family constraints and plan their commitments.
///
/// Each domain maps its identifier to actors in compiler order. Every
/// nontrivial weak emit component forms a cut cohort so its actors can exchange
/// one generated state layout. A selector requirement creates an ordered table
/// prefix, followed by the component's remaining non-gate actors. Without one,
/// components with at least three members become family candidates whose
/// inbound gates remain direct. The first gate, or the first member when there
/// are no gates, represents the family without affecting its structure.
pub fn route_plan(
    graph: &RouteGraph,
    domains: &BTreeMap<String, Vec<String>>,
    selectors: &[SelectorRequirement],
) -> Result<RoutePlan, RoutePlanError> {
    validate_selector_requirements(domains, selectors)?;

    let mut families = Vec::new();
    let mut constraints = CommitmentConstraints::default();

    for (domain, actor_order) in domains {
        let domain_actors = actor_order.iter().cloned().collect::<BTreeSet<_>>();
        for component in components(graph, &domain_actors) {
            if component.members.len() > 1 {
                constraints.cohorts.push(component.members.clone());
            }

            let members = ordered_members(actor_order, &component.members);
            let gates = ordered_members(actor_order, &component.gates);
            let rep = gates.first().or_else(|| members.first()).expect("components are nonempty").clone();
            let gate_set = gates.iter().cloned().collect::<BTreeSet<_>>();
            let table = if let Some(mut table) = selector_prefix_for_component(domain, &component.members, selectors)? {
                let prefix = table.iter().cloned().collect::<BTreeSet<_>>();
                table.extend(members.iter().filter(|actor| !gate_set.contains(*actor) && !prefix.contains(*actor)).cloned());
                table
            } else {
                // A table for two actors saves no template space and adds slicing.
                // With a gate, it would contain only one actor and be even less useful.
                if component.members.len() < 3 {
                    continue;
                }

                let table = members.iter().filter(|actor| !gate_set.contains(*actor)).cloned().collect::<Vec<_>>();

                // Multiple gates can leave only one table member even in a
                // larger component. A one-entry table has no storage benefit.
                if table.len() < 2 {
                    continue;
                }
                table
            };

            constraints.families.push(table.clone());
            families.push(FamilyPlan { domain: domain.clone(), rep, members, gates, table });
        }
    }

    let commitments = commitment_plan(graph, &constraints)?;
    Ok(RoutePlan { families, commitments })
}

fn validate_selector_requirements(
    domains: &BTreeMap<String, Vec<String>>,
    selectors: &[SelectorRequirement],
) -> Result<(), RoutePlanError> {
    for (selector_index, selector) in selectors.iter().enumerate() {
        let actor_order = domains
            .get(&selector.domain)
            .ok_or_else(|| RoutePlanError::UnknownSelectorDomain { selector_index, domain: selector.domain.clone() })?;
        let domain_actors = actor_order.iter().cloned().collect::<BTreeSet<_>>();
        if !domain_actors.contains(&selector.source) {
            return Err(RoutePlanError::SelectorSourceOutsideDomain {
                selector_index,
                domain: selector.domain.clone(),
                source_actor: selector.source.clone(),
            });
        }
        if selector.variants.len() < 2 {
            return Err(RoutePlanError::SelectorTooSmall { selector_index });
        }

        let mut variants = BTreeSet::new();
        for actor in &selector.variants {
            if !variants.insert(actor) {
                return Err(RoutePlanError::DuplicateSelectorVariant { selector_index, actor: actor.clone() });
            }
            if !domain_actors.contains(actor) {
                return Err(RoutePlanError::SelectorVariantOutsideDomain {
                    selector_index,
                    domain: selector.domain.clone(),
                    actor: actor.clone(),
                });
            }
        }
    }
    Ok(())
}

fn selector_prefix_for_component(
    domain: &str,
    component: &BTreeSet<String>,
    selectors: &[SelectorRequirement],
) -> Result<Option<Vec<String>>, RoutePlanError> {
    let component_selectors = selectors
        .iter()
        .enumerate()
        .filter(|(_, selector)| selector.domain == domain && component.contains(&selector.source))
        .collect::<Vec<_>>();
    let Some((first_selector_index, first)) = component_selectors.first().copied() else {
        return Ok(None);
    };

    for (selector_index, selector) in component_selectors {
        if let Some(actor) = selector.variants.iter().find(|actor| !component.contains(*actor)) {
            return Err(RoutePlanError::SelectorVariantOutsideComponent {
                selector_index,
                domain: domain.to_string(),
                source_actor: selector.source.clone(),
                actor: actor.clone(),
            });
        }
        if selector.variants != first.variants {
            return Err(RoutePlanError::ConflictingSelectors {
                selector_index,
                first_selector_index,
                domain: domain.to_string(),
                source_actor: selector.source.clone(),
            });
        }
    }

    Ok(Some(first.variants.clone()))
}

fn ordered_members(actor_order: &[String], members: &BTreeSet<String>) -> Vec<String> {
    actor_order.iter().filter(|actor| members.contains(*actor)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{CommitmentForest, CommitmentNode, Cut, NodePath};

    #[test]
    fn route_plan_separates_family_structure_from_its_shared_cut() {
        let mut graph = RouteGraph::default();
        graph.add_actor("Knight");
        graph.add_emit("Player", "Mux");
        graph.add_emit("Mux", "Knight");
        graph.add_emit("Mux", "Pawn");
        graph.add_emit("Pawn", "Mux");
        graph.add_emit("Mux", "Settle");
        let domains = BTreeMap::from([
            ("PieceState".to_string(), strings(["Knight", "Mux", "Pawn"])),
            ("PlayerState".to_string(), strings(["Player"])),
            ("SettleState".to_string(), strings(["Settle"])),
        ]);

        let plan = route_plan(&graph, &domains, &[]).expect("inferred constraints are valid");

        assert_eq!(
            plan.families,
            vec![FamilyPlan {
                domain: "PieceState".to_string(),
                members: strings(["Knight", "Mux", "Pawn"]),
                gates: strings(["Mux"]),
                rep: "Mux".to_string(),
                table: strings(["Knight", "Pawn"]),
            }]
        );
        assert_eq!(
            plan.commitments.forest,
            CommitmentForest {
                roots: vec![
                    CommitmentNode::Branch { children: vec![leaf("Knight"), leaf("Pawn")] },
                    leaf("Mux"),
                    leaf("Player"),
                    leaf("Settle"),
                ]
            }
        );
        let cohort_cut = cut([&[0, 0], &[0, 1], &[1], &[3]]);
        assert_eq!(plan.commitments.cuts["Knight"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Mux"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Pawn"], cohort_cut);
    }

    #[test]
    fn gate_less_family_keeps_its_representative_in_the_table() {
        let mut graph = RouteGraph::default();
        graph.add_emit("A", "B");
        graph.add_emit("B", "C");
        graph.add_emit("C", "A");
        let domains = BTreeMap::from([("State".to_string(), strings(["A", "B", "C"]))]);

        let plan = route_plan(&graph, &domains, &[]).expect("inferred constraints are valid");

        assert_eq!(plan.families[0].rep, "A");
        assert!(plan.families[0].gates.is_empty());
        assert_eq!(plan.families[0].table, strings(["A", "B", "C"]));
        assert_eq!(
            plan.commitments.forest,
            CommitmentForest { roots: vec![CommitmentNode::Branch { children: vec![leaf("A"), leaf("B"), leaf("C")] }] }
        );
    }

    #[test]
    fn small_component_forms_a_cohort_without_a_family() {
        let mut graph = RouteGraph::default();
        graph.add_emit("Left", "Right");
        graph.add_emit("Right", "Tail");
        graph.add_emit("Source", "Left");
        let domains = BTreeMap::from([
            ("PairState".to_string(), strings(["Left", "Right"])),
            ("SourceState".to_string(), strings(["Source"])),
            ("TailState".to_string(), strings(["Tail"])),
        ]);

        let plan = route_plan(&graph, &domains, &[]).expect("inferred constraints are valid");
        let cohort_cut = cut([&[0], &[1], &[3]]);

        assert!(plan.families.is_empty());
        assert_eq!(plan.commitments.cuts["Left"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Right"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Source"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Tail"], Cut::new());
    }

    #[test]
    fn selector_defines_an_ordered_prefix_and_keeps_the_gate_direct() {
        let mut graph = RouteGraph::default();
        graph.add_emit("Player", "Mux");
        graph.add_emit("Mux", "A");
        graph.add_emit("Mux", "B");
        graph.add_emit("A", "C");
        let domains =
            BTreeMap::from([("PlayerState".to_string(), strings(["Player"])), ("State".to_string(), strings(["Mux", "A", "B", "C"]))]);
        let selectors =
            [SelectorRequirement { domain: "State".to_string(), source: "Mux".to_string(), variants: strings(["B", "A"]) }];

        let plan = route_plan(&graph, &domains, &selectors).expect("selector requirement is valid");

        assert_eq!(plan.families[0].gates, strings(["Mux"]));
        assert_eq!(plan.families[0].table, strings(["B", "A", "C"]));
        assert_eq!(
            plan.commitments.forest,
            CommitmentForest {
                roots: vec![CommitmentNode::Branch { children: vec![leaf("B"), leaf("A"), leaf("C")] }, leaf("Mux"), leaf("Player"),]
            }
        );
    }

    #[test]
    fn selector_forces_a_family_in_a_two_actor_component() {
        let mut graph = RouteGraph::default();
        graph.add_emit("A", "B");
        let domains = BTreeMap::from([("State".to_string(), strings(["A", "B"]))]);
        let selectors = [SelectorRequirement { domain: "State".to_string(), source: "A".to_string(), variants: strings(["B", "A"]) }];

        let plan = route_plan(&graph, &domains, &selectors).expect("selector requirement is valid");

        assert_eq!(plan.families[0].table, strings(["B", "A"]));
        assert_eq!(
            plan.commitments.forest,
            CommitmentForest { roots: vec![CommitmentNode::Branch { children: vec![leaf("B"), leaf("A")] }] }
        );
    }

    #[test]
    fn conflicting_selectors_in_one_component_are_rejected() {
        let mut graph = RouteGraph::default();
        graph.add_emit("Mux", "A");
        graph.add_emit("Mux", "B");
        let domains = BTreeMap::from([("State".to_string(), strings(["Mux", "A", "B"]))]);
        let selectors = [
            SelectorRequirement { domain: "State".to_string(), source: "Mux".to_string(), variants: strings(["A", "B"]) },
            SelectorRequirement { domain: "State".to_string(), source: "Mux".to_string(), variants: strings(["B", "A"]) },
        ];

        assert_eq!(
            route_plan(&graph, &domains, &selectors),
            Err(RoutePlanError::ConflictingSelectors {
                selector_index: 1,
                first_selector_index: 0,
                domain: "State".to_string(),
                source_actor: "Mux".to_string(),
            })
        );
    }

    fn leaf(actor: &str) -> CommitmentNode {
        CommitmentNode::Leaf { actor: actor.to_string() }
    }

    fn cut<const N: usize>(paths: [&[usize]; N]) -> Cut {
        paths.into_iter().map(|path| NodePath::new(path.to_vec())).collect()
    }

    fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
