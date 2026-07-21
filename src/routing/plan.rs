//! Compiler-facing adaptation from route domains to commitment plans.

use std::collections::{BTreeMap, BTreeSet};

use super::commitment::{CommitmentConstraints, CommitmentPlan, ConstraintError, commitment_plan};
use super::graph::{RouteGraph, components};

/// One inferred route family in compiler actor order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyPlan {
    pub domain: String,
    pub rep: String,
    pub members: Vec<String>,
    pub gates: Vec<String>,
    pub table: Vec<String>,
}

/// The inferred route families and their shared commitment plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePlan {
    pub families: Vec<FamilyPlan>,
    pub commitments: CommitmentPlan,
}

/// Derive current route-family constraints and plan their commitments.
///
/// Each domain maps its identifier to actors in compiler order. Every
/// nontrivial weak emit component forms a cut cohort so its actors can exchange
/// one generated state layout. Components with at least three members also
/// become family candidates. Their inbound gates remain direct. The first
/// gate, or the first member when there are no gates, represents the family
/// without affecting its structure. All non-gate members form the commitment
/// family.
pub fn route_plan(graph: &RouteGraph, domains: &BTreeMap<String, Vec<String>>) -> Result<RoutePlan, ConstraintError> {
    let mut families = Vec::new();
    let mut constraints = CommitmentConstraints::default();

    for (domain, actor_order) in domains {
        let domain_actors = actor_order.iter().cloned().collect::<BTreeSet<_>>();
        for component in components(graph, &domain_actors) {
            if component.members.len() > 1 {
                constraints.cohorts.push(component.members.clone());
            }

            // A table for two actors saves no template space and adds slicing.
            // With a gate, it would contain only one actor and be even less useful.
            if component.members.len() < 3 {
                continue;
            }

            let members = ordered_members(actor_order, &component.members);
            let gates = ordered_members(actor_order, &component.gates);
            let rep = gates.first().or_else(|| members.first()).expect("components are nonempty").clone();
            let gate_set = gates.iter().cloned().collect::<BTreeSet<_>>();
            let table = members.iter().filter(|actor| !gate_set.contains(*actor)).cloned().collect::<Vec<_>>();

            // Multiple gates can leave only one table member even in a larger
            // component. A one-entry table has no storage benefit.
            if table.len() < 2 {
                continue;
            }

            let family = members.iter().filter(|actor| !gate_set.contains(*actor)).cloned().collect();
            constraints.families.push(family);
            families.push(FamilyPlan { domain: domain.clone(), rep, members, gates, table });
        }
    }

    let commitments = commitment_plan(graph, &constraints)?;
    Ok(RoutePlan { families, commitments })
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

        let plan = route_plan(&graph, &domains).expect("inferred constraints are valid");

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

        let plan = route_plan(&graph, &domains).expect("inferred constraints are valid");

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

        let plan = route_plan(&graph, &domains).expect("inferred constraints are valid");
        let cohort_cut = cut([&[0], &[1], &[3]]);

        assert!(plan.families.is_empty());
        assert_eq!(plan.commitments.cuts["Left"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Right"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Source"], cohort_cut);
        assert_eq!(plan.commitments.cuts["Tail"], Cut::new());
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
