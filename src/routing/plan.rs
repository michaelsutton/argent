//! Compiler-facing adaptation from route domains to commitment plans.

use std::collections::{BTreeMap, BTreeSet};

use super::commitment::{CommitmentConstraints, CommitmentPlan, ConstraintError, commitment_plan};
use super::graph::{RouteGraph, components};

/// One inferred route family in compiler actor order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyPlan {
    pub domain: String,
    pub members: Vec<String>,
    pub gates: Vec<String>,
    pub direct: Vec<String>,
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
/// Each domain maps its identifier to actors in compiler order. Weak emit
/// components with at least three members become family candidates. Their
/// inbound gates remain direct; a component without gates keeps its first actor
/// direct. The remaining actors form a commitment family when at least two
/// table entries remain, while all component members form one cut cohort.
pub fn route_plan(graph: &RouteGraph, domains: &BTreeMap<String, Vec<String>>) -> Result<RoutePlan, ConstraintError> {
    let mut families = Vec::new();
    let mut constraints = CommitmentConstraints::default();

    for (domain, actor_order) in domains {
        let domain_actors = actor_order.iter().cloned().collect::<BTreeSet<_>>();
        for component in components(graph, &domain_actors) {
            // With at least one gate, the table would have at most one entry,
            // adding a commitment and slicing without reducing template storage.
            if component.members.len() < 3 {
                continue;
            }

            let members = ordered_members(actor_order, &component.members);
            let gates = ordered_members(actor_order, &component.gates);
            let direct = if gates.is_empty() { vec![members[0].clone()] } else { gates.clone() };
            let direct_set = direct.iter().cloned().collect::<BTreeSet<_>>();
            let table = members.iter().filter(|actor| !direct_set.contains(*actor)).cloned().collect::<Vec<_>>();

            // Multiple gates can leave only one table member even in a larger
            // component. A one-entry table has no storage benefit.
            if table.len() < 2 {
                continue;
            }

            constraints.families.push(table.iter().cloned().collect());
            constraints.cohorts.push(component.members);
            families.push(FamilyPlan { domain: domain.clone(), members, gates, direct, table });
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
                direct: strings(["Mux"]),
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
