//! Pure graph and commitment-tree structures used to plan actor routing.

use std::collections::{BTreeMap, BTreeSet};

/// A directed graph of actor emit and consume relations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteGraph {
    actors: BTreeSet<String>,
    emits: BTreeMap<String, BTreeSet<String>>,
    consumes: BTreeMap<String, BTreeSet<String>>,
}

impl RouteGraph {
    /// Add an actor without adding any routes.
    pub fn add_actor(&mut self, actor: impl Into<String>) {
        self.actors.insert(actor.into());
    }

    /// Add an emit relation whose target and transitive needs belong to its source.
    pub fn add_emit(&mut self, source: impl Into<String>, target: impl Into<String>) {
        let source = source.into();
        let target = target.into();
        self.actors.insert(source.clone());
        self.actors.insert(target.clone());
        self.emits.entry(source).or_default().insert(target);
    }

    /// Add a consume relation whose target belongs directly to its source.
    pub fn add_consume(&mut self, source: impl Into<String>, target: impl Into<String>) {
        let source = source.into();
        let target = target.into();
        self.actors.insert(source.clone());
        self.actors.insert(target.clone());
        self.consumes.entry(source).or_default().insert(target);
    }
}

/// One node in a commitment forest before any concrete hashing is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentNode {
    Actor { actor: String },
    Branch { children: Vec<CommitmentNode> },
}

/// An ordered forest whose leaves are actor templates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentForest {
    pub roots: Vec<CommitmentNode>,
}

/// The structural location of one node in a commitment forest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodePath {
    pub root: usize,
    pub child_indices: Vec<usize>,
}

/// A partial commitment-tree cut, represented by structural node locations.
pub type Cut = BTreeSet<NodePath>;

/// The actor templates needed by each actor through transitive emits and direct
/// consumes.
pub type Needs = BTreeMap<String, BTreeSet<String>>;

/// Compute the actor templates needed by every actor.
///
/// Emit targets contribute themselves and their complete needs. Consume targets
/// contribute only themselves. Actors are resolved in sorted order, allowing a
/// traversal to reuse complete needs sets for emit targets preceding its source.
///
/// A source actor is included in its own needs only when reached through a
/// non-empty route, such as an emit cycle, a consume from an emit-reachable
/// actor, or a self-consume.
pub fn needs(g: &RouteGraph) -> Needs {
    let mut reachable = Needs::new();

    for src in &g.actors {
        // Consume targets are direct needs, but never enter the emit traversal.
        let mut src_reachable = g.consumes.get(src).cloned().unwrap_or_default();
        let mut stack = g.emits.get(src).into_iter().flatten().cloned().collect::<Vec<_>>();
        let mut expanded = BTreeSet::new();

        while let Some(dst) = stack.pop() {
            src_reachable.insert(dst.clone());

            // An actor may already be reachable through consumes but still
            // require expansion after being reached through emits.
            if !expanded.insert(dst.clone()) {
                continue;
            }

            // Sources are visited in BTreeSet order. A lower actor was therefore
            // resolved in an earlier iteration.
            if &dst < src {
                // A resolved actor contributes its complete closure at once.
                let dst_reachable = reachable.get(&dst).expect("lower actors are resolved");
                src_reachable.extend(dst_reachable.iter().cloned());
            } else {
                // An unresolved actor contributes its consumes directly, while
                // its emits continue the traversal.
                src_reachable.extend(g.consumes.get(&dst).into_iter().flatten().cloned());
                stack.extend(g.emits.get(&dst).into_iter().flatten().cloned());
            }
        }

        // Publishing the closure makes it reusable by all later sources.
        reachable.insert(src.clone(), src_reachable);
    }

    reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_propagates_through_cycles_and_downstream_routes() {
        let mut graph = RouteGraph::default();
        graph.add_actor("Spectator");
        graph.add_emit("Player", "Mux");
        graph.add_emit("Mux", "Pawn");
        graph.add_emit("Pawn", "Mux");
        graph.add_emit("Mux", "Settle");

        let expected = BTreeMap::from([
            ("Mux".to_string(), strings(["Mux", "Pawn", "Settle"])),
            ("Pawn".to_string(), strings(["Mux", "Pawn", "Settle"])),
            ("Player".to_string(), strings(["Mux", "Pawn", "Settle"])),
            ("Settle".to_string(), BTreeSet::new()),
            ("Spectator".to_string(), BTreeSet::new()),
        ]);

        assert_eq!(needs(&graph), expected);
    }

    #[test]
    fn needs_only_propagates_through_emit_edges() {
        let mut graph = RouteGraph::default();
        graph.add_consume("Source", "Consumed");
        graph.add_emit("Consumed", "NotInherited");

        // `Shared` is already a direct consume need, but its emit edge must
        // still be traversed because Source also emits it.
        graph.add_consume("Source", "Shared");
        graph.add_emit("Source", "Shared");
        graph.add_emit("Shared", "Inherited");

        let result = needs(&graph);
        assert_eq!(result["Source"], strings(["Consumed", "Inherited", "Shared"]));
        assert_eq!(result["Consumed"], strings(["NotInherited"]));
    }

    fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
