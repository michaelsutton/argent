//! Pure graph and commitment-tree structures used to plan actor routing.

use std::collections::{BTreeMap, BTreeSet};

/// A directed graph whose vertices are actor names and whose edges are possible
/// actor-to-actor routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteGraph {
    actors: BTreeSet<String>,
    outgoing: BTreeMap<String, BTreeSet<String>>,
}

impl RouteGraph {
    /// Add an actor without adding any routes.
    pub fn add_actor(&mut self, actor: impl Into<String>) {
        self.actors.insert(actor.into());
    }

    /// Add a directed route and, by definition, both of its endpoint actors.
    pub fn add_route(&mut self, source: impl Into<String>, target: impl Into<String>) {
        let source = source.into();
        let target = target.into();
        self.actors.insert(source.clone());
        self.actors.insert(target.clone());
        self.outgoing.entry(source).or_default().insert(target);
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

/// The actor templates transitively needed by each actor.
pub type Needs = BTreeMap<String, BTreeSet<String>>;

/// Compute positive-length route reachability for every actor.
///
/// Direct targets initialize the result. Actors are resolved in sorted order,
/// so traversal reuses complete needs sets for actors preceding the source and
/// follows direct targets for the rest. An actor needs itself only when
/// traversal returns through a non-empty cycle.
pub fn needs(graph: &RouteGraph) -> Needs {
    // Every entry starts as direct reachability. During the ordered pass, each
    // completed entry is replaced with its full transitive closure.
    let mut needs =
        graph.actors.iter().map(|actor| (actor.clone(), graph.outgoing.get(actor).cloned().unwrap_or_default())).collect::<Needs>();

    for source in &graph.actors {
        // Resolve into a local set so the shared entry for `source` continues
        // to mean direct reachability until this traversal is complete.
        let mut source_needs = needs.get(source).cloned().expect("graph actors have a needs entry");
        // Direct targets are unique because `source_needs` is a set. Later
        // targets are queued only when first inserted into that same set.
        let mut pending = source_needs.iter().cloned().collect::<Vec<_>>();

        while let Some(actor) = pending.pop() {
            let actor_needs = needs.get(&actor).expect("route targets are graph actors");

            // Sources are visited in BTreeSet order. A lower actor was therefore
            // resolved in an earlier iteration, while this actor and all higher
            // actors still hold only their direct targets.
            if &actor < source {
                // A resolved actor contributes its complete closure at once.
                source_needs.extend(actor_needs.iter().cloned());
            } else {
                // An unresolved actor still holds direct targets. Insertion is
                // also the queue guard, so cycles cannot enqueue an actor twice.
                for needed in actor_needs {
                    if source_needs.insert(needed.clone()) {
                        pending.push(needed.clone());
                    }
                }
            }
        }

        // Publishing the closure makes it reusable by all later sources.
        needs.insert(source.clone(), source_needs);
    }

    needs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_propagates_through_cycles_and_downstream_routes() {
        let mut graph = RouteGraph::default();
        graph.add_actor("Spectator");
        graph.add_route("Player", "Mux");
        graph.add_route("Mux", "Pawn");
        graph.add_route("Pawn", "Mux");
        graph.add_route("Mux", "Settle");

        let expected = BTreeMap::from([
            ("Mux".to_string(), strings(["Mux", "Pawn", "Settle"])),
            ("Pawn".to_string(), strings(["Mux", "Pawn", "Settle"])),
            ("Player".to_string(), strings(["Mux", "Pawn", "Settle"])),
            ("Settle".to_string(), BTreeSet::new()),
            ("Spectator".to_string(), BTreeSet::new()),
        ]);

        assert_eq!(needs(&graph), expected);
    }

    fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
