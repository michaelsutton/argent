//! Pure graph structures and algorithms used to plan actor routing.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

/// A directed graph of actor emit and consume relations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteGraph {
    pub(super) actors: BTreeSet<String>,
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

/// One weakly connected emit component inside a selected graph domain.
///
/// `gates` are component members with an incoming emit edge whose source is
/// outside the component. The source may be outside the domain entirely; the
/// full graph remains visible while connectivity is restricted to the domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub members: BTreeSet<String>,
    pub gates: BTreeSet<String>,
}

/// Find weak emit-components and their inbound gates within `domain`.
///
/// Emit direction is ignored only while finding components. Directed incoming
/// edges then identify component members targeted from outside their component.
/// Consume edges do not participate. Every domain actor is returned exactly
/// once, including isolated actors, and components follow the domain's actor
/// order.
///
/// # Panics
///
/// Panics if `domain` contains an actor absent from `graph`.
pub fn components(graph: &RouteGraph, domain: &BTreeSet<String>) -> Vec<Component> {
    assert!(domain.is_subset(&graph.actors), "component domain contains actors absent from the route graph");

    // Build the undirected adjacency of the emit graph induced by the domain.
    // Initializing every domain actor also preserves isolated components. Keep
    // targets reached from outside the domain for gate classification after
    // components are known.
    let mut neighbors = domain.iter().map(|actor| (actor.clone(), BTreeSet::new())).collect::<BTreeMap<_, _>>();
    let mut gates = Vec::new();
    for (source, targets) in &graph.emits {
        let source_in_domain = domain.contains(source);
        for target in targets.intersection(domain) {
            if source == target {
                continue;
            }
            if !source_in_domain {
                gates.push(target);
                continue;
            }
            neighbors.get_mut(source).expect("domain actor has neighbor storage").insert(target.clone());
            neighbors.get_mut(target).expect("domain actor has neighbor storage").insert(source.clone());
        }
    }

    // Discover components in domain order and retain each actor's component so
    // the later incoming-edge pass can assign gates without another traversal.
    let mut components = Vec::new();
    let mut component_by_actor = BTreeMap::<String, usize>::new();
    for actor in domain {
        if component_by_actor.contains_key(actor) {
            continue;
        }

        let component_index = components.len();
        let mut members = BTreeSet::new();
        // Direction has already been erased in `neighbors`, so this traversal
        // computes one weakly connected component. Actors are assigned when
        // queued so each actor enters the pending stack at most once.
        component_by_actor.insert(actor.clone(), component_index);
        let mut pending = vec![actor.clone()];
        while let Some(actor) = pending.pop() {
            members.insert(actor.clone());
            for neighbor in &neighbors[&actor] {
                if let Entry::Vacant(entry) = component_by_actor.entry(neighbor.clone()) {
                    entry.insert(component_index);
                    pending.push(neighbor.clone());
                }
            }
        }
        components.push(Component { members, gates: BTreeSet::new() });
    }

    // Every retained target has an incoming edge from outside the domain and
    // therefore outside its component.
    for target in gates {
        let component_index = component_by_actor[target];
        components[component_index].gates.insert(target.clone());
    }

    components
}

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
    fn components_use_weak_domain_connectivity_and_full_graph_inputs() {
        let mut graph = RouteGraph::default();
        graph.add_actor("Zed");
        graph.add_emit("Knight", "Mux");
        graph.add_emit("Mux", "Pawn");
        graph.add_emit("Player", "Mux");
        graph.add_emit("Mux", "Settle");
        graph.add_consume("Zed", "Pawn");
        let domain = strings(["Knight", "Mux", "Pawn", "Zed"]);

        assert_eq!(
            components(&graph, &domain),
            vec![
                Component { members: strings(["Knight", "Mux", "Pawn"]), gates: strings(["Mux"]) },
                Component { members: strings(["Zed"]), gates: BTreeSet::new() },
            ]
        );
    }

    #[test]
    #[should_panic(expected = "component domain contains actors absent from the route graph")]
    fn component_domains_must_belong_to_the_graph() {
        components(&RouteGraph::default(), &strings(["Unknown"]));
    }

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
