//! Pure graph and commitment-tree structures used to plan actor routing.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

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

/// One node in a commitment forest before any concrete hashing is chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentNode {
    Leaf { actor: String },
    Branch { children: Vec<CommitmentNode> },
}

/// An ordered forest whose leaves are actor templates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentForest {
    pub roots: Vec<CommitmentNode>,
}

impl CommitmentForest {
    /// Select every forest root, producing the fully packed cut.
    pub fn root_cut(&self) -> Cut {
        (0..self.roots.len()).map(NodePath::root).collect()
    }

    /// Return whether every selected path exists and no two selected nodes are
    /// ancestors or descendants of one another.
    pub fn is_valid_cut(&self, cut: &Cut) -> bool {
        let mut previous = None::<&NodePath>;
        for path in cut {
            if self.node(path).is_none() {
                return false;
            }
            // BTreeSet iteration follows NodePath's derived lexicographic order.
            // This places an ancestor immediately before its first selected
            // descendant, so comparing adjacent paths is sufficient.
            if previous.is_some_and(|previous| path.path_indices.starts_with(&previous.path_indices)) {
                return false;
            }
            previous = Some(path);
        }
        true
    }

    /// Replace one selected branch with all of its immediate children.
    pub fn open(&self, cut: &Cut, branch: &NodePath) -> Option<Cut> {
        if !self.is_valid_cut(cut) || !cut.contains(branch) {
            return None;
        }
        let CommitmentNode::Branch { children } = self.node(branch)? else {
            return None;
        };
        if children.is_empty() {
            return None;
        }

        let mut opened = cut.clone();
        opened.remove(branch);
        opened.extend((0..children.len()).map(|child| branch.child(child)));
        Some(opened)
    }

    /// Replace all selected immediate children of one branch with that branch.
    pub fn pack(&self, cut: &Cut, branch: &NodePath) -> Option<Cut> {
        if !self.is_valid_cut(cut) {
            return None;
        }
        let CommitmentNode::Branch { children } = self.node(branch)? else {
            return None;
        };
        if children.is_empty() {
            return None;
        }
        let child_paths = (0..children.len()).map(|child| branch.child(child)).collect::<Vec<_>>();
        if child_paths.iter().any(|child| !cut.contains(child)) {
            return None;
        }

        let mut packed = cut.clone();
        for child in child_paths {
            packed.remove(&child);
        }
        packed.insert(branch.clone());
        Some(packed)
    }

    fn node(&self, path: &NodePath) -> Option<&CommitmentNode> {
        let (root, path) = path.split_root();
        let mut node = self.roots.get(root)?;
        for child_idx in path {
            let CommitmentNode::Branch { children } = node else {
                return None;
            };
            node = children.get(*child_idx)?;
        }
        Some(node)
    }
}

/// The structural location of one node in a commitment forest.
///
/// The first index selects a forest root and each remaining index selects a
/// child. A valid node path is therefore never empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodePath {
    path_indices: Vec<usize>,
}

impl NodePath {
    /// Construct a nonempty path whose first index selects a forest root.
    ///
    /// # Panics
    ///
    /// Panics if `path_indices` is empty because every node path must select a
    /// forest root.
    pub fn new(path_indices: Vec<usize>) -> Self {
        assert!(!path_indices.is_empty(), "node path must select a forest root");
        Self { path_indices }
    }

    fn root(root: usize) -> Self {
        Self { path_indices: vec![root] }
    }

    fn child(&self, child: usize) -> Self {
        let mut path_indices = self.path_indices.clone();
        path_indices.push(child);
        Self { path_indices }
    }

    fn split_root(&self) -> (usize, &[usize]) {
        let (root, children) = self.path_indices.split_first().expect("node paths are nonempty");
        (*root, children)
    }
}

/// A partial commitment-tree cut, represented by structural node locations.
pub type Cut = BTreeSet<NodePath>;

/// Actor groups represented as branches in the commitment forest.
pub type Families = Vec<BTreeSet<String>>;

/// Actor groups that share one cut and appear directly in that cut.
pub type Cohorts = Vec<BTreeSet<String>>;

/// Structural and cut-selection constraints used to plan commitments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentConstraints {
    pub families: Families,
    pub cohorts: Cohorts,
}

/// A global commitment forest together with the canonical partial cut carried
/// by each actor.
///
/// The forest defines one shared address space for all possible actor
/// commitments. A cut selects only the nodes an actor must carry from that
/// forest. For example, given a family branch and one standalone actor:
///
/// ```text
/// [0] family
///     [0, 0] A
///     [0, 1] B
/// [1] C
/// ```
///
/// An actor outside a cohort needing `A` and `C` carries `{ [0], [1] }`: the
/// foreign family remains packed. If `A` and `B` form a cohort, both receive a
/// cut containing `{ [0, 0], [0, 1] }`, plus any external nodes needed by
/// either member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentPlan {
    pub forest: CommitmentForest,
    pub cuts: BTreeMap<String, Cut>,
}

/// Direct paths recorded while constructing a forest so cut planning does not
/// need to search the completed tree or reconstruct its ordering rules.
struct CommitmentLocations {
    /// The leaf path for every actor, including actors inside family branches.
    actor_paths: BTreeMap<String, NodePath>,
    /// The packed branch path for every family.
    family_paths: BTreeMap<usize, NodePath>,
}

/// Invalid input supplied to commitment planning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConstraintError {
    #[error("family {family_index} is empty")]
    EmptyFamily { family_index: usize },
    #[error("family {family_index} contains unknown actor `{actor}`")]
    UnknownFamilyActor { family_index: usize, actor: String },
    #[error("actor `{actor}` belongs to more than one family")]
    OverlappingFamilyActor { actor: String },
    #[error("cohort {cohort_index} is empty")]
    EmptyCohort { cohort_index: usize },
    #[error("cohort {cohort_index} contains unknown actor `{actor}`")]
    UnknownCohortActor { cohort_index: usize, actor: String },
    #[error("actor `{actor}` belongs to more than one cohort")]
    OverlappingCohortActor { actor: String },
}

/// Build a deterministic forest with one branch per family and one actor root
/// for every actor outside a family.
///
/// Family children follow actor order. A family branch occupies the root
/// position of its first actor, so the order of `families` does not affect the
/// forest structure.
pub fn commitment_forest(g: &RouteGraph, families: &Families) -> Result<CommitmentForest, ConstraintError> {
    let family_by_actor = validate_families(g, families)?;

    Ok(build_commitment_forest(g, families, &family_by_actor).0)
}

/// Build the commitment forest and the canonical partial cut carried by every
/// actor.
///
/// Planning proceeds in four phases:
///
/// 1. Validate disjoint family and cohort membership, then build the
///    deterministic forest. Forest construction also records direct paths to
///    actor leaves and family branches.
/// 2. Compute each actor's transitive emit and direct consume needs.
/// 3. Translate actors outside cohorts independently. A needed standalone actor
///    becomes its leaf; any needed family member becomes its packed family
///    branch.
/// 4. For each cohort, union every member's needs and construct one shared cut.
///    Every cohort member appears directly in that cut. Exposing a family
///    member opens its family branch, which necessarily exposes its siblings as
///    well.
///
/// Cuts are partial: roots unrelated to an actor's needs or cohort are omitted.
/// Cohort members receive the same cut by construction, not by comparing
/// independently computed cuts afterward.
pub fn commitment_plan(g: &RouteGraph, constraints: &CommitmentConstraints) -> Result<CommitmentPlan, ConstraintError> {
    // Phase 1 establishes the shared forest topology and stable paths into it.
    let families = &constraints.families;
    let family_by_actor = validate_families(g, families)?;
    let cohort_by_actor = validate_cohorts(g, &constraints.cohorts)?;
    let (forest, locations) = build_commitment_forest(g, families, &family_by_actor);

    // Phase 2 resolves graph semantics before they are mapped onto the tree.
    let actor_needs = needs(g);
    let mut cuts = BTreeMap::new();

    for actor in &g.actors {
        // Processing one cohort member publishes the shared cut for every
        // member, so later members require no independent calculation.
        if cuts.contains_key(actor) {
            continue;
        }

        let Some(cohort_index) = cohort_by_actor.get(actor).copied() else {
            // Phase 3: actors outside cohorts preserve all families as packed
            // branch commitments.
            let cut = cut_for_needs(&actor_needs[actor], &family_by_actor, &locations);
            debug_assert!(forest.is_valid_cut(&cut));
            cuts.insert(actor.clone(), cut);
            continue;
        };

        // Phase 4: a cohort uses one route representation, so its cut must
        // satisfy the needs of every member.
        let cohort = &constraints.cohorts[cohort_index];
        let mut cohort_needs = BTreeSet::new();
        for member in cohort {
            cohort_needs.extend(actor_needs[member].iter().cloned());
        }

        let mut cut = cut_for_needs(&cohort_needs, &family_by_actor, &locations);
        expose_actors(&mut cut, cohort, families, &family_by_actor, &locations);
        debug_assert!(forest.is_valid_cut(&cut));

        for member in cohort {
            cuts.insert(member.clone(), cut.clone());
        }
    }

    Ok(CommitmentPlan { forest, cuts })
}

/// Construct the deterministic forest and retain paths needed by cut planning.
///
/// A standalone actor becomes a root leaf. The first actor of each family in
/// global actor order emits one root branch, and all other family members are
/// skipped because they are already children of that branch. For example:
///
/// ```text
/// actors   = { A, B, C }
/// families = [ { A, B } ]
///
/// roots[0] = Branch(Leaf(A), Leaf(B))
/// roots[1] = Leaf(C)
/// ```
///
/// `family_by_actor` must already have been produced by `validate_families`.
fn build_commitment_forest(
    g: &RouteGraph,
    families: &Families,
    family_by_actor: &BTreeMap<String, usize>,
) -> (CommitmentForest, CommitmentLocations) {
    let mut roots = Vec::new();
    let mut actor_paths = BTreeMap::new();
    let mut family_paths = BTreeMap::new();

    let mut emitted_families = BTreeSet::new();
    // Actor order places each family at its lowest member independently of the
    // order in which the family sets were supplied.
    for actor in &g.actors {
        let Some(family_index) = family_by_actor.get(actor).copied() else {
            actor_paths.insert(actor.clone(), NodePath::root(roots.len()));
            roots.push(CommitmentNode::Leaf { actor: actor.clone() });
            continue;
        };
        if !emitted_families.insert(family_index) {
            continue;
        }

        let family_path = NodePath::root(roots.len());
        family_paths.insert(family_index, family_path.clone());
        let children = families[family_index]
            .iter()
            .enumerate()
            .map(|(child_index, actor)| {
                actor_paths.insert(actor.clone(), family_path.child(child_index));
                CommitmentNode::Leaf { actor: actor.clone() }
            })
            .collect();
        roots.push(CommitmentNode::Branch { children });
    }

    (CommitmentForest { roots }, CommitmentLocations { actor_paths, family_paths })
}

/// Translate actor needs into leaf paths and packed family paths.
///
/// Each standalone need maps to its actor leaf. All needs belonging to the
/// same family map to the same family branch and collapse naturally in the
/// returned `BTreeSet`:
///
/// ```text
/// need A in family 0 -> [0]
/// need B in family 0 -> [0]
/// need C standalone  -> [1]
/// result             -> { [0], [1] }
/// ```
fn cut_for_needs(actor_needs: &BTreeSet<String>, family_by_actor: &BTreeMap<String, usize>, locations: &CommitmentLocations) -> Cut {
    actor_needs
        .iter()
        .map(|actor| {
            family_by_actor
                .get(actor)
                .map_or_else(|| locations.actor_paths[actor].clone(), |family| locations.family_paths[family].clone())
        })
        .collect()
}

/// Add actors directly to a cut, opening their family branches when needed.
///
/// A valid tree cut cannot mix a packed family branch with individual children
/// or expose only some of those children. Therefore exposing one family member
/// replaces the packed branch, if present, with every leaf in that family.
fn expose_actors(
    cut: &mut Cut,
    actors: &BTreeSet<String>,
    families: &Families,
    family_by_actor: &BTreeMap<String, usize>,
    locations: &CommitmentLocations,
) {
    let mut opened_families = BTreeSet::new();
    for actor in actors {
        let Some(family_index) = family_by_actor.get(actor).copied() else {
            cut.insert(locations.actor_paths[actor].clone());
            continue;
        };
        if !opened_families.insert(family_index) {
            continue;
        }

        cut.remove(&locations.family_paths[&family_index]);
        cut.extend(families[family_index].iter().map(|member| locations.actor_paths[member].clone()));
    }
}

/// Validate family membership and return each family actor's family index.
fn validate_families(g: &RouteGraph, families: &Families) -> Result<BTreeMap<String, usize>, ConstraintError> {
    let mut family_by_actor = BTreeMap::<String, usize>::new();
    for (family_index, family) in families.iter().enumerate() {
        if family.is_empty() {
            return Err(ConstraintError::EmptyFamily { family_index });
        }
        for actor in family {
            if !g.actors.contains(actor) {
                return Err(ConstraintError::UnknownFamilyActor { family_index, actor: actor.clone() });
            }
            if family_by_actor.insert(actor.clone(), family_index).is_some() {
                return Err(ConstraintError::OverlappingFamilyActor { actor: actor.clone() });
            }
        }
    }
    Ok(family_by_actor)
}

/// Validate cohort membership and return each cohort actor's cohort index.
fn validate_cohorts(g: &RouteGraph, cohorts: &Cohorts) -> Result<BTreeMap<String, usize>, ConstraintError> {
    let mut cohort_by_actor = BTreeMap::<String, usize>::new();
    for (cohort_index, cohort) in cohorts.iter().enumerate() {
        if cohort.is_empty() {
            return Err(ConstraintError::EmptyCohort { cohort_index });
        }
        for actor in cohort {
            if !g.actors.contains(actor) {
                return Err(ConstraintError::UnknownCohortActor { cohort_index, actor: actor.clone() });
            }
            if cohort_by_actor.insert(actor.clone(), cohort_index).is_some() {
                return Err(ConstraintError::OverlappingCohortActor { actor: actor.clone() });
            }
        }
    }
    Ok(cohort_by_actor)
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

    #[test]
    fn families_form_branches_that_open_and_pack_one_level() {
        let mut graph = RouteGraph::default();
        for actor in ["Knight", "Mux", "Pawn", "Player", "Settle"] {
            graph.add_actor(actor);
        }
        let families = vec![strings(["Knight", "Mux", "Pawn"])];

        let forest = commitment_forest(&graph, &families).expect("family is valid");
        assert_eq!(
            forest,
            CommitmentForest {
                roots: vec![
                    CommitmentNode::Branch { children: vec![leaf("Knight"), leaf("Mux"), leaf("Pawn")] },
                    leaf("Player"),
                    leaf("Settle"),
                ],
            }
        );

        let packed = cut([&[0], &[1], &[2]]);
        let opened = cut([&[0, 0], &[0, 1], &[0, 2], &[1], &[2]]);
        let family = path(&[0]);

        assert_eq!(forest.root_cut(), packed);
        assert!(forest.is_valid_cut(&opened));
        assert_eq!(forest.open(&packed, &family), Some(opened.clone()));
        assert_eq!(forest.pack(&opened, &family), Some(packed.clone()));
        assert_eq!(forest.open(&packed, &path(&[1])), None);
        assert_eq!(forest.pack(&packed, &family), None);

        let invalid = cut([&[0], &[0, 0]]);
        assert!(!forest.is_valid_cut(&invalid));
        assert_eq!(forest.open(&invalid, &family), None);
    }

    #[test]
    fn commitment_plan_uses_families_for_structure_and_cohorts_for_shared_cuts() {
        let mut graph = RouteGraph::default();
        graph.add_actor("Knight");
        graph.add_emit("Player", "Mux");
        graph.add_emit("Mux", "Pawn");
        graph.add_emit("Pawn", "Mux");
        graph.add_emit("Mux", "Settle");
        let constraints =
            CommitmentConstraints { families: vec![strings(["Knight", "Pawn"])], cohorts: vec![strings(["Knight", "Mux", "Pawn"])] };

        let plan = commitment_plan(&graph, &constraints).expect("constraints are valid");
        let cohort_cut = cut([&[0, 0], &[0, 1], &[1], &[3]]);

        assert_eq!(
            plan.forest,
            CommitmentForest {
                roots: vec![
                    CommitmentNode::Branch { children: vec![leaf("Knight"), leaf("Pawn")] },
                    leaf("Mux"),
                    leaf("Player"),
                    leaf("Settle"),
                ],
            }
        );
        assert_eq!(plan.cuts["Knight"], cohort_cut);
        assert_eq!(plan.cuts["Mux"], cohort_cut);
        assert_eq!(plan.cuts["Pawn"], cohort_cut);
        assert_eq!(plan.cuts["Player"], cut([&[0], &[1], &[3]]));
        assert_eq!(plan.cuts["Settle"], Cut::new());
        assert!(plan.cuts.values().all(|cut| plan.forest.is_valid_cut(cut)));
    }

    #[test]
    fn family_members_do_not_share_cuts_without_a_cohort() {
        let mut graph = RouteGraph::default();
        graph.add_actor("B");
        graph.add_emit("A", "External");
        let constraints = CommitmentConstraints { families: vec![strings(["A", "B"])], cohorts: Vec::new() };

        let plan = commitment_plan(&graph, &constraints).expect("constraints are valid");

        assert_eq!(plan.cuts["A"], cut([&[1]]));
        assert_eq!(plan.cuts["B"], Cut::new());
    }

    #[test]
    fn exposing_a_cohort_member_opens_its_entire_family() {
        let mut graph = RouteGraph::default();
        for actor in ["A", "Anchor", "Sibling"] {
            graph.add_actor(actor);
        }
        let constraints = CommitmentConstraints { families: vec![strings(["A", "Sibling"])], cohorts: vec![strings(["A", "Anchor"])] };

        let plan = commitment_plan(&graph, &constraints).expect("constraints are valid");
        let cohort_cut = cut([&[0, 0], &[0, 1], &[1]]);

        assert_eq!(plan.cuts["A"], cohort_cut);
        assert_eq!(plan.cuts["Anchor"], cohort_cut);
        assert_eq!(plan.cuts["Sibling"], Cut::new());
    }

    #[test]
    fn commitment_forest_rejects_invalid_families() {
        let mut graph = RouteGraph::default();
        graph.add_actor("A");
        graph.add_actor("B");

        assert_eq!(commitment_forest(&graph, &vec![BTreeSet::new()]), Err(ConstraintError::EmptyFamily { family_index: 0 }));
        assert_eq!(
            commitment_forest(&graph, &vec![strings(["Unknown"])]),
            Err(ConstraintError::UnknownFamilyActor { family_index: 0, actor: "Unknown".to_string() })
        );
        assert_eq!(
            commitment_forest(&graph, &vec![strings(["A"]), strings(["A", "B"])]),
            Err(ConstraintError::OverlappingFamilyActor { actor: "A".to_string() })
        );
    }

    #[test]
    fn commitment_plan_rejects_invalid_cohorts() {
        let mut graph = RouteGraph::default();
        graph.add_actor("A");
        graph.add_actor("B");

        let constraints = CommitmentConstraints { cohorts: vec![BTreeSet::new()], ..Default::default() };
        assert_eq!(commitment_plan(&graph, &constraints), Err(ConstraintError::EmptyCohort { cohort_index: 0 }));

        let constraints = CommitmentConstraints { cohorts: vec![strings(["Unknown"])], ..Default::default() };
        assert_eq!(
            commitment_plan(&graph, &constraints),
            Err(ConstraintError::UnknownCohortActor { cohort_index: 0, actor: "Unknown".to_string() })
        );

        let constraints = CommitmentConstraints { cohorts: vec![strings(["A"]), strings(["A", "B"])], ..Default::default() };
        assert_eq!(commitment_plan(&graph, &constraints), Err(ConstraintError::OverlappingCohortActor { actor: "A".to_string() }));
    }

    #[test]
    #[should_panic(expected = "node path must select a forest root")]
    fn node_paths_must_select_a_root() {
        NodePath::new(Vec::new());
    }

    #[test]
    fn cuts_order_paths_lexicographically() {
        let paths = cut([&[1], &[0, 1], &[0], &[0, 0, 2], &[0, 0]]);
        let ordered = paths.into_iter().map(|path| path.path_indices).collect::<Vec<_>>();

        assert_eq!(ordered, vec![vec![0], vec![0, 0], vec![0, 0, 2], vec![0, 1], vec![1]]);
    }

    fn leaf(actor: &str) -> CommitmentNode {
        CommitmentNode::Leaf { actor: actor.to_string() }
    }

    fn path(indices: &[usize]) -> NodePath {
        NodePath::new(indices.to_vec())
    }

    fn cut<const N: usize>(paths: [&[usize]; N]) -> Cut {
        paths.into_iter().map(path).collect()
    }

    fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
