//! Pure commitment-tree structures used to plan actor routing.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use super::graph::{RouteGraph, needs};

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

/// Ordered actor groups represented as branches in the commitment forest.
pub type Families = Vec<Vec<String>>;

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
    #[error("family {family_index} repeats actor `{actor}`")]
    DuplicateFamilyActor { family_index: usize, actor: String },
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
/// Family children follow their supplied order. A family branch occupies the
/// root position of its earliest member in global actor order, so the order of
/// `families` does not affect the forest structure.
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
/// 2. Equalize each cohort's outgoing dependencies, then compute every actor's
///    transitive emit and direct consume needs. Equalization happens before
///    propagation so upstream emitters inherit complete cohort requirements.
/// 3. Translate actors outside cohorts independently. A needed standalone actor
///    becomes its leaf; any needed family member becomes its packed family
///    branch.
/// 4. Construct one shared cut from each cohort's equal needs. Every cohort
///    member appears directly in that cut. Exposing a family member opens its
///    family branch, which necessarily exposes its siblings as well.
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
    let mut needs_graph = g.clone();
    for cohort in &constraints.cohorts {
        needs_graph.equalize_outgoing(cohort);
    }
    let actor_needs = needs(&needs_graph);
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

        // Phase 4: equalized cohort members use one route representation.
        let cohort = &constraints.cohorts[cohort_index];
        let first = cohort.iter().next().expect("validated cohorts are nonempty");
        let cohort_needs = &actor_needs[first];
        debug_assert!(cohort.iter().all(|member| &actor_needs[member] == cohort_needs));

        let mut cut = cut_for_needs(cohort_needs, &family_by_actor, &locations);
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
    // order in which the families were supplied.
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
        let mut members = BTreeSet::new();
        for actor in family {
            if !g.actors.contains(actor) {
                return Err(ConstraintError::UnknownFamilyActor { family_index, actor: actor.clone() });
            }
            if !members.insert(actor) {
                return Err(ConstraintError::DuplicateFamilyActor { family_index, actor: actor.clone() });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_form_branches_that_open_and_pack_one_level() {
        let mut graph = RouteGraph::default();
        for actor in ["Knight", "Mux", "Pawn", "Player", "Settle"] {
            graph.add_actor(actor);
        }
        let families = vec![actors(["Pawn", "Knight", "Mux"])];

        let forest = commitment_forest(&graph, &families).expect("family is valid");
        assert_eq!(
            forest,
            CommitmentForest {
                roots: vec![
                    CommitmentNode::Branch { children: vec![leaf("Pawn"), leaf("Knight"), leaf("Mux")] },
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
            CommitmentConstraints { families: vec![actors(["Knight", "Pawn"])], cohorts: vec![strings(["Knight", "Mux", "Pawn"])] };

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
    fn cohort_dependencies_propagate_to_upstream_emitters_without_peer_edges() {
        let mut graph = RouteGraph::default();
        graph.add_emit("A", "B");
        graph.add_actor("C");
        graph.add_emit("C", "D");
        let constraints = CommitmentConstraints { families: Vec::new(), cohorts: vec![strings(["B", "C"])] };

        let plan = commitment_plan(&graph, &constraints).expect("constraints are valid");

        assert_eq!(plan.cuts["A"], cut([&[1], &[3]]));
        assert_eq!(plan.cuts["B"], cut([&[1], &[2], &[3]]));
        assert_eq!(plan.cuts["C"], plan.cuts["B"]);
    }

    #[test]
    fn family_members_do_not_share_cuts_without_a_cohort() {
        let mut graph = RouteGraph::default();
        graph.add_actor("B");
        graph.add_emit("A", "External");
        let constraints = CommitmentConstraints { families: vec![actors(["A", "B"])], cohorts: Vec::new() };

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
        let constraints = CommitmentConstraints { families: vec![actors(["A", "Sibling"])], cohorts: vec![strings(["A", "Anchor"])] };

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

        assert_eq!(commitment_forest(&graph, &vec![Vec::new()]), Err(ConstraintError::EmptyFamily { family_index: 0 }));
        assert_eq!(
            commitment_forest(&graph, &vec![actors(["Unknown"])]),
            Err(ConstraintError::UnknownFamilyActor { family_index: 0, actor: "Unknown".to_string() })
        );
        assert_eq!(
            commitment_forest(&graph, &vec![actors(["A", "A"])]),
            Err(ConstraintError::DuplicateFamilyActor { family_index: 0, actor: "A".to_string() })
        );
        assert_eq!(
            commitment_forest(&graph, &vec![actors(["A"]), actors(["A", "B"])]),
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

    fn actors<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_string).collect()
    }

    fn strings<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
        values.into_iter().map(str::to_string).collect()
    }
}
