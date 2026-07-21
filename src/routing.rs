//! Pure graph and commitment-tree structures used to plan actor routing.

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

/// Invalid family membership supplied to commitment-forest construction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FamilyError {
    #[error("family {family_index} is empty")]
    Empty { family_index: usize },
    #[error("family {family_index} contains unknown actor `{actor}`")]
    UnknownActor { family_index: usize, actor: String },
    #[error("actor `{actor}` belongs to more than one family")]
    OverlappingActor { actor: String },
}

/// Build a deterministic forest with one branch per family and one actor root
/// for every actor outside a family.
///
/// Family children follow actor order. A family branch occupies the root
/// position of its first actor, so the order of `families` does not affect the
/// forest structure.
pub fn commitment_forest(g: &RouteGraph, families: &Families) -> Result<CommitmentForest, FamilyError> {
    let family_by_actor = validate_families(g, families)?;

    let mut roots = Vec::new();
    let mut emitted_families = BTreeSet::new();
    // Actor order places each family at its lowest member independently of the
    // order in which the family sets were supplied.
    for actor in &g.actors {
        let Some(family_index) = family_by_actor.get(actor).copied() else {
            roots.push(CommitmentNode::Leaf { actor: actor.clone() });
            continue;
        };
        if !emitted_families.insert(family_index) {
            continue;
        }

        let children = families[family_index].iter().map(|actor| CommitmentNode::Leaf { actor: actor.clone() }).collect();
        roots.push(CommitmentNode::Branch { children });
    }

    Ok(CommitmentForest { roots })
}

/// Validate family membership and return each family actor's family index.
fn validate_families(g: &RouteGraph, families: &Families) -> Result<BTreeMap<String, usize>, FamilyError> {
    let mut family_by_actor = BTreeMap::<String, usize>::new();
    for (family_index, family) in families.iter().enumerate() {
        if family.is_empty() {
            return Err(FamilyError::Empty { family_index });
        }
        for actor in family {
            if !g.actors.contains(actor) {
                return Err(FamilyError::UnknownActor { family_index, actor: actor.clone() });
            }
            if family_by_actor.insert(actor.clone(), family_index).is_some() {
                return Err(FamilyError::OverlappingActor { actor: actor.clone() });
            }
        }
    }
    Ok(family_by_actor)
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
    fn commitment_forest_rejects_invalid_families() {
        let mut graph = RouteGraph::default();
        graph.add_actor("A");
        graph.add_actor("B");

        assert_eq!(commitment_forest(&graph, &vec![BTreeSet::new()]), Err(FamilyError::Empty { family_index: 0 }));
        assert_eq!(
            commitment_forest(&graph, &vec![strings(["Unknown"])]),
            Err(FamilyError::UnknownActor { family_index: 0, actor: "Unknown".to_string() })
        );
        assert_eq!(
            commitment_forest(&graph, &vec![strings(["A"]), strings(["A", "B"])]),
            Err(FamilyError::OverlappingActor { actor: "A".to_string() })
        );
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
