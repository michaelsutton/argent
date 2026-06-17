use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ast::{Import, Program};
use crate::error::{ArgentError, Result};
use crate::parser::parse_module;

pub fn load_program(root: impl AsRef<Path>) -> Result<Program> {
    let root = root.as_ref().to_path_buf();
    let canonical_root = fs::canonicalize(&root).map_err(|err| ArgentError::at(&root, err.to_string()))?;
    let mut loader = Loader { visited: BTreeSet::new(), modules: Vec::new() };
    loader.load_module(&canonical_root)?;
    Ok(Program { root: canonical_root, modules: loader.modules })
}

struct Loader {
    visited: BTreeSet<PathBuf>,
    modules: Vec<crate::ast::Module>,
}

impl Loader {
    fn load_module(&mut self, path: &Path) -> Result<()> {
        let canonical = fs::canonicalize(path).map_err(|err| ArgentError::at(path, err.to_string()))?;
        if !self.visited.insert(canonical.clone()) {
            return Ok(());
        }

        let source = fs::read_to_string(&canonical).map_err(|err| ArgentError::at(&canonical, err.to_string()))?;
        let module = parse_module(canonical.clone(), source)?;
        let base = canonical.parent().ok_or_else(|| ArgentError::at(&canonical, "module path has no parent"))?.to_path_buf();
        let imports = module.imports.clone();
        self.modules.push(module);

        for import in imports {
            let import_path = match import {
                Import::Module { path } | Import::Actor { path, .. } => path,
            };
            self.load_module(&base.join(import_path))?;
        }

        Ok(())
    }
}
