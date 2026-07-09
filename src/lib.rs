use std::path::{Path, PathBuf};

pub mod artifact;
pub mod ast;
pub mod builder;
pub mod codec;
pub mod emit;
pub mod error;
pub mod lexer;
pub mod loader;
pub mod parser;
pub mod routes;

pub use error::{ArgentError, Result};

/// Compile an inline Argent source string and return its artifact.
///
/// `source_label` is used for diagnostics and module identity; it does not
/// need to exist on disk.
pub fn compile_inline(source_label: impl AsRef<Path>, source: impl Into<String>) -> Result<artifact::Artifact> {
    let nonce =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|duration| duration.as_nanos()).unwrap_or_default();
    let out_dir = std::env::temp_dir().join(format!("argent-inline-{}-{nonce}", std::process::id()));
    let artifact = build_inline(source_label, source, &out_dir);
    if artifact.is_ok() {
        let _ = std::fs::remove_dir_all(&out_dir);
    }
    artifact
}

/// Build an inline Argent source string into `out_dir` and return its artifact.
///
/// This writes the same generated files as `argentc build`, including
/// `artifact.json`, `manifest.json`, and generated Silverscript contracts.
pub fn build_inline(
    source_label: impl AsRef<Path>,
    source: impl Into<String>,
    out_dir: impl AsRef<Path>,
) -> Result<artifact::Artifact> {
    let source_label = source_label.as_ref().to_path_buf();
    let program = inline_program(source_label, source.into())?;
    emit::emit_build(&program, out_dir.as_ref())?;
    read_artifact(out_dir.as_ref())
}

fn inline_program(source_label: PathBuf, source: String) -> Result<ast::Program> {
    let module = parser::parse_module(source_label.clone(), source)?;
    Ok(ast::Program { root: source_label, modules: vec![module] })
}

fn read_artifact(out_dir: &Path) -> Result<artifact::Artifact> {
    let path = out_dir.join("artifact.json");
    let json = std::fs::read_to_string(&path)?;
    serde_json::from_str(&json).map_err(|err| ArgentError::at(path, err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER_APP: &str = r#"
state CounterState {
    int count;
}

actor Counter owns CounterState {
    entry bump(delta: int) emits one Counter {
        CounterState next = {
            count: count + delta,
        };

        become Counter(next);
    }
}

app CounterApp {
    actor Counter;
}
"#;

    #[test]
    fn compile_inline_returns_artifact_without_a_user_output_dir() {
        let artifact = compile_inline("counter.ag", COUNTER_APP).expect("inline app compiles");
        assert_eq!(artifact.app, "CounterApp");
        assert!(artifact.sil_abi.contract("Counter").is_some());
    }

    #[test]
    fn build_inline_writes_outputs_and_returns_artifact() {
        let out_dir = std::env::temp_dir().join(format!("argent-build-inline-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out_dir);

        let artifact = build_inline("counter.ag", COUNTER_APP, &out_dir).expect("inline app builds");

        assert_eq!(artifact.app, "CounterApp");
        assert!(out_dir.join("artifact.json").exists());
        assert!(out_dir.join("sil").join("Counter.sil").exists());

        let _ = std::fs::remove_dir_all(out_dir);
    }
}
