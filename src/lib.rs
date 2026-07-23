use std::path::{Path, PathBuf};

pub mod artifact;
pub mod ast;
pub mod builder;
pub mod codec;
pub mod emit;
pub mod error;
mod language;
pub mod lexer;
pub mod loader;
pub mod parser;
pub mod routes;
pub mod routing;

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

/// Build a file-backed Argent app into `out_dir` and return its artifact.
///
/// This is the library equivalent of `argentc build <app.ag> --out <dir>`.
/// Imports are resolved relative to the input file.
pub fn build_file(input: impl AsRef<Path>, out_dir: impl AsRef<Path>) -> Result<artifact::Artifact> {
    let program = loader::load_program(input.as_ref())?;
    emit::emit_build(&program, out_dir.as_ref())?;
    read_artifact(out_dir.as_ref())
}

/// Build one named app from a file that declares multiple apps.
///
/// Only apps declared in the input file are selectable. App declarations in
/// imported files remain supporting compilation context.
pub fn build_file_app(input: impl AsRef<Path>, app_name: &str, out_dir: impl AsRef<Path>) -> Result<artifact::Artifact> {
    let program = loader::load_program(input.as_ref())?;
    emit::emit_build_app(&program, app_name, out_dir.as_ref())?;
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
    entry bump(int delta) emits one Counter {
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

    const TWO_APPS: &str = r#"
state LeftState {
    int amount;
}

actor Left owns LeftState {
    entry bump() emits one Left {
        LeftState next = {
            amount: amount + 1,
        };
        become Left(next);
    }
}

state RightState {
    int amount;
}

actor Right owns RightState {
    entry bump() emits one Right {
        RightState next = {
            amount: amount + 1,
        };
        become Right(next);
    }
}

actor RightAlt owns RightState {
    entry bump() emits one RightAlt {
        RightState next = {
            amount: amount + 1,
        };
        become RightAlt(next);
    }
}

actor enum RightKind {
    Right;
    RightAlt;
}

app LeftApp {
    actor Left;
}

app RightApp {
    actor Right;
    actor RightAlt;
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

    #[test]
    fn build_file_writes_outputs_and_returns_artifact() {
        let temp = std::env::temp_dir().join(format!("argent-build-file-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("temp dir created");

        let input = temp.join("counter.ag");
        let out_dir = temp.join("build");
        std::fs::write(&input, COUNTER_APP).expect("source written");

        let artifact = build_file(&input, &out_dir).expect("file app builds");

        assert_eq!(artifact.app, "CounterApp");
        assert!(out_dir.join("artifact.json").exists());
        assert!(out_dir.join("sil").join("Counter.sil").exists());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn build_file_app_selects_one_root_app() {
        let temp = std::env::temp_dir().join(format!("argent-build-file-app-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("temp dir created");

        let input = temp.join("pair.ag");
        std::fs::write(&input, TWO_APPS).expect("source written");

        let left = build_file_app(&input, "LeftApp", temp.join("left")).expect("left app builds");
        assert_eq!(left.app, "LeftApp");
        assert!(left.sil_abi.contract("Left").is_some());
        assert!(left.sil_abi.contract("Right").is_none());

        let right = build_file_app(&input, "RightApp", temp.join("right")).expect("right app builds");
        assert_eq!(right.app, "RightApp");
        assert!(right.sil_abi.contract("Right").is_some());
        assert!(right.sil_abi.contract("RightAlt").is_some());
        assert!(right.sil_abi.contract("Left").is_none());
        assert!(right.argent.actor_enums.iter().any(|actor_enum| actor_enum.name == "RightKind"));

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn build_file_app_removes_stale_selected_app_contracts() {
        let temp = std::env::temp_dir().join(format!("argent-build-file-app-clean-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("temp dir created");

        let input = temp.join("pair.ag");
        let out_dir = temp.join("build");
        std::fs::write(&input, TWO_APPS).expect("source written");

        build_file_app(&input, "LeftApp", &out_dir).expect("left app builds");
        assert!(out_dir.join("sil/Left.sil").exists());

        build_file_app(&input, "RightApp", &out_dir).expect("right app builds");
        assert!(!out_dir.join("sil/Left.sil").exists());
        assert!(out_dir.join("sil/Right.sil").exists());
        assert!(out_dir.join("sil/RightAlt.sil").exists());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn build_file_requires_selection_for_multiple_root_apps() {
        let temp = std::env::temp_dir().join(format!("argent-build-file-ambiguous-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).expect("temp dir created");

        let input = temp.join("pair.ag");
        std::fs::write(&input, TWO_APPS).expect("source written");

        let error = build_file(&input, temp.join("build")).expect_err("app selection is required");
        assert!(error.to_string().contains("select one with `--app <name>`"));

        let _ = std::fs::remove_dir_all(temp);
    }
}
