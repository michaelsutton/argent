use std::env;
use std::path::PathBuf;

use argent::emit::{emit_build, emit_build_app};
use argent::loader::load_program;
use argent::{ArgentError, Result};

fn main() {
    if let Err(err) = run() {
        eprintln!("argentc: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    let command = args.remove(0);
    match command.as_str() {
        "build" => build(args),
        _ => Err(ArgentError::new(format!("unknown command `{command}`"))),
    }
}

fn build(args: Vec<String>) -> Result<()> {
    let mut input = None;
    let mut app_name = None;
    let mut out_dir = PathBuf::from("build/argent");
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--out" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| ArgentError::new("missing value after --out"))?;
                out_dir = PathBuf::from(value);
            }
            "--app" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| ArgentError::new("missing value after --app"))?;
                app_name = Some(value.clone());
            }
            value if input.is_none() => input = Some(PathBuf::from(value)),
            value => return Err(ArgentError::new(format!("unexpected argument `{value}`"))),
        }
        idx += 1;
    }

    let input = input.ok_or_else(|| ArgentError::new("missing input .ag file"))?;
    let program = load_program(&input)?;
    if let Some(app_name) = app_name {
        emit_build_app(&program, &app_name, &out_dir)?;
    } else {
        emit_build(&program, &out_dir)?;
    }
    println!("wrote {}", out_dir.display());
    Ok(())
}

fn print_usage() {
    eprintln!("usage: argentc build <app.ag> [--app <name>] [--out <dir>]");
}
