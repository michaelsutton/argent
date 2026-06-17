use std::env;
use std::path::PathBuf;

use argent::emit::emit_build;
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
    let mut out_dir = PathBuf::from("build/argent");
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--out" => {
                idx += 1;
                let value = args.get(idx).ok_or_else(|| ArgentError::new("missing value after --out"))?;
                out_dir = PathBuf::from(value);
            }
            value if input.is_none() => input = Some(PathBuf::from(value)),
            value => return Err(ArgentError::new(format!("unexpected argument `{value}`"))),
        }
        idx += 1;
    }

    let input = input.ok_or_else(|| ArgentError::new("missing input .ag file"))?;
    let program = load_program(&input)?;
    emit_build(&program, &out_dir)?;
    println!("wrote {}", out_dir.display());
    Ok(())
}

fn print_usage() {
    eprintln!("usage: argentc build <app.ag> [--out <dir>]");
}
