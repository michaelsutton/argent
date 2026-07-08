#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

regen_examples=false

case "${1:-}" in
    "")
        ;;
    --regen-examples|--full)
        regen_examples=true
        ;;
    -h|--help)
        cat <<'USAGE'
Usage: ./check.sh [--regen-examples|--full]

Runs the standard local verification loop.

Options:
  --regen-examples, --full  Regenerate tracked example build outputs first.
  -h, --help                Show this help.
USAGE
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        echo "try: ./check.sh --help" >&2
        exit 2
        ;;
esac

cargo fmt --check
cargo check --workspace

if [ "$regen_examples" = true ]; then
    cargo run -- build examples/tickets.ag --out examples/build/tickets
    cargo run -- build examples/stones/app.ag --out examples/build/stones
    cargo run -- build examples/toy_chess/app.ag --out examples/build/toy_chess
    cargo run -- build examples/icc/kcc20_asset.ag --out examples/build/icc_kcc20_asset
    cargo run -- build examples/icc/minter.ag --out examples/build/icc_minter
    cargo run -- build examples/open_icc/agent.ag --out examples/build/open_icc_agent
    cargo run -- build examples/open_icc/core.ag --out examples/build/open_icc_core
fi

cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
