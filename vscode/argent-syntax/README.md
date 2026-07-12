# Argent Syntax

Tiny VS Code syntax extension for `.ag` files.

It intentionally does only highlighting:

- `.ag` files get the `argent` language id.
- Argent routing words such as `become`, `emits`, `consumes`, and `observes`
  use keyword scopes.
- Current language words such as `delegate`, `actor enum`, `virtual`,
  `expands`, `const`, `inputs`, `outputs`, and `as` are highlighted.
- Current primitive/source types such as `int`, `byte`, `bool`, `sig`, `pubkey`,
  `covid`, `datasig`, and `actor_type<State>` are highlighted.
- The rest of the file falls through to Rust TextMate highlighting.

Install locally by symlinking the unpacked extension from the repo root, then reload VS Code:

```bash
mkdir -p ~/.vscode/extensions
ln -s "$PWD/vscode/argent-syntax" ~/.vscode/extensions/kaspanet.argent-syntax-0.0.1
```

If the workspace has a manual `files.associations` entry for `*.ag`, set it to `argent` or remove it.
