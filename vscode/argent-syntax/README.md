# Argent for VS Code

Lightweight VS Code language support for `.ag` files. It has no runtime
dependencies and does not require a separate language server.

Features:

- `.ag` files get the `argent` language id.
- Argent routing words such as `become`, `emits`, `consumes`, `observes`, and `spawns`
  use keyword scopes.
- Current language words such as `delegate`, `actor enum`, `virtual`,
  `expands`, `const`, `inputs`, `outputs`, and `as` are highlighted.
- Current primitive/source types such as `int`, `byte`, `bool`, `sig`, `pubkey`,
  `cov_id`, `datasig`, and `actor_type<State>` are highlighted.
- The rest of the file falls through to Rust TextMate highlighting.
- Completion includes Argent keywords, primitive types, builtins, top-level
  `state`, `actor`, `actor enum`, `fn`, `const`, and `app` declarations, plus
  actor `entry` and `delegate` callables.
- Relative imports are followed recursively, so declarations from imported
  `.ag` files participate in completion, semantic highlighting, hover, and
  go-to-definition.
- Import paths are clickable and support go-to-definition.
- `///` and `/** ... */` comments immediately above declarations appear as
  Markdown documentation in completion previews and hovers.
- Parameters of `fn`, `entry`, and `delegate` callables participate in
  completion, semantic highlighting, hover, and go-to-definition within their
  implementation bodies.
- `self.` completes fields from the enclosing actor's owned state (including
  inherited expanded-state fields); hover and go-to-definition resolve back to
  the field declaration.
- The editor indexer is tolerant of unfinished function and actor bodies.

Install locally by symlinking the unpacked extension from the repo root, then reload VS Code:

```bash
mkdir -p ~/.vscode/extensions
ln -s "$PWD/vscode/argent-syntax" ~/.vscode/extensions/kaspanet.argent-syntax-0.1.0
```

If the workspace has a manual `files.associations` entry for `*.ag`, set it to `argent` or remove it.

Run the dependency-free scanner tests with:

```bash
cd vscode/argent-syntax
npm test
```
