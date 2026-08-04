# franken-lsp — Editor / LSP Setup

> Editor integration for the E5 authority/intake analyzer (`bd-fqlfw.5.3`,
> `bd-fqlfw.5.6`). `franken-lsp` surfaces the same authority-footprint findings
> as `frankenctl check` as live editor diagnostics, sharing the
> [`analyze_authority_footprint`](../../crates/franken-engine/src/authority_footprint.rs)
> core — there is no second analysis model, so the editor and the CLI agree.

## What it does

`franken-lsp` is a minimal [Language Server Protocol](https://microsoft.github.io/language-server-protocol/)
server. It reads JSON-RPC messages over **stdin/stdout** (standard `Content-Length`
framing) and publishes authority-footprint diagnostics as you edit: ambient-authority
rejections (`FE-CAP-0001`), denied flows (`FE-CAP-0002`), and required-declassification
obligations (`FE-CAP-0003`), each at its source span. It is read-only and
side-effect-free; it never executes the analyzed source.

## Build

```bash
cargo build --release -p frankenengine-engine --bin franken-lsp
# binary at ./target/release/franken-lsp
```

## Supported LSP methods

| Method | Behavior |
|---|---|
| `initialize` | Handshake. Honors `initializationOptions.parse_goal` (`"script"` \| `"module"`; default `script`). |
| `textDocument/didOpen` / `didChange` | Re-analyzes the document and publishes `textDocument/publishDiagnostics`. |
| `textDocument/didClose` | Drops the document's state. |
| `textDocument/hover` | Hover text for the finding at a position (the implied capability / IFC obligation). |
| `textDocument/codeLens` | Per-finding code lenses with stable IDs. |
| `shutdown` / `exit` | Orderly teardown. |

Diagnostics are emitted via `textDocument/publishDiagnostics`. Because the server
reuses the CLI analyzer, a diagnostic in the editor is exactly a `frankenctl check`
finding for the same source and parse goal.

## Editor configuration

### Neovim (built-in LSP)

```lua
vim.api.nvim_create_autocmd("FileType", {
  pattern = { "javascript", "typescript" },
  callback = function(args)
    vim.lsp.start({
      name = "franken-lsp",
      cmd = { "/abs/path/to/target/release/franken-lsp" },
      root_dir = vim.fs.dirname(vim.fs.find({ ".git" }, { upward = true })[1]),
      init_options = { parse_goal = "module" },  -- or "script"
    })
  end,
})
```

### VS Code

`franken-lsp` speaks stdio LSP, so a thin extension that launches it as a
`LanguageClient` with `TransportKind.stdio` works:

```ts
const serverOptions: ServerOptions = {
  command: "/abs/path/to/target/release/franken-lsp",
  transport: TransportKind.stdio,
};
const clientOptions: LanguageClientOptions = {
  documentSelector: [{ language: "javascript" }, { language: "typescript" }],
  initializationOptions: { parse_goal: "module" },
};
new LanguageClient("frankenLsp", "FrankenEngine Authority Footprint", serverOptions, clientOptions).start();
```

### Generic stdio client

Any editor that can launch a stdio LSP server works: point it at the
`franken-lsp` binary, select `javascript`/`typescript` documents, and optionally
pass `initializationOptions.parse_goal`.

## Bounded-claim note

`franken-lsp` shows the **inferred authority footprint for supported syntax** — the
same bound as `frankenctl check` (see
[`AUTHORITY_FOOTPRINT_ANALYZED_SUBSET_V1.md`](../AUTHORITY_FOOTPRINT_ANALYZED_SUBSET_V1.md)).
Absence of a diagnostic is **not** a proof of noninterference; constructs the
pipeline cannot lower are not analyzed (the CLI surfaces this as `unanalyzable` /
`bounded_at_first_violation`, exit `2`/bounded). Treat the diagnostics as an
authority-footprint aid, not a security clearance.
