# OpenMind architecture

How OpenMind is put together, how it plugs into OpenCode, and where each
security boundary lives. Read this alongside the `Security and VAPT` section of
[README.md](./README.md).

## 1. What OpenMind is

OpenMind is a single-file OpenCode plugin (`index.js`) plus one Python helper
(`lib/imgread.py`). It provides:

- **Durable, project-scoped memory** — an opt-in JSONL store with BM25 recall and
  a bounded auto-injection budget.
- **`listen_analyze`** — an SSRF-hardened fetcher and extractor for one public
  web page, exposed as the `/listen` slash command.
- **`image_read`** — attaches real images and rasterized PDFs to the model, with
  OCR and SSRF-guarded URL reads, exposed as `/imgread`.

OpenMind never records sessions. A memory exists only because a tool call
explicitly created it, and it belongs to the worktree it was created in.

## 2. Repository layout

```
index.js              the whole plugin: tools, store, crypto, listen, image
lib/imgread.py        image/PDF/OCR helper (invoked with an argv array, no shell)
commands/             /listen and /imgread slash commands (copied by install.mjs)
install.mjs           cross-platform setup: deps, plugin registration, commands
install.sh/.cmd/.ps1  thin launchers around install.mjs
test/                 12 executable suites (see section 9)
.github/workflows/    CI: lint + syntax check + the full suite on Node 22 and 24
```

There is no build step and no runtime dependency beyond `@opencode-ai/plugin`;
the plugin is the source you read.

## 3. OpenCode integration

`index.js` has two surfaces:

| Surface | Shape | Who uses it |
| --- | --- | --- |
| `export default { id: "openmind", async setup(ctx) }` | OpenCode **V2** plugin definition | OpenCode at runtime |
| `export const MemoryPlugin = async (input, options) => ({ tool, ...hooks })` | V1-style factory returning the core | the test suite, and `setup()` internally |

`setup(ctx)` is the adapter:

- **Tools** — `ctx.tool.transform((editor) => …)` re-registers every entry of
  `core.tool`, converting the historical fluent `args` builders into a plain
  JSON Schema (`makeSchema`/`tool` shim) and wrapping `execute` so its
  `{ title, output, metadata, attachments }` result becomes the V2
  `{ content, metadata }` shape (`toToolResult`).
- **Project resolution** — V2 tool context carries only a `sessionID`, so
  `directoryFor(sessionID)` resolves the session's own directory via
  `ctx.session.get(...)` (cached), falling back to the plugin load directory.
- **Memory injection** — `ctx.session.hook("context", …)` calls the shared
  `experimental.chat.system.transform` handler and pushes the rendered memory
  block (and any startup warning) onto `event.system`.
- **Shell environment** — `ctx.shell.hook("create.before", …)` calls the shared
  `shell.env` handler, exporting `OPENCODE_MEMORY_FILE` and
  `OPENCODE_MEMORY_PROJECT` for subprocesses.

The V1 hook names are kept as the internal interface because the tests drive
them directly; `setup()` is a thin translation layer over the same logic.

Local (non-npm) installs are registered by `install.mjs` as
`opencode plugin <root> --global --force`, which is why the README's manual
config shows a **path** entry rather than a package name.

## 4. Tool surface

12 tools, all defined once inside `MemoryPlugin`:

| Tool | Purpose |
| --- | --- |
| `memory_remember` | save/update one project memory (near-duplicates dedupe) |
| `memory_update` | edit text/tags/source/pinned by id |
| `memory_recall` | BM25 search, `-token` negation, tag filter |
| `memory_list` | recent memories for this project |
| `memory_unlock` | verify password / enable encryption (5-attempt lockout) |
| `memory_forget` | delete one memory by id |
| `memory_prune` | preview then delete by id, text, or tag |
| `memory_delete_store` | delete all memories and the store file |
| `memory_reassign` | rebind memories orphaned by a move/rename |
| `memory_export` | inspect/export visible (or all) memories |
| `image_read` | attach an image/PDF plus OCR text |
| `listen_analyze` | fetch and analyze one public page |

Every tool body runs through `guarded()`, which converts an escaping exception
into a readable tool result instead of breaking the turn.

## 5. Store, scoping, and encryption

- **Location** — `$OPENCODE_MEMORY_DIR`, else the XDG/APPDATA data dir, ending
  in `memories.jsonl`. Directories are `0700`, files `0600`.
- **Scope** — project-only. A memory's `project` field is a hash of the
  worktree path (or `ns:<name>` when a namespace is set); every read filters on
  exact match. There is deliberately no global or session scope.
- **Format** — one JSON object per line. Plaintext is the default; an
  encrypted store begins with `OPENMIND_ENC_V3`, an `scrypt` parameter line, and
  `salt:iv:authTag:ciphertext` (AES-256-GCM). Plaintext lines that are not
  valid JSON are parsed as legacy records or skipped, never trusted.
- **Atomicity** — writes go through `writeAtomic` (temp file + `rename`), which
  also replaces a symlink rather than writing through it. Plaintext appends use
  an O(1) fast path with a defensive rewrite fallback.
- **Key handling** — the derived key is cached per store file, keyed by a
  SHA-256 of the password, and cleared when the password changes or the store is
  deleted. Password files must be `0600` regular files ≤ 4096 bytes, and every
  rejection reports the same message so the tool cannot probe a path.

## 6. Concurrency

Two writers must not corrupt the JSONL. OpenMind layers:

1. an **in-process mutex** (`withLock`) so one event loop serialises mutations, and
2. a **cross-process lockfile** (`*.lock`) carrying `pid:host:token:timestamp`.

The lock is stolen only when it is older than a grace period **and** the recorded
owner is provably gone, and a holder removes the lockfile only if it still
carries its own token. This is exercised by `test/concurrency.mjs`.

## 7. Recall and injection

- **Recall** — BM25 over a weighted document (`text` > `tags` > `source`). Query
  terms match verbatim or stemmed, by prefix, or with one edit inside words of
  five or more characters. Negated `-terms` exclude. The recorded project path is
  never indexed, so a query naming the directory does not match everything.
- **Injection** — pinned first, then relevance to the last user message, then
  recency, bounded by `injectLimit` (count), `injectMaxChars` (total) and
  `injectItemMaxChars` (per entry). Each memory is clipped before the budget is
  spent, and an entry that does not fit is skipped rather than ending the pass.
  Web-derived memories are fenced and tagged `listen`, and carry an UNTRUSTED
  warning that survives later tag updates.

## 8. Network I/O guards

**`listen_analyze` / `/listen`** (`fetchPublicResource`):

- scheme and port allowlist; only `http`/`https`;
- hostname resolved once with DNS; private, loopback, link-local, reserved,
  `.local`, `.internal` and cloud-metadata answers abort before any request;
- the vetted address is **pinned** via a custom `lookup`, so a short-TTL record
  cannot re-answer `127.0.0.1`; SNI/Host/TLS stay on the original name;
- every redirect is re-screened and re-pinned under a redirect cap;
- a single wall-clock deadline covers `robots.txt`, redirects and the body;
- bodies are streamed against a size cap and decompressed with a bounded output;
- a strict HTML content-type gate, and regex-free extraction (globs and
  `indexOf` scans) to avoid catastrophic backtracking;
- `robots.txt` is honoured (fail-open on network error) unless
  `OPENCODE_MEMORY_IGNORE_ROBOTS=1`.

**`image_read`** reuses the same DNS-resolution + private-address rules for URL
targets, streams against a 25 MB cap, and spawns `lib/imgread.py` with an
argument array (never a shell). Local reads are refuse-by-default: only image
files are parsed and raw bytes are never echoed.

## 9. Testing and CI

`npm test` runs ESLint, `node --check`, then 12 suites:

`smoke`, `compat`, `encryption`, `locked`, `concurrency`, `store`, `ranking`,
`security`, `image`, `listen`, `vapt`, `vapt2`.

They are executable and hermetic: each creates its own temp store, and the
network suites run against a loopback test server whose hostname resolves to a
private address, which the guard must block. `.github/workflows/ci.yml` runs the
same gate with `npm ci` on Node 22 and 24, so a lockfile/config drift or a
newer-than-supported API fails in CI rather than in someone's install.
