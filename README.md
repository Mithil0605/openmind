# OpenMind v5

Privacy-first, user-controlled memory tools for **OpenCode V2** on Windows, Linux, and macOS — project-scoped BM25 recall, an SSRF-guarded web listener/analyzer, image and PDF reading with OCR, and optional AES-256-GCM encryption.

OpenMind installs as a single OpenCode plugin that registers 12 tools and a bounded memory-injection hook. It never saves sessions. Durable memory is opt-in and is limited to explicit project preferences. Users can permanently delete one item, matching unwanted items, or the entire backing store.

The store can be encrypted with AES-256-GCM. A password is verified like `sudo`, with a 5-attempt rate limit that locks access for 5 minutes after repeated failures.

For how the plugin is wired into OpenCode and where each security boundary lives, see [ARCHITECTURE.md](./ARCHITECTURE.md).

## The /listen Command

OpenMind v5 ships a `/listen` slash command for web listening, learning, and analysis. The setup script copies it into your OpenCode config directory (`commands/`), so it is available after install.

1. Type `/listen https://example.com` (or just `/listen` and let the model ask for the URL).
2. OpenMind fetches that single page over HTTPS/HTTP and analyzes it: title, meta tags, Open Graph data, heading outline, links, images, code snippets, tables, lists, visible text, and a detected technology stack (React, Vue, Next.js, Tailwind, and more).
3. Add `permanent: true` (or say "remember this") to also save a summary of the findings to OpenMind memory for this project.

`/listen` is SSRF-guarded — private IPs, loopback addresses, cloud metadata endpoints, `.local`/`.internal` domains, and link-local IPv6 are all blocked before any request is made — and it honors `robots.txt` (set `OPENCODE_MEMORY_IGNORE_ROBOTS=1` to opt out on a host you own).

Only the URL you give is fetched: links are listed, never followed, and JavaScript is never executed, so a client-rendered page will legitimately come back with little text. The model is told to report that rather than filling the gap.

### What `/listen` Extracts

- **Metadata**: title, description, author, keywords, canonical, robots
- **Open Graph**: og:title, og:description, og:image, og:type, etc.
- **Structure**: full heading hierarchy (H1–H6)
- **Content**: paragraphs and body text, trimmed to the first 10,000 characters (2,000 with `depth: "quick"`)
- **Navigation**: all external links with anchor text
- **Media**: image sources and alt text
- **Code**: `<pre><code>` blocks
- **Data**: tables and lists
- **Tech stack**: automatic detection of React, Vue, Angular, Next.js, Nuxt, Svelte, Tailwind, Bootstrap, jQuery, WordPress, Drupal, Joomla, Shopify, Gatsby, Astro, Cloudflare, Nginx, Apache, Vercel

`depth: "quick"` returns metadata, tech stack, and text only. The whole report is capped (24,000 characters, 512 KB response in quick mode, 5 MB in full mode) under one shared 30-second deadline that covers `robots.txt`, redirects, and the page.

## Easiest Install

For non-technical users, use [SETUP.md](./SETUP.md).

Windows: double-click `install.cmd`.

Linux/macOS: run:

```bash
sh ./install.sh
```

This installs the plugin dependency, registers the plugin with OpenCode, **and copies the `/listen` and `/imgread` slash commands** into your OpenCode config directory. Then restart OpenCode.

To install only the slash commands into the current project instead of your global config:

```bash
node install.mjs --commands project
```

## Install From npm

After publishing this package to npm:

```bash
opencode plugin openmind-v5 --global
```

Restart OpenCode after installation. This registers the plugin only. To get the `/listen` and `/imgread` slash commands as well, run `node install.mjs` once, or copy the files in the package's `commands/` directory into `.opencode/commands/` (OpenCode reads both `command/` and `commands/`).

## Install From a Local Folder

Linux/macOS:

```bash
git clone <repo-url> opencode-memory-extension
cd opencode-memory-extension
npm install
node install.mjs
```

Windows PowerShell:

```powershell
git clone <repo-url> opencode-memory-extension
cd opencode-memory-extension
npm install
node install.mjs
```

Or register the plugin by hand without the setup script:

```bash
opencode plugin "$(pwd)" --global --force
```

## Manual Config

OpenCode stores global config under its config directory. You can also add the plugin manually.

Linux/macOS example:

```json
{
  "plugin": [
    ["./path/to/opencode-memory-extension", {
      "autoInject": true,
      "injectLimit": 8
    }]
  ]
}
```

Windows example:

```json
{
  "plugin": [
    ["C:\\Users\\you\\code\\opencode-memory-extension", {
      "autoInject": true,
      "injectLimit": 8
    }]
  ]
}
```

## Tools

- `memory_remember`: explicitly save a project memory (identical or near-identical text updates the existing memory instead of duplicating)
- `memory_update`: update text, tags, source, or the pinned flag of an existing memory by id
- `memory_recall`: search memories with BM25-style ranking; prefix a token with `-` to exclude memories containing it
- `memory_list`: list recent memories
- `memory_unlock`: verify the store password to enable encryption or access an encrypted store (5-attempt rate limit). Takes `passwordFile` (preferred) or `password`
- `memory_forget`: permanently delete a memory by id
- `memory_prune`: preview then permanently delete unwanted memories by id, text, or tag
- `memory_delete_store`: permanently delete all memories and remove the storage file
- `memory_reassign`: list and rebind orphaned memories (records whose recorded project path is no longer the current worktree, e.g. after the directory was renamed or moved). Orphaned memories are invisible to every other tool, so this is the recovery path.
- `memory_export`: show/export stored memories
- `image_read`: read an image or PDF so the model can actually *see* it — attaches the real image to the conversation and reports format, dimensions, and OCR'd text. Accepts a local path or an http(s) URL. Only image files are read; everything else is refused without revealing contents. URLs are SSRF-guarded (private, loopback, link-local, and cloud-metadata hosts are blocked).
- `listen_analyze`: fetch and comprehensively analyze one public website: metadata, Open Graph data, headings, links, images, code, tables, lists, full text, and detected tech stack. SSRF-guarded, honors `robots.txt`, and runs under size, deadline, and content-type limits. Backed by the `/listen` slash command.

### How recall ranks

Ranking is BM25 over a weighted bag: text counts more than tags, tags more than source, and the recorded project path is never indexed (it is a path, not content). Recall is deliberately forgiving:

- tokens are matched verbatim *and* stemmed, so `test` finds `tests` while identifiers like `redis` stay exact;
- a query term matches a longer indexed term by prefix (`kubern` → `kubernetes`);
- a one-character typo in words of five or more characters still matches (`webhok` → `webhook`), scored lower than an exact hit.

`memory_recall` only ever returns memories belonging to the current worktree.

## Image Reading

`image_read` removes the common LLM image limitations at the CLI:

- **Real image attachment** — the downscaled PNG is returned as an attachment, so the model sees the picture instead of a text description of it (capped at 8 MB per image; pass `attach: false` for metadata-only).
- **PDFs** — rasterized page by page with `pdftoppm`/`pdftocairo`, `mutool`, or `gs`, then attached and OCR'd. `pages` selects how many pages (1–5).
- **Web URLs** — downloads public images automatically (requires `python3`), streamed against a 25 MB cap and a 30-second deadline.
- **Large images** — downscales over the `max` cap (default 1400) so the model can ingest them.
- **Fine text / OCR** — runs `tesseract` directly (no Python needed) and returns the extracted text. `python3` + Pillow is the fallback path when tesseract itself is unavailable.
- **Vector images** — dumps SVG markup as text.
- **Format support** — PNG, JPEG, GIF, BMP, WEBP, TIFF, SVG, PDF.

Examples the model can act on:

```text
Read the screenshot at ./assets/login.png and tell me what it shows.
What text is on this QR code image? /data/qr.png
Summarize the first two pages of the attached spec PDF.
Read the diagram at https://example.com/architecture.svg, no OCR needed.
```

`image_read` is deliberately refuse-by-default: it reads only image files and never echoes arbitrary file contents, so it cannot be misused as a file-exfiltration channel. If `python3` (with Pillow) is not installed, OpenMind falls back to JavaScript: it reads only the first 64 bytes to report type and dimensions, attempts OCR via `tesseract`, and URL reading is unavailable. Without any of `python3`+Pillow, `tesseract`, or a PDF rasterizer, a PDF cannot be shown and the tool says so instead of pretending.

## Known limitations

Stated plainly so nothing here is a surprise:

- No JavaScript rendering. A single-page app fetched over plain HTTP returns its shell, not its content; `/listen` reports that explicitly.
- No link following and no crawling. Exactly one URL is fetched per call.
- No proxy or custom-CA support in the fetcher; corporate TLS interception will fail the request.
- `robots.txt` is honored on a best-effort basis and fails open on network errors, which is the de-facto standard but not an access-control boundary.
- Extraction is regex-based HTML parsing, not a browser DOM: malformed markup and content assembled only by script will be missed.
- Injection is keyword-relevance ranked, not semantic. It cannot tell that "the deploy script" and "ship.sh" mean the same thing.
- Memories are private to the worktree they were saved in. There is no cross-project search; use `memory_export` with `scope: "all"` to move things deliberately, or set a shared `namespace`.
- OCR quality depends entirely on `tesseract`; a scanned, skewed, or low-contrast document will extract poorly.
- A single attachment is capped at 8 MB and PDFs at 5 pages per call — call again for more.


## Security and VAPT

OpenMind v5 ships with a built-in static and dynamic security test suite, plus eslint and a GitHub Actions workflow that runs both on every push. `npm test` runs lint and all twelve suites: `test/smoke.mjs`, `test/compat.mjs`, `test/encryption.mjs`, `test/locked.mjs`, `test/concurrency.mjs`, `test/store.mjs`, `test/ranking.mjs`, `test/security.mjs`, `test/image.mjs`, `test/listen.mjs`, `test/vapt.mjs`, and `test/vapt2.mjs`:

- **Input injection / fuzzing** — newline-forged records, prototype-pollution tags, oversized text, regex metacharacters in queries.
- **Tampered and corrupt stores** — the plugin never crashes or leaks partial data.
- **Symlink attacks** — atomic writes replace the file instead of writing through a link.
- **Cross-process concurrency** — parallel writers never corrupt the JSONL format. A lockfile records the owner pid and host: it is stolen only when it is older than the grace period *and* the owner is provably gone, and a holder only ever removes a lockfile carrying its own token.
- **Store isolation** — two stores open at once share no vault state, key cache, or password, and deleting a store clears its lockout counters and leaves no lockfile behind.
- **Context budget** — injection is capped by total characters, not just a memory count, so one oversized memory cannot crowd out the rest; an entry that does not fit is skipped instead of ending the pass.
- **Ranking integrity** — the project path is never indexed as searchable content, and field weights keep tag hits below text hits.
- **Encryption** — AES-256-GCM authentication rejects tampered ciphertext; locked stores never disclose contents; 5-attempt lockout that only counts failures from the interactive `memory_unlock` path. The derived-key cache is scoped per store file and cleared when the password changes or the store is deleted.
- **Command injection** — `image_read` spawns the helper with an argument array (no shell); flag-like, control-character, and oversized targets are rejected up front.
- **SSRF for image URLs** — URL hosts are DNS-resolved once and any private/loopback/link-local answer (including `169.254.169.254`) blocks the fetch. The vetted address is then **pinned**: the connection dials that IP directly, so a short-TTL record cannot answer `127.0.0.1` on a second lookup. Host name, `Host` header, TLS SNI and certificate verification all still use the original name, redirects re-screen and re-pin per hop, ports are allowlisted, and proxies are disabled so the pin cannot be bypassed.
- **SSRF for web listening** — `listen_analyze` resolves the hostname with DNS and blocks private, loopback, link-local, reserved, `.local`, `.internal`, and cloud-metadata addresses before any request is made. Only `http`/`https` protocols are allowed.
- **Web fetch limits** — response cap (5 MB full / 512 KB quick), one shared 30-second deadline across `robots.txt`, redirects and the page, a strict HTML content-type gate, and bounded decompression of `gzip`/`deflate`/`br` bodies.
- **No catastrophic regex backtracking** — `robots.txt` patterns are matched as globs with a linear scan rather than a regex (a `*`-heavy rule is a measured ReDoS otherwise, and capping the star count does not fix it), and HTML containers are walked with `indexOf` rather than `[\s\S]*?`, which is quadratic on unclosed tags.
- **robots.txt** — a named group beats the wildcard group, patterns support `*` and trailing `$`, `Allow` wins ties, and the file is fetched under its own short deadline with a fail-open default.
- **Prompt injection** — a `/listen` page's prose is never stored. Only facts *about* the page are saved, with newlines, markup, and invisible formatting characters (including RTL overrides) stripped. Injected memories are fenced, the fence delimiter is escaped so a memory cannot close it, and web-derived entries carry an explicit UNTRUSTED warning that survives tag updates.
- **No content leak** — refused file types and corrupt images report a safe message, never the file bytes.
- **Errors are values** — a failing store returns a readable tool result instead of throwing out of the tool and breaking the turn.
- **Permissions** — store files `0600`; store directories are `0700`, tightened on every write even if they already existed more permissively. Temp files are created with `mkstemp` or exclusive `0600` creation, never from a predictable name.

## Encryption and Password

The store is plaintext by default for compatibility. Ask OpenCode to unlock the store with a password:

```text
Unlock the memory store with my password.
```

> **Passing a password as a tool argument sends it to your model provider** and it is normally kept in the session transcript and logs. Nothing that protects your memories needs to travel through an LLM, so prefer one of the two options below. `sudo`-style interactive unlocking is kept for convenience, not because it is the safe path.

The safe options:

```json
{
  "plugin": [
    ["opencode-memory-extension", {
      "passwordFile": "~/.config/opencode/memory.pw",
      "autoInject": true
    }]
  ]
}
```

or the environment variable `OPENCODE_MEMORY_PASSWORD_FILE=~/.config/opencode/memory.pw` (also `OPENCODE_MEMORY_PASSWORD` for a raw secret). With either of these the store is unlocked at session start with no tool call at all, and the secret never enters the conversation. `passwordFile` refuses to proceed on non-Windows if the file is group- or world-readable.

`memory_unlock` also accepts `passwordFile` directly if you want the model to unlock on demand without ever seeing the secret. Two deliberate limits apply:

- A password file must be a regular file of at most 4096 bytes with mode `0600` on non-Windows systems. Every failure reports the same message, so the tool cannot be used to probe whether an arbitrary path exists or what its permissions are.
- Encrypting a store that is not encrypted yet, using a password file, requires an explicit `confirm: true`. Without it the tool only unlocks an already-encrypted store, so pointing it at a file cannot silently re-key your memories.

An unusable `passwordFile` in the plugin config never prevents the plugin from loading. The store comes up locked and the reason is reported in the session, rather than every OpenMind tool disappearing.

On a new store this sets the password and encrypts it; on an existing plaintext store it migrates the contents to the encrypted format in place.

- Encrypted files start with the `OPENMIND_ENC_V3` header, then a `scrypt,n=<N>,r=<R>,p=<P>` line recording the key-derivation parameters used for that file, then `salt:iv:authTag:ciphertext` (AES-256-GCM, keyed by scrypt). Recording the parameters means a future cost increase never invalidates an existing store. Older `OPENMIND_ENC_V2` files are still readable and are transparently migrated to v3 on the next successful unlock.
- Wrong passwords are counted. After 5 failed attempts, access is locked for 5 minutes. `memory_unlock` reports the number of attempts remaining. Only the interactive unlock counts as an attempt: an ambient `OPENCODE_MEMORY_PASSWORD` that fails to decrypt does not burn the budget.
- While locked, read and write tools answer with instructions to run `memory_unlock` instead of exposing data.

To avoid typing the password each session, set it once in the environment or plugin config:

```bash
export OPENCODE_MEMORY_PASSWORD="your-password"
```

Or in the plugin config:

```json
{
  "plugin": [
    ["opencode-memory-extension", {
      "password": "your-password",
      "autoInject": true,
      "injectLimit": 8
    }]
  ]
}
```

To keep the password out of the config file entirely, point at a `0600` file:

```json
{
  "plugin": [
    ["opencode-memory-extension", {
      "passwordFile": "~/.config/opencode/memory.pw",
      "autoInject": true
    }]
  ]
}
```

`passwordFile` (or `OPENCODE_MEMORY_PASSWORD_FILE`) reads the password from disk and refuses to proceed if the file is group- or world-readable on non-Windows systems. Note: the password is kept in memory for the life of the OpenCode process, and its SHA-256 (never the password itself) is used as the derived-key cache key, which is scoped per store file and dropped when the password changes or the store is deleted. It is never written to the store.

`password` (inline, in config or passed to `memory_unlock`) is supported but see the warning above.

## Scopes

- `project`: the only scope. A memory belongs to the worktree it was saved in and is visible only in that project.

There is deliberately no `global` or `session` scope. Only project-scoped memories are stored; legacy global or session records created by earlier versions are ignored and never surfaced.

### Moving or renaming a project

A memory records the absolute worktree path it was saved under. Rename the project directory, move it, or open it from a different path and its memories become **orphaned**: `memory_recall`, `memory_list`, `memory_update`, `memory_forget`, and `memory_prune` all filter by exact path match, so those memories become invisible and unreachable.

`memory_reassign` is the recovery path:

```text
Show me any orphaned OpenMind memories.
Reassign all orphaned memories to this project.
```

It lists orphans without changing anything, then rebinds them to the current worktree on confirmation. After that they behave like any other project memory.

If you open the same project from several paths on purpose, set `namespace` (or `OPENCODE_MEMORY_NAMESPACE`) instead. That makes every path map to one shared project key:

```json
{
  "plugin": [
    ["opencode-memory-extension", {
      "namespace": "my-monorepo",
      "autoInject": true
    }]
  ]
}
```

Namespace changes the stored key format to `ns:<name>`; memories saved before the change are not migrated automatically.

## Injection budget

Saved memories are injected into the system prompt on every turn. Three settings control how much:

- `injectLimit` (default 8, max 25): how many memories are injected.
- `injectMaxChars` (default 4000, max 40000): hard cap on total characters injected per turn.
- `injectItemMaxChars` (default 400): per-memory clip applied before the budget is spent.

Each memory is clipped to `injectItemMaxChars` before the budget is spent, so several short preferences always beat one long note. With the defaults an 8000-character memory contributes 400 characters instead of 8000. A memory that still does not fit is skipped, and the remaining budget is offered to the memories after it.

Selection order is pinned first, then relevance to the current user message (keyword overlap, stemmed both sides), then most recently updated. Without the relevance step the same fixed set would be injected on every turn forever.

## Storage

Default memory file locations:

- Linux: `$XDG_DATA_HOME/opencode-memory/memories.jsonl`, or `~/.local/share/opencode-memory/memories.jsonl`
- Windows: `%APPDATA%\opencode-memory\memories.jsonl`
- macOS: `~/.local/share/opencode-memory/memories.jsonl`

You can override the directory with `OPENCODE_MEMORY_DIR`:

Linux/macOS:

```bash
export OPENCODE_MEMORY_DIR="$HOME/.opencode-memory"
```

Windows PowerShell:

```powershell
$env:OPENCODE_MEMORY_DIR = "$env:USERPROFILE\.opencode-memory"
```

Or set it in plugin config:

```json
{
  "plugin": [
    ["opencode-memory-extension", {
      "directory": "~/.opencode-memory",
      "autoInject": true,
      "injectLimit": 8
    }]
  ]
}
```

## Examples

Ask OpenCode:

```text
Remember for this project that I prefer concise final answers.
Remember for this project that tests should be run with npm test.
What do you remember about this project?
Search my memories for "tests" but exclude anything about Windows.
Forget memory 4dbf8c53-...
Delete all memories tagged temporary.
Delete all OpenMind memory and its storage file.
```

## Architecture

OpenMind is a single-file plugin (`index.js`) that default-exports an OpenCode V2 definition (`{ id, setup }`) and registers its tools through `ctx.tool.transform`, injects memories through `ctx.session.hook("context")`, and exports `OPENCODE_MEMORY_FILE`/`OPENCODE_MEMORY_PROJECT` through `ctx.shell.hook("create.before")`. The historical V1 factory (`MemoryPlugin`) is kept as the internal core so the test suite can drive the same logic directly. A `lib/imgread.py` helper does the image/PDF/OCR work and is spawned with an argument array (no shell). [ARCHITECTURE.md](./ARCHITECTURE.md) covers the full design: storage and encryption format, cross-process locking, BM25 ranking and the injection budget, and the network-I/O guards shared by `listen_analyze` and `image_read`.

## Development

```bash
npm install
npm test
npm pack
```

`npm test` runs ESLint, a syntax check, and the twelve suites in `test/`. `npm pack` creates a `.tgz` package that can be shared or published. Do not commit `node_modules/`, generated `.tgz` files, or `.env`; all are already ignored by `.gitignore`. The image helper lives in `lib/imgread.py` and is referenced relative to the plugin location, so it works in any clean clone without absolute paths.

`install.mjs` accepts `--commands global` (default), `--commands project`, or `--commands none` to control where the slash commands go.
