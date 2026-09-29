# OpenMind v5

Privacy-first, user-controlled memory tools for OpenCode on Windows, Linux, and macOS — with an SSRF-guarded web listener/analyzer, image reading with OCR, and optional AES-256-GCM encryption.

OpenMind never saves sessions. Durable memory is opt-in and is limited to explicit project preferences. Users can permanently delete one item, matching unwanted items, or the entire backing store.

The store can be encrypted with AES-256-GCM. A password is verified like `sudo`, with a 5-attempt rate limit that locks access for 5 minutes after repeated failures.

## The /listen Command

OpenMind v5 adds the `/listen` slash command — a web listening, learning, and analysis tool that works through Firefox-compatible web fetching:

1. Type `/listen` in the OpenCode chat.
2. OpenMind asks: "What website URL should I listen to and analyze?"
3. OpenMind then asks: "Should I learn from this website permanently (saved to OpenMind memory) or just analyze it this once?"
4. It fetches and comprehensively analyzes the site: title, meta tags, Open Graph data, headings, paragraphs, links, images, code snippets, tables, lists, and detects the technology stack (React, Vue, Next.js, Tailwind, etc.).
5. If you chose permanent learning, it saves the key findings to OpenMind memory with tags so they persist across sessions.

`/listen` is SSRF-guarded — private IPs, loopback addresses, cloud metadata endpoints, `.local`/`.internal` domains, and link-local IPv6 are all blocked before any request is made.

### What `/listen` Extracts

- **Metadata**: title, description, author, keywords, canonical, robots
- **Open Graph**: og:title, og:description, og:image, og:type, etc.
- **Structure**: full heading hierarchy (H1–H6)
- **Content**: paragraphs and body text, trimmed to the first 10,000 characters
- **Navigation**: all external links with anchor text
- **Media**: image sources and alt text
- **Code**: all `<pre><code>` blocks
- **Data**: all tables and lists
- **Tech stack**: automatic detection of React, Vue, Angular, Next.js, Nuxt, Svelte, Tailwind, Bootstrap, jQuery, WordPress, Cloudflare, Nginx, Apache, Vercel, and more

## Easiest Install

For non-technical users, use [SETUP.md](./SETUP.md).

Windows: double-click `install.cmd`.

Linux/macOS: run:

```bash
sh ./install.sh
```

Then restart OpenCode.

## Install From npm

After publishing this package to npm:

```bash
opencode plugin openmind-v5 --global
```

Restart OpenCode after installation.

## Install From a Local Folder

Linux/macOS:

```bash
git clone <repo-url> opencode-memory-extension
cd opencode-memory-extension
npm install
opencode plugin "$(pwd)" --global --force
```

Windows PowerShell:

```powershell
git clone <repo-url> opencode-memory-extension
cd opencode-memory-extension
npm install
opencode plugin (Resolve-Path .).Path --global --force
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
- `memory_unlock`: verify the store password to enable encryption or access an encrypted store (5-attempt rate limit)
- `memory_forget`: permanently delete a memory by id
- `memory_prune`: preview then permanently delete unwanted memories by id, text, or tag
- `memory_delete_store`: permanently delete all memories and remove the storage file
- `memory_reassign`: list and rebind orphaned memories (records whose recorded project path is no longer the current worktree, e.g. after the directory was renamed or moved). Orphaned memories are invisible to every other tool, so this is the recovery path.
- `memory_export`: show/export stored memories
- `image_read`: read an image so the model can "see" it — prints format, dimensions, OCR'd text, and the downscaled size of large images. Accepts a local path or an http(s) URL. Only image files are read; everything else is refused without revealing contents. URLs are SSRF-guarded (private, loopback, link-local, and cloud-metadata hosts are blocked).
- `listen_analyze`: listen to, learn from, and comprehensively analyze any public website. Fetches the page, extracts metadata, Open Graph data, headings, links, images, code, tables, lists, full text, and detects the technology stack. SSRF-guarded against private/loopback/cloud-metadata hosts, with size, timeout, and content-type limits. Backed by the `/listen` slash command.

## Image Reading

`image_read` removes the common LLM image limitations at the CLI:

- **Web URLs** — downloads public images automatically (requires `python3`).
- **Large images** — downscales over the `max` cap (default 1400) so the model can ingest them.
- **Fine text / OCR** — runs `tesseract` directly (no Python needed) and returns the extracted text. `python3` + Pillow is used as a fallback path when tesseract itself is unavailable.
- **Vector images** — dumps SVG markup as text.
- **Format support** — PNG, JPEG, GIF, BMP, WEBP, TIFF, SVG, plus a PDF-to-image hint.

Examples the model can act on:

```text
Read the screenshot at ./assets/login.png and tell me what it shows.
What text is on this QR code image? /data/qr.png
Read the diagram at https://example.com/architecture.svg, no OCR needed.
```

`image_read` is deliberately refuse-by-default: it reads only image files and never echoes arbitrary file contents, so it cannot be misused as a file-exfiltration channel. If `python3` (with Pillow) is not installed, OpenMind falls back to JavaScript: it reads only the first 64 bytes to report type and dimensions, attempts OCR via `tesseract`, and URL reading is unavailable.

## Security and VAPT

OpenMind v5 ships with a built-in static and dynamic security test suite, plus eslint and a GitHub Actions workflow that runs both on every push. `npm test` runs lint and all nine suites: `test/smoke.mjs`, `test/compat.mjs`, `test/encryption.mjs`, `test/locked.mjs`, `test/concurrency.mjs`, `test/security.mjs`, `test/image.mjs`, `test/listen.mjs`, and `test/vapt.mjs`:

- **Input injection / fuzzing** — newline-forged records, prototype-pollution tags, oversized text, regex metacharacters in queries.
- **Tampered and corrupt stores** — the plugin never crashes or leaks partial data.
- **Symlink attacks** — atomic writes replace the file instead of writing through a link.
- **Cross-process concurrency** — parallel writers never corrupt the JSONL format; a stale lock is only stolen after a grace period, and a holder only ever removes a lockfile carrying its own token.
- **Context budget** — injection is capped by total characters, not just a memory count, so one oversized memory cannot crowd out the rest.
- **Encryption** — AES-256-GCM authentication rejects tampered ciphertext; locked stores never disclose contents; 5-attempt lockout that only counts failures from the interactive `memory_unlock` path.
- **Command injection** — `image_read` spawns the helper with an argument array (no shell); flag-like, control-character, and oversized targets are rejected up front.
- **SSRF for image URLs** — URL hosts are DNS-resolved and any private/loopback/link-local address (including `169.254.169.254`) blocks the fetch; redirects are re-checked per hop.
- **SSRF for web listening** — `listen_analyze` resolves the hostname with DNS and blocks private, loopback, link-local, reserved, `.local`, `.internal`, and cloud-metadata addresses before any request is made. Only `http`/`https` protocols are allowed.
- **Web fetch limits** — 5MB response cap, 30s timeout, HTML content-type check, and early rejection of non-HTML responses.
- **No content leak** — refused file types and corrupt images report a safe message, never the file bytes.
- **Permissions** — store files `0600`, directories `0700`.

## Encryption and Password

The store is plaintext by default for compatibility. To enable encryption, ask OpenCode to unlock the store with a password:

```text
Unlock the memory store with my password.
```

OpenMind will prompt for the password and call `memory_unlock`. On a new store this sets the password and encrypts it; on an existing plaintext store it migrates the contents to the encrypted format in place.

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

`passwordFile` (or `OPENCODE_MEMORY_PASSWORD_FILE`) reads the password from disk and refuses to proceed if the file is group- or world-readable on non-Windows systems. Note: the password is kept in memory for the life of the OpenCode process, and its SHA-256 (never the password itself) is used as the derived-key cache key. It is never written to the store.

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

Saved memories are injected into the system prompt on every turn. Two settings control how much:

- `injectLimit` (default 8, max 25): how many memories are considered, pinned first, then most recently updated.
- `injectMaxChars` (default 4000, max 40000): hard cap on total characters injected per turn.

Each memory is clipped to `injectItemMaxChars` (default 400) before the budget is spent, so several short preferences always beat one long note. With the defaults an 8000-character memory contributes 400 characters instead of 8000.

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

## Development

```bash
npm install
npm test
npm pack
```

`npm pack` creates a `.tgz` package that can be shared or published. Do not commit `node_modules/`, generated `.tgz` files, or `.env`; all are already ignored by `.gitignore`. The image helper lives in `lib/imgread.py` and is referenced relative to the plugin location, so it works in any clean clone without absolute paths.
