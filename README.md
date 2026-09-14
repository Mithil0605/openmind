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
- **Content**: paragraphs and full body text
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
opencode plugin openmind-v4 --global
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
- `memory_export`: show/export stored memories
- `image_read`: read an image so the model can "see" it — prints format, dimensions, OCR'd text, and the downscaled size of large images. Accepts a local path or an http(s) URL. Only image files are read; everything else is refused without revealing contents. URLs are SSRF-guarded (private, loopback, link-local, and cloud-metadata hosts are blocked).
- `listen_analyze`: listen to, learn from, and comprehensively analyze any public website. Fetches the page, extracts metadata, Open Graph data, headings, links, images, code, tables, lists, full text, and detects the technology stack. SSRF-guarded against private/loopback/cloud-metadata hosts, with size, timeout, and content-type limits. Backed by the `/listen` slash command.

## Image Reading

`image_read` removes the common LLM image limitations at the CLI:

- **Web URLs** — downloads public images automatically.
- **Large images** — downscales over the `max` cap (default 1400) so the model can ingest them.
- **Fine text / OCR** — runs `tesseract` and returns the extracted text directly.
- **Vector images** — dumps SVG markup as text.
- **Format support** — PNG, JPEG, GIF, BMP, WEBP, TIFF, SVG, plus a PDF-to-image hint.

Examples the model can act on:

```text
Read the screenshot at ./assets/login.png and tell me what it shows.
What text is on this QR code image? /data/qr.png
Read the diagram at https://example.com/architecture.svg, no OCR needed.
```

`image_read` is deliberately refuse-by-default: it reads only image files and never echoes arbitrary file contents, so it cannot be misused as a file-exfiltration channel. If `python3` (with Pillow and tesseract) is not installed, OpenMind reports a safe fallback with basic type/dimension detection.

## Security and VAPT

OpenMind v5 ships with a built-in static and dynamic security test suite (`npm test` runs `node test/security.mjs`, `test/image.mjs`, `test/listen.mjs`, and `test/vapt.mjs`):

- **Input injection / fuzzing** — newline-forged records, prototype-pollution tags, oversized text, regex metacharacters in queries.
- **Tampered and corrupt stores** — the plugin never crashes or leaks partial data.
- **Symlink attacks** — atomic writes replace the file instead of writing through a link.
- **Cross-process concurrency** — parallel writers never corrupt the JSONL format.
- **Encryption** — AES-256-GCM authentication rejects tampered ciphertext; locked stores never disclose contents; 5-attempt lockout.
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

- Encrypted files start with the `OPENMIND_ENC_V2` header followed by `salt:iv:authTag:ciphertext` (AES-256-GCM, keyed by scrypt). Saved memory text is never stored in plaintext.
- Wrong passwords are counted. After 5 failed attempts, access is locked for 5 minutes. `memory_unlock` reports the number of attempts remaining.
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

Note: the password is kept in memory for the life of the OpenCode process. It is never written to the store.

## Scopes

- `project`: the only scope. A memory belongs to the worktree it was saved in and is visible only in that project.

There is deliberately no `global` or `session` scope. Only project-scoped memories are stored; legacy global or session records created by earlier versions are ignored and never surfaced.

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
