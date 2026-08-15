# OpenMind v2

Privacy-first, user-controlled memory tools for OpenCode on Windows, Linux, and macOS.

OpenMind never saves sessions. Durable memory is opt-in and is limited to explicit project preferences. Users can permanently delete one item, matching unwanted items, or the entire backing store.

The store can be encrypted with AES-256-GCM. A password is verified like `sudo`, with a 5-attempt rate limit that locks access for 5 minutes after repeated failures.

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
opencode plugin openmind-v2 --global
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

`npm pack` creates a `.tgz` package that can be shared or published.

## GitHub Release Checklist

Before posting this repository publicly:

```bash
npm install
npm test
git init
git add .
git commit -m "Initial OpenCode memory extension"
```

Do not commit `node_modules/` or generated `.tgz` files. They are ignored by `.gitignore`.
