# OpenMind v2

Privacy-first, user-controlled memory tools for OpenCode on Windows, Linux, and macOS.

OpenMind never saves sessions. Durable memory is opt-in and is limited to explicit project or global preferences. Users can permanently delete one item, matching unwanted items, or the entire backing store.

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

- `memory_remember`: explicitly save a project or global memory
- `memory_recall`: search memories
- `memory_list`: list recent memories
- `memory_forget`: permanently delete a memory by id
- `memory_prune`: preview then permanently delete unwanted memories by id, text, or tag
- `memory_delete_store`: permanently delete all memories and remove the storage file
- `memory_export`: show/export stored memories

## Scopes

- `project`: default; visible only in the current worktree
- `global`: visible in every OpenCode project

There is deliberately no `session` scope. During its first v2 load, OpenMind removes any session records created by earlier versions.

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
Remember globally that I prefer concise final answers.
Remember for this project that tests should be run with npm test.
What do you remember about this project?
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
