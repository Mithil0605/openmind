# Easy Setup

This is the simplest way to install OpenCode Memory Extension.

## Before You Start

Install these first:

- OpenCode
- Node.js 22 or newer from https://nodejs.org/

## Windows

1. Download or unzip the `opencode-memory-extension` folder.
2. Open the folder.
3. Double-click `install.cmd`.
4. Restart OpenCode.

If Windows blocks the file, right-click `install.cmd`, choose **Properties**, select **Unblock** if shown, then run it again.

## Linux or macOS

Open a terminal in the `opencode-memory-extension` folder and run:

```bash
sh ./install.sh
```

Then restart OpenCode.

## Check That It Works

In OpenCode, type:

```text
Remember globally that I prefer short answers.
What do you remember about me?
```

## Where Memories Are Saved

- Windows: `%APPDATA%\opencode-memory\memories.jsonl`
- Linux: `~/.local/share/opencode-memory/memories.jsonl`
- macOS: `~/.local/share/opencode-memory/memories.jsonl`

To use a different folder, set `OPENCODE_MEMORY_DIR` before starting OpenCode.
