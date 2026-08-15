# Easy Setup

This is the simplest way to install OpenMind v2.

## Before You Start

Install these first:

- OpenCode
- Node.js 22 or newer from https://nodejs.org/

## Windows

1. Download or unzip the `openmind-v2` folder.
2. Open the folder.
3. Double-click `install.cmd`.
4. Restart OpenCode.

If Windows blocks the file, right-click `install.cmd`, choose **Properties**, select **Unblock** if shown, then run it again.

## Linux or macOS

Open a terminal in the `openmind-v2` folder and run:

```bash
sh ./install.sh
```

Then restart OpenCode.

## Check That It Works

In OpenCode, type:

```text
Remember for this project that I prefer short answers.
What do you remember about this project?
```

## Privacy and Deletion

OpenMind v2 does not save session conversations. It stores only memories that are explicitly saved as project preferences.

Ask OpenCode to delete a specific memory, delete memories matching a tag or phrase, or delete all OpenMind memory and its storage file. Matching deletions are previewed before permanent removal.

## Optional Encryption

By default the store is plaintext. Ask OpenCode to "unlock the memory store with my password" to encrypt it. The password is verified like sudo with a 5-attempt rate limit, then the store is AES-256-GCM encrypted on disk.

## Where Explicitly Saved Memories Are Stored

- Windows: `%APPDATA%\opencode-memory\memories.jsonl`
- Linux: `~/.local/share/opencode-memory/memories.jsonl`
- macOS: `~/.local/share/opencode-memory/memories.jsonl`

To use a different folder, set `OPENCODE_MEMORY_DIR` before starting OpenCode.
