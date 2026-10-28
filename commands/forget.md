---
description: Forget a specific memory
---

Delete a specific memory using the OpenMind `memory_forget` tool.

1. Take the memory id from `$ARGUMENTS`. If empty, ask for the id (short or full) and stop until the user answers.
2. If the user wants to delete multiple, or isn't sure which id to use, call `memory_recall` or `memory_list` first to show candidates and their ids/scopes.
3. Call `memory_forget` with `ids` containing the id(s) the user confirmed.
4. Report what was deleted. If nothing matched, say so clearly.
5. For bulk deletions by tag/phrase, use `memory_prune` (it shows a preview unless confirmed) — don't guess.
