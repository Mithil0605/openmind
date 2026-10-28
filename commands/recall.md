---
description: Recall memories for this project
---

Recall memories for the current project using the OpenMind `memory_recall` tool.

1. Take the query from `$ARGUMENTS`. If empty, show recent memories using `memory_list` instead (or ask for a query).
2. Call `memory_recall` with:
   - `query`: the text/keywords the user wants (supports `-term` to exclude)
   - `tags`: only if the user wants to filter to specific tags
   - `limit`: only if the user asked for a specific number (default 10, max 50)
   - `last`/`after`/`before`: only if the user asked about a time window
3. Present the results as shown by the tool (ids, scope, tags, pinned, timestamp). If there are no matches, say so plainly.
4. If the user says "why was X injected" or seems confused, suggest `memory_inspect <id>` or `/stats` to debug.
