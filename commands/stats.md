---
description: Show OpenMind store stats
---

Show OpenMind store health and suggestions using the OpenMind `memory_stats` tool.

1. Call `memory_stats` with no arguments.
2. Present the full result as returned (path, encryption, size, format/migrations, counts, oldest/newest, tags, index state).
3. If it reports stranded/legacy memories, suggest `memory_reassign` (preview first).
4. If it reports the store is locked, suggest `memory_unlock` with `passwordFile` if available.
5. Keep the output readable and actionable.
