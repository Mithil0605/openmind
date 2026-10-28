---
description: Remember a fact for this project
---

Remember a durable project fact using the OpenMind `memory_remember` tool.

1. Take the text from `$ARGUMENTS`. If empty, ask for the fact to remember and stop until the user answers.
2. If the user wants tags, extract them (e.g. `tags: api, auth`) or ask; otherwise omit tags.
3. Call `memory_remember` with `text` (required). Optionally pass `tags`, `source`, `pinned`.
4. Report the result clearly, including the memory id and scope shown by the tool.
5. If the tool says it updated an existing memory (deduplicated), say so.

Do not save session transcripts or conversation history. Only save explicit project facts/preferences.
