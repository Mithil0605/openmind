---
description: Fetch and analyze a public website with listen_analyze, optionally saving findings to OpenMind memory
---

When /listen is invoked, analyze a website with the OpenMind `listen_analyze`
tool.

1. Take the URL from `$ARGUMENTS`. If it is empty, ask the user for one URL and
   stop until they answer.
2. Call `listen_analyze` with:
   - `url`: the URL the user gave.
   - `depth`: `"quick"` for metadata + tech stack + text only, `"full"`
     (default) for headings, links, images, code blocks, tables and lists.
   - `permanent`: `true` only when the user asked to remember the site, `false`
     for a one-time read. Do not save anything the user did not ask to save.
3. Present the result faithfully: title/description/Open Graph, heading outline,
   detected tech stack, the visible text and any code or tables, plus notable
   links. Quote the page; do not add facts the fetch did not return.
4. Report the tool's own warnings when present: a robots.txt refusal, a
   client-rendered page that returned almost no text, a non-HTML content type, or
   a truncated report.
5. If `permanent` was true, tell the user the memory id that was saved, and
   note that it is a project-scoped memory they can delete with `memory_forget`
   or `memory_delete_store`.

Notes: the tool honors robots.txt, refuses private/loopback/link-local and
cloud-metadata hosts, executes no JavaScript, and follows no links — only the
single URL given is fetched.
