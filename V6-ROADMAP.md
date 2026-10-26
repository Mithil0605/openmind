# OpenMind v6 — audit findings and improvement backlog

Audit target: `openmind-v5@5.2.0` (`index.js`, 2879 lines), commit `7509899`.
Method: source read of the whole plugin + empirical reproduction with throwaway harnesses.
Every "REPRODUCED" claim below has a runnable case; `npm test` (12 suites) passes on
the current tree, i.e. none of these are caught by the existing suite.

---

## Status (as of 6.1.0)

**Shipped in 6.0.0 — P0 #1, #2, #3, #4, #5 and #20.** All five correctness bugs are
fixed and each one is pinned by a regression test, so a reintroduction is caught before release.

| Item | Fix |
|---|---|
| #1 injection key mismatch | The tool path and the injection path now resolve the project key through one helper, so a memory written by the tools is injected back. Corrected root cause: the plugin instance is loaded *per location*, and that location is the **project** the instance serves, not necessarily the session's directory. |
| #2 sanitizer bypass | Dedupe updates, `memory_update` and `memory_reassign` all rebuild the record through `sanitizeEntry`. |
| #3 negation-only recall | A query with no positive terms filters by exclusion and ranks by pinned/recency. |
| #4 reassign mislabels live projects | Orphans are inferred from a *missing project directory*, not from path difference. A live project's memories are never taken by a bulk rebind; one can only be moved by naming its id explicitly. |
| #5 dead `global` scope | Legacy globals are counted separately and returned by `memory_export { scope: "all" }`, and `memory_reassign` adopts them into the current project. |
| #20 test gaps | The regression suite covers (a) save-then-inject across directories, (b) source/tag caps through dedupe and update, (c) negative-only queries, (d) reassign ownership, (e) global-scope visibility, plus moved-session isolation and preview/confirm consistency. |

**Behaviour changes worth knowing (breaking):**

- `memory_reassign` previews and confirms share one selection, so `metadata.count`
  always describes what the matching `confirm` would move. A preview that names
  `ids` now reports the selected count instead of the whole orphan set.
- `includeForeign` renders only an id, the owning project and a ≤120-character
  excerpt, capped at 25 items. It is a review aid, not a content dump.
- `memory_export { scope: "all" }` is still a full-store dump, but it now carries a
  `scope` and a cross-project `warning` field. It is a recovery/diagnostic escape
  hatch, not the normal migration path.

**Shipped in 6.1.0 — P1 #6 (`memory_import`) and P3 #17/#18 (partially), plus
features the audit implied but did not list.** All four are agent-facing: they
answer "what do I actually have in memory, and how do I get it back?".

| Feature | Tool | Why it matters |
|---|---|---|
| Store inventory | `memory_stats` | Path, size, encryption state, total/visible/pinned/stranded counts, oldest and newest visible memory, tag histogram. Distinguishes an empty store from a locked one from memories stranded under a stale path, without printing another project's path. |
| Tag inventory | `memory_tags` | The vocabulary, with counts, most frequent first. Makes `memory_recall({tags})` usable without guessing tag names. |
| Time windows | `last` / `after` / `before` on `memory_recall` and `memory_list` | "What did I decide last week?" An unparseable bound is an error, never a silently ignored filter (a silently dropped window returns the whole store and looks like a success). |
| Import / restore | `memory_import` | The inverse of `memory_export`, and the only supported way to restore a backup. Dry-run by default; 8 MB / 5000-entry caps; everything re-sanitized; project-scoped by default. |

Two security decisions in this release are worth recording:

- **`onConflict: "overwrite"` may only replace a record this project owns.** The
  first implementation keyed replacement off the payload's own `project` field,
  which is attacker-controlled; importing one crafted entry with another
  project's id deleted that project's memory. Found by red-team review during
  this release, reproduced, fixed, and pinned by two regression tests. Foreign
  ids are now always given a fresh id.
- **Imported text is untrusted text.** It gets an `imported` tag, and the
  injection fence now treats `imported` like `listen`: sticky through
  `memory_update`, and framed as quoted data the model must not obey.
- **Inline fields are sanitized, not just capped.** An independent red-team pass
  found that `tags` and `createdAt`/`updatedAt` were the only import fields
  rendered inline that were still stored verbatim, so a newline in either one
  forged an extra line that looked like a memory owned by another project
  (`- <uuid> [admin] pinned (project=/root/...)`) — the id-token rule protected
  only ids. Tags and timestamps now have control characters, bidi overrides and
  structural brackets/parentheses stripped, timestamps must parse and fit in 40
  characters, and ids are rendered through the same cleaner. `pinned` must be a
  real boolean.
- **Import cannot create a global record.** A global belongs to no project, is
  invisible everywhere, and is the one record kind another project's
  `memory_reassign` adopts *in bulk*. Accepting one from a payload was therefore
  a way to plant text a different worktree later picks up. Globals are re-homed
  into the importing project, which is also the only way they become reachable.
- **The file-read error is singular.** Directory, missing, unreadable and
  oversized all return the same message with no real size, so `file` cannot be
  used as a filesystem or file-size oracle. `memory_stats` no longer uses
  `Math.min(...stamps)`, which threw a `RangeError` on stores above roughly
  125k entries — i.e. exactly when the tool becomes useful.

`@opencode-ai/plugin` also moved from `dependencies` to `devDependencies`. It was
never imported by `index.js`, but it transitively pinned vulnerable `toml`/`zod`
versions into every user install; `npm audit --omit=dev` is now clean, and
`npm install --omit=dev` installs nothing at all.

**Open follow-ups (not in 6.0.0):**
1. **Stable project identity (#7).** Scope is still a raw absolute path. Routing
   the key through `ctx.location.project.id` / `session.projectID` fixes the
   *isolation* question but not the *renaming* one: moving a checkout still
   orphans its memories. This is the highest-value remaining correctness item.
2. **Export size cap.** `memory_export` is still unbounded in output size; with a
   large store it can exhaust the model's context. Import is capped, export is
   not. Same class of issue as #8.
3. **Cross-project visibility.** `memory_export { scope: "all" }` plus an explicit-id
   `memory_reassign` is, together, a two-call primitive for moving another project's
   memory. That is inherent to having any cross-project recovery path; the wording
   now says so instead of claiming it is impossible. A capability model (per-project
   opt-in for cross-project reads) would close it properly.
4. **Namespace orphan recovery.** In namespace mode (`ns:team`) no record looks like
   a filesystem path, so every foreign record is classified live and bulk recovery
   finds nothing. Needs its own notion of "the namespace no longer exists".
5. **`useSessionProject` is not configurable.** The instance project always wins; a
   user who deliberately moves a session to another checkout gets the old project's
   memories. A documented option would make that intentional rather than surprising.
6. **Injection transparency (#18).** A one-line provenance footer (how many
   memories were injected, how many the budget dropped) is still missing. It is the
   cheapest remaining observability win, but it adds noise to every prompt, so it
   needs a config toggle to be worth shipping.
7. **FTS5 (#12) is now 6.2 work.** It did not make 6.1: it touches storage, the
   encrypted-store path, and the BM25 tests at once, and the released features did
   not need it.

---

## P0 — Correctness bugs (all reproduced)

### 1. Injection is keyed to the plugin directory, not the session directory — memories are saved but never injected

This is the headline defect: the product's core promise ("remember across sessions")
silently does not work in OpenCode V2.

- Tool write path: `index.js:2822` resolves the session's real directory via
  `directoryFor(toolCtx.sessionID)` → `ctx.session.get({sessionID})` (`index.js:2801-2813`),
  and keys the memory with it.
- Injection path: `index.js:2757-2761` builds the context from the *plugin's* load
  location (`_input.directory` / `_input.worktree`) — the directory the plugin was
  loaded from, not the directory the session is in.

Memory and injection therefore key on two different paths. `experimental.chat.system.transform`
only receives `{sessionID, model}` (confirmed in `@opencode-ai/plugin` `index.d.ts:265-270`),
so the session directory must be resolved through `ctx.session.get()` — exactly what the
tool path already does.

Reproduced: a memory saved with a session directory different from the plugin's
load directory produces `INJECTED SYSTEM BLOCKS: []`. Passing `directory` on the
transform input does not help — the handler never reads it.

Fix: resolve the session directory in the V2 `context` hook and thread it into the
transform handler; add a regression test that uses two different directories.

### 2. `sanitizeEntry` is bypassed on two write paths

`sanitizeEntry` (`index.js:1216-1239`) is the single place that enforces
`text ≤ 8000`, `source ≤ 2000`, `tags ≤ 50 × 64`. Two paths mutate entries directly:

- `saveMemory` dedupe branch, `index.js:2097-2104` — assigns `existing.text/tags/source`
  raw. Reproduced: `source` of 5000 chars and a 200-char tag persisted verbatim.
- `memory_update`, `index.js:2205` — `memory.source = args.source?.trim() || null`,
  no 2000-char cap. Reproduced: 5000-char source persisted.

A 64-char tag is a plausible prompt-injection carrier, and `source` is rendered at
injection time, so both are attacker-influenced surfaces.

Fix: run every mutation through `sanitizeEntry` (re-derive the entry, don't patch fields),
or apply the caps at the point of assignment.

### 3. A query made only of negated terms returns nothing

`filterMemories`, `index.js:1587-1638`: when `positive.length === 0` and
`negative.length > 0`, the query falls through to the BM25 branch with an empty token
list, every score is `0`, and the `.filter(doc => doc.score > 0)` at line 1627 discards
everything. Reproduced: `query: "-windows"` → `"No matching memories found."`

Negation is documented as a first-class feature in the tool description
(`index.js:2221`: "Prefix a token with `-` to exclude memories containing it").

Fix: when there are no positive terms, filter by exclusion alone and rank by
pinned/recency.

### 4. `memory_reassign` labels live memories of *other* projects as orphans

Orphan predicate, `index.js:2486-2488`:
`memory.scope !== "global" && memory.project && memory.project !== current`.
"Orphan" is inferred purely from *path difference*, so every memory belonging to a
different project is presented as an orphan and offered for rebinding. Reproduced: a
memory written in project B is listed as orphaned when called from project A.

With `confirm: true` this is a cross-project takeover primitive: a project can absorb
another project's memories. The tool's own description claims orphans are records
"that no longer matches the worktree you are in" — which is indistinguishable from
"belongs to a different project".

Fix: distinguish *moved* from *foreign*. Requires a stable project identity
(see P2 #4) — a path hash alone cannot answer it. Until then, the tool must not
present foreign-project memories as orphans.

### 5. `scope: "global"` is a dead scope

- `visibleToProject` (`index.js:1436-1439`) returns `false` for `scope === "global"`,
  so global records are invisible to every project.
- `memory_export` with `scope: "all"` filters `memory.scope !== "global"`
  (`index.js:2537`), so they are not exported either.
- `memory_reassign` skips them (`index.js:2487`).
- `memory_remember` accepts a `scope` argument, ignores it, and stores
  `scope: "project"` (`index.js:2115`), printing a note that it was downgraded.

Legacy `scope: "global"` records are stored, invisible, and unexportable. Reproduced:
a legacy global record does not appear in `memory_list` nor in `memory_export scope=all`.

Fix: either implement global scope (visible to every project, never deleted by a
project-scoped prune) or remove the argument and migrate legacy records to project
scope. Right now the API promises a scope that does not exist.

---

## P1 — API / correctness-of-design gaps

6. **No import/restore path.** `memory_export` exists (`index.js:2524`); there is no
   `memory_import`. A user who clears the store has no supported way to restore an
   export — and `memory_delete_store` is one confirmed call away. Add `memory_import`
   (file or inline JSON, dry-run by default, per-entry id collision policy, runs
   `sanitizeEntry` on everything it reads).

7. **No stable project identity.** Project scope is a raw absolute path
   (`makeProjectKey`, `index.js:1420-1426`). Renaming or moving a project orphans
   every memory; opening the same repo from a different path creates a second
   invisible memory space. This is the root cause of #4. Use a stable id (git
   common-dir hash / worktree id) with the path kept as a display hint.

8. **Unbounded store growth.** No entry-count cap, no TTL, no aging. Every
   `memory_remember` appends forever; `memory_recall` scores the entire history on
   every query. Add a soft cap with eviction of least-useful, least-recent entries,
   plus a `memory_stats` tool (entry count, bytes, project breakdown, oldest/newest).

9. **No per-agent or per-workspace scope.** `memory_remember` receives
   `context.agent` but ignores it. Global and agent-specific preferences are
   common enough to warrant first-class scopes (see #5).

10. **`memory_remember` silently ignores `scope`.** Either honour it or remove it
    from the schema — a silently-ignored argument is worse than a missing one.

11. **Query surface is lexical only.** BM25 over a hand-rolled stemmer is decent but
    cannot answer "what did I decide about auth?" when the memory says "login
    strategy". No fuzzy/near-duplicate clustering beyond `isDuplicate`, no
    date/temporal filters, no "recently changed" filter.

---

## P2 — v6 headline features (environment-verified)

### 12. Replace hand-rolled BM25 with a real full-text index: `node:sqlite` + FTS5

The current implementation re-tokenizes and re-scores the entire store on every
recall (`bm25Documents`, `index.js:1524-1585`), builds the vocabulary by scanning
every term in the corpus, and does fuzzy expansion with an O(|vocab|) prefix/edit-distance
scan per query term.

`node:sqlite` is available on this host and fully featured — verified on Node v24.21.0:
`DatabaseSync` present, **FTS5**, **trigram tokenizer**, and **json1** all working.
FTS5 gives: a real inverted index (no full-corpus rescan), prefix queries
(`token*`), BM25 ranking built in, `trigram` for substring/fuzzy matching,
`snippet()`/`highlight()` for previews, and `json1` for querying structured columns
(tags, scope, pinned) inside the index.

Plan: keep the JSONL store as the source of truth (portability + existing backup
story) and maintain a derived SQLite FTS index rebuilt from it, or migrate to a
SQLite primary store with a JSONL export path. Must handle: index corruption →
rebuild from JSONL; lock contention with the existing file lock; encrypted stores
(plaintext index on disk would leak memory text — index must live inside the
encrypted container or be rebuilt in a temp file and deleted).

### 13. Semantic / hybrid recall

Add embedding-backed recall, combined with FTS/BM25 via reciprocal rank fusion
(RRF), which needs no score calibration between the two rankers. Storage: a small
vector column (or a sidecar file) alongside each memory, plus a `memory_recall`
mode flag (`keyword | semantic | hybrid`). Embeddings must be computed locally
(no network, no provider key) — a small ONNX/transformers model is the sane
default; an optional remote embedder behind an explicit opt-in flag if desired.
Must remain compatible with the encrypted store (vectors are derived data and leak
text; keep them inside the encrypted payload or regenerate).

### 14. KDF upgrade: scrypt → Argon2id

Current KDF: scrypt `n=2^17, r=8, p=1`, header `OPENMIND_ENC_V3`, AES-256-GCM,
5-attempt / 5-minute lockout. Argon2id is the modern recommendation and is
**available in this Node** — verified: `crypto.argon2` and `crypto.argon2Sync` are
present on Node v24.21.0.

Plan: new store header (e.g. `OPENMIND_ENC_V4`) with Argon2id parameters
(`m=64 MiB, t=3, p=1` as the default, memory-hard and GPU/ASIC-resistant),
versioned params in the header, transparent re-key on unlock
(decrypt with the old KDF, re-encrypt with the new one) so existing stores keep
working with no user action.

### 15. Publish to npm

The package is **not published**: `npm view openmind` → 404 and
`npm view openmind-v5` → 404 (checked 2026-10-21). The remote is
`git@github.com:Mithil0605/openmind.git`. Publishing removes the
`opencode plugin <absolute-path> --global --force` install requirement from
`install.mjs` and makes version upgrades possible for other users. Decide the
package name (`openmind` is likely taken; `opencode-memory-extension` or
`openmind-v6`), ship a `bin` CLI (`openmind init|doctor|export|import|reindex`)
and a `postinstall` that does not touch global config silently.

### 16. Store format v6 + migrations

Introduce an explicit store version and a migration runner
(`V1 flat JSON → V2 legacy lines → V3 encrypted → v6 index`), so upgrades are
testable and rollback is possible. Include a `migration` test that materializes
each historical fixture and asserts the v6 result.

---

## P3 — Observability and ergonomics

17. **`openmind doctor` / `memory_stats`**: report store path, encryption state,
    entry count, project key, index health, lock file state, last injection
    time, and whether the *session* key matches the *store* key (would have caught
    bug #1 immediately).

18. **Injection transparency**: when memories are injected, include a one-line
    provenance footer (count, project key, how many were budgeted out). Today a
    silent zero-injection is indistinguishable from "nothing to remember".

19. **`listen_analyze` caching**: no content-hash cache, no URL dedupe — repeated
    fetches of the same page create near-duplicate memories that dedupe
    imperfectly. Cache by URL+content hash; skip saving when the digest matches
    an existing entry.

20. **Test-suite gaps that let the P0 bugs through**: there is no test that
    (a) saves under one directory and injects under another, (b) asserts the
    2000-char source cap and 64-char tag cap through `memory_update` and the
    dedupe path, (c) exercises a negative-only query, (d) asserts
    `memory_reassign` does not touch another project's live memories,
    (e) asserts global-scope visibility. Add all five as regressions.

---

## Suggested v6 sequencing

| Milestone | Contents | Why first |
|---|---|---|
| **v6.0 (correctness)** — shipped | P0 #1–#5 + regression tests #20 | The store works; the *feature* does not. Ship the injection fix first — it is the difference between "OpenMind remembers" and "OpenMind saves". |
| **v6.1 (visibility + restore)** — shipped | #6 `memory_import`, #17 `memory_stats`, tag inventory, time windows, `imported` trust tag | Restores what export could only back up, and answers "what is actually in memory?" without reading the JSONL. |
| **v6.2 (index)** | P2 #12 (SQLite/FTS5) + P2 #16 (format/migrations) + #18 | Turns recall from O(corpus) rescan to a real index. Import (#6) and stats (#17) already landed, so this is purely the storage change. |
| **v6.3 (scope + lifecycle)** | #7 stable project identity, #5 global scope done properly, #8 caps/TTL + export cap, #9 agent scope | Fixes the family of "which project does this belong to" problems at the root instead of patching the symptom. |
| **v6.4 (security + reach)** | P2 #14 Argon2id re-key, P2 #15 npm publish, #13 semantic recall | Argon2id is a cheap, high-value hardening; publishing makes the fixes usable by others. |
