// Ranking, injection budgeting and lock-staleness behavior that used to be
// unreachable from outside index.js. All pure functions, no network, no disk.
import { stem, filterMemories, bm25Documents, budgetMemories, orderForInjection, lockIsAbandoned, parseLockToken } from "../index.js";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const KEY = "project-a";

function memory(text, extra = {}) {
  return {
    id: extra.id || text.slice(0, 8),
    text,
    tags: extra.tags || [],
    scope: "project",
    source: extra.source ?? null,
    pinned: extra.pinned ?? false,
    project: extra.project ?? KEY,
    createdAt: extra.updatedAt || "2026-01-01T00:00:00.000Z",
    updatedAt: extra.updatedAt || "2026-01-01T00:00:00.000Z",
  };
}

console.log("  Ranking tests...");

// --- stemming -----------------------------------------------------------------
assert(stem("tests") === stem("test"), '"tests" should stem to "test"');
assert(stem("preferences") === stem("preference"), '"preferences" should stem to "preference"');
assert(stem("cat") === "cat", "short words must be left alone");
assert(stem("deployments") === stem("deployment"), '"deployments" should stem to "deployment"');

// An identifier keeps its exact form in the index even when its stem folds, so
// querying it still works.
const redisHit = filterMemories([memory("we use redis for the session cache")], KEY, { query: "redis" });
assert(redisHit.length === 1, "identifier query did not match exactly");

const entries = [
  memory("Run the unit tests with npm test", { id: "m1" }),
  memory("Deployment runs on Render", { id: "m2" }),
  memory("Tests live in test/*.mjs", { id: "m3", tags: ["testing"] }),
];

// Inflection: querying "test" must find the "tests" memories.
const hits = filterMemories(entries, KEY, { query: "test" }).map((m) => m.id);
assert(hits.includes("m1"), "stemmed query did not match an inflected memory");
assert(hits.includes("m3"), "stemmed query did not match an inflected memory");
assert(!hits.includes("m2"), "unrelated memory leaked into results");

// Exact term in the text outranks a fuzzy/prefix match elsewhere.
const ranked = filterMemories(
  [memory("deploy configuration notes"), memory("the configuration file is here, configuration everywhere")],
  KEY,
  { query: "configuration" },
);
assert(ranked[0].text.includes("everywhere"), "the denser exact match should rank first");

// Typo tolerance for words of 5+ characters.
const typo = filterMemories([memory("the webhook endpoint is documented")], KEY, { query: "webhok" });
assert(typo.length === 1, "a one-edit typo should still match");

// Two edits on a short word must NOT match, or recall turns to noise.
const noise = filterMemories([memory("the cat sat")], KEY, { query: "dog" });
assert(noise.length === 0, "an unrelated short word matched");

// Prefix matching: a partial word finds the memory.
const prefix = filterMemories([memory("kubernetes deployment notes")], KEY, { query: "kubern" });
assert(prefix.length === 1, "prefix query did not match");

// Negation still works, and is applied against the stemmed vocabulary.
const negated = filterMemories(entries, KEY, { query: "test -deployment" });
assert(negated.every((m) => !/deploy/i.test(m.text)), "negated term was not excluded");

// The absolute project path must not be part of the searchable vocabulary:
// otherwise a query naming the directory matches every memory in it.
const pathHit = bm25Documents([{ text: "an unrelated note", tags: [], source: null, project: "/home/dev/projects/opencode-memory-extension" }], ["opencode-memory-extension"]);
assert(pathHit[0].score === 0, "the project path itself is being indexed as content");

// Fields are weighted: text beats tags, tags beat source.
const weighted = bm25Documents(
  [{ text: "zebra", tags: [], source: null }, { text: "nothing", tags: ["zebra"], source: null }],
  ["zebra"],
);
assert(weighted[0].score > weighted[1].score, "text field is not weighted above tags");

// Visibility: another project's memories are never candidates.
const scoped = filterMemories([memory("mine"), memory("theirs", { project: "project-b" })], KEY, {});
assert(scoped.length === 1 && scoped[0].project === KEY, "cross-project memory was visible");

console.log("    Ranking: PASS");

// --- injection ----------------------------------------------------------------
// A memory that does not fit must be skipped, not treated as the end of the
// pass: with the old `break` every memory below it was silently dropped.
const injected = budgetMemories(
  [
    memory("first ".repeat(100), { id: "long" }),
    memory("short one", { id: "s1" }),
    memory("short two", { id: "s2" }),
  ],
  { limit: 3, maxChars: 30, itemMaxChars: 40 },
);
assert(!injected.some((m) => m.id === "long"), "an entry over the whole budget should be dropped");
assert(injected.map((m) => m.id).join(",") === "s1,s2", "small memories after an oversized one were lost");

// Per-item clipping happens before the budget is spent, so a very long memory is
// clipped and still admitted rather than crowding everything else out.
const clipped = budgetMemories([memory("x".repeat(500))], { limit: 5, maxChars: 1000, itemMaxChars: 50 });
assert(clipped[0].text.length === 50, "per-item clip not applied");

// Relevance beats recency, pinned beats everything.
const ordered = orderForInjection(
  [
    memory("old note about kubernetes", { id: "old", updatedAt: "2026-01-01T00:00:00.000Z" }),
    memory("recent note about the weather", { id: "recent", updatedAt: "2026-09-01T00:00:00.000Z" }),
    memory("pinned but unrelated", { id: "pinned", pinned: true, updatedAt: "2026-01-01T00:00:00.000Z" }),
  ],
  "why is my kubernetes deploy failing",
).map((m) => m.id);
assert(ordered[0] === "pinned", "a pinned memory must stay first");
assert(ordered[1] === "old", "relevance to the current message did not outrank recency");
assert(ordered[2] === "recent", "the irrelevant recent memory should rank last");

// An empty message must not reshuffle anything by relevance.
const noQuery = orderForInjection([memory("a", { id: "a", updatedAt: "2026-02-01T00:00:00.000Z" }), memory("b", { id: "b", updatedAt: "2026-03-01T00:00:00.000Z" })], "").map((m) => m.id);
assert(noQuery.join(",") === "b,a", "with no query the order must stay recency-based");

console.log("    Injection: PASS");

// --- lock staleness -----------------------------------------------------------
const { hostname } = await import("node:os");
const me = hostname();

assert(lockIsAbandoned(`${process.pid}@${me}:abc`, 10 * 60 * 1000) === false, "a live owner's stale-looking lock was stolen");
assert(lockIsAbandoned("999999999@someotherhost:abc", 10 * 60 * 1000) === true, "a lock from a dead pid was not reclaimed");
assert(lockIsAbandoned(`${process.pid}@${me}:abc`, 1000) === false, "a fresh lock was stolen");
assert(lockIsAbandoned("999999999@someotherhost:abc", 1000) === false, "a fresh foreign lock was stolen");

// A pid that exists locally but is not ours must not be trusted as the owner on a
// foreign host: age alone decides there.
assert(lockIsAbandoned(`1@elsewhere:abc`, 10 * 60 * 1000) === true, "foreign host lock not judged by age");

const parsed = parseLockToken(`${process.pid}@${me}:deadbeef`);
assert(parsed.pid === process.pid && parsed.host === me, "lock token not parsed correctly");
assert(parseLockToken("garbage").pid === null, "garbage lock token produced a pid");

// Legacy token shape (pid:random) must still parse its pid.
assert(parseLockToken(`${process.pid}:deadbeef`).pid === process.pid, "legacy lock token lost its pid");

console.log("    Locks: PASS");
console.log("ranking: all tests passed");
