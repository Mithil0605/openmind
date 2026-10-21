// Regression tests for the OpenMind v6.0 correctness fixes.
//
// Each test here covers a defect that the v5.2.0 test suite did not catch:
//
//   1. injection keyed on the plugin instance location instead of the session's
//      own directory, so a memory saved through the tools was never injected;
//   2. sanitizeEntry bypassed on the dedupe path and on memory_update, so an
//      over-long source or tag reached the store verbatim;
//   3. a query made only of negated terms returned nothing;
//   4. memory_reassign presented another live project's memories as orphans,
//      which made a cross-project takeover possible with a single confirm;
//   5. legacy global-scope records were stored but unreachable: invisible to
//      every project, dropped from the export, and adoptable by no tool.
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryPlugin as plugin, default as pluginModule } from "../index.js";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function context(directory, sessionID = "regression-session") {
  return {
    sessionID,
    messageID: "m1",
    agent: "a1",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

// A minimal stand-in for the OpenCode V2 plugin context: it records the
// registered tools and session hooks so the test can drive the real V2 path.
//
// A session is either a directory or { directory, projectID }. The project id
// is what OpenCode uses to tell projects apart; two projects can share a
// directory, and a session can be moved from one project to another.
function v2Context({ location, options, sessions, projectID }) {
  const tools = new Map();
  const hooks = new Map();
  return {
    location: {
      directory: location,
      project: { id: projectID || null, directory: location, canonical: location },
    },
    options: options || {},
    session: {
      async get({ sessionID }) {
        const entry = sessions[sessionID];
        if (!entry) throw new Error(`unknown session ${sessionID}`);
        const resolved = typeof entry === "string" ? { directory: entry } : entry;
        return {
          projectID: resolved.projectID === undefined ? projectID : resolved.projectID,
          location: { directory: resolved.directory },
        };
      },
      async hook(name, callback) {
        hooks.set(name, callback);
        return { dispose() {} };
      },
    },
    tool: {
      async transform(callback) {
        const editor = { add: (definition) => tools.set(definition.name, definition) };
        await callback(editor);
      },
    },
    shell: {
      async hook() {
        return { dispose() {} };
      },
    },
    tools,
    hooks,
  };
}

async function readStore(file) {
  const raw = await readFile(file, "utf8");
  return raw
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

// The V2 context hook pushes system parts as objects, the V1 transform pushes
// plain strings. Read both the same way.
function systemText(event) {
  return (event.system || [])
    .map((part) => (typeof part === "string" ? part : part?.text || ""))
    .join("\n");
}

// ---------------------------------------------------------------------------
// 1. Injection must use the session's own directory.
// ---------------------------------------------------------------------------
{
  const root = await mkdtemp(join(tmpdir(), "openmind-v6-inject-"));
  try {
    const storeDir = join(root, "store");
    const projectA = join(root, "project-a");
    const projectB = join(root, "project-b");
    await mkdir(storeDir, { recursive: true });
    await mkdir(projectA, { recursive: true });
    await mkdir(projectB, { recursive: true });

    // The plugin instance is loaded for project A ...
    const ctx = v2Context({
      location: projectA,
      options: { directory: storeDir },
      sessions: { "session-b": projectB },
    });
    await pluginModule.setup(ctx);

    const remember = ctx.tools.get("memory_remember");
    assert(remember, "memory_remember was not registered");

    // ... but the session actually lives in project B.
    const saved = await remember.execute(
      { text: "memory saved from the other project directory" },
      { sessionID: "session-b", agent: "a1", messageID: "m1", signal: new AbortController().signal },
    );
    const id = saved.metadata?.id;
    assert(id, "memory_remember did not return an id");

    // The context hook must inject it: the memory belongs to the session's
    // directory, which is where the write path keyed it.
    const event = { sessionID: "session-b", messages: [], system: [] };
    await ctx.hooks.get("context")(event);
    assert(
      systemText(event).includes("memory saved from the other project directory"),
      "a memory saved in the session's directory was not injected",
    );

    // And a session in the plugin instance's own directory still works.
    const ctx2 = v2Context({
      location: projectA,
      options: { directory: storeDir },
      sessions: { "session-a": projectA },
    });
    await pluginModule.setup(ctx2);
    const event2 = { sessionID: "session-a", messages: [], system: [] };
    await ctx2.hooks.get("context")(event2);
    assert(
      !systemText(event2).includes("memory saved from the other project directory"),
      "a memory from another project leaked into this project's context",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 2. Every write path must go through sanitizeEntry.
// ---------------------------------------------------------------------------
{
  const dir = await mkdtemp(join(tmpdir(), "openmind-v6-caps-"));
  try {
    const hooks = await plugin({ directory: dir, worktree: dir }, { directory: dir });
    const ctx = context(dir);

    const longSource = "S".repeat(5000);
    const longTag = "T".repeat(200);

    // The dedupe path: a near-identical text updates the existing entry.
    const first = await hooks.tool.memory_remember.execute({ text: "dedupe path probe entry" }, ctx);
    await hooks.tool.memory_remember.execute(
      { text: "dedupe path probe entry", tags: [longTag], source: longSource },
      ctx,
    );
    let store = await readStore(first.metadata.file);
    let entry = store.find((item) => item.id === first.metadata.id);
    assert(entry, "the deduped entry vanished from the store");
    assert(
      String(entry.source).length <= 2000,
      `the dedupe path stored an uncapped source (${String(entry.source).length} chars)`,
    );
    assert(
      (entry.tags || []).every((tag) => tag.length <= 64),
      "the dedupe path stored an uncapped tag",
    );

    // The update path.
    const second = await hooks.tool.memory_remember.execute({ text: "update path probe entry" }, ctx);
    await hooks.tool.memory_update.execute({ id: second.metadata.id, source: longSource }, ctx);
    store = await readStore(second.metadata.file);
    entry = store.find((item) => item.id === second.metadata.id);
    assert(
      String(entry.source).length <= 2000,
      `memory_update stored an uncapped source (${String(entry.source).length} chars)`,
    );

    // And an update that replaces the tags is capped too.
    await hooks.tool.memory_update.execute({ id: second.metadata.id, tags: [longTag] }, ctx);
    store = await readStore(second.metadata.file);
    entry = store.find((item) => item.id === second.metadata.id);
    assert(
      (entry.tags || []).every((tag) => tag.length <= 64),
      "memory_update stored an uncapped tag",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 3. A query made only of negated terms must still return matches.
// ---------------------------------------------------------------------------
{
  const dir = await mkdtemp(join(tmpdir(), "openmind-v6-negation-"));
  try {
    const hooks = await plugin({ directory: dir, worktree: dir }, { directory: dir });
    const ctx = context(dir);
    await hooks.tool.memory_remember.execute({ text: "the deployment targets windows hosts" }, ctx);
    await hooks.tool.memory_remember.execute({ text: "the deployment targets linux hosts" }, ctx);

    const negated = String(await hooks.tool.memory_recall.execute({ query: "-windows" }, ctx));
    assert(
      negated.includes("linux hosts"),
      "a negation-only query did not return the memories that survive the exclusion",
    );
    assert(!negated.includes("windows hosts"), "a negation-only query returned an excluded memory");

    const mixed = String(await hooks.tool.memory_recall.execute({ query: "deployment -windows" }, ctx));
    assert(mixed.includes("linux hosts"), "a mixed query lost the surviving memory");
    assert(!mixed.includes("windows hosts"), "a mixed query returned an excluded memory");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 4. memory_reassign must not hand over another live project's memories.
// ---------------------------------------------------------------------------
{
  const root = await mkdtemp(join(tmpdir(), "openmind-v6-reassign-"));
  try {
    const dirA = join(root, "project-a");
    const dirB = join(root, "project-b");
    const gone = join(root, "deleted-project");
    await mkdir(dirA, { recursive: true });
    await mkdir(dirB, { recursive: true });

    const hooks = await plugin({ directory: dirA, worktree: dirA }, { directory: dirA });
    await hooks.tool.memory_remember.execute({ text: "project B keeps this preference" }, context(dirB, "b"));
    await hooks.tool.memory_remember.execute({ text: "a memory of a deleted project" }, context(gone, "g"));

    // The live project B memory must not show up as an orphan.
    const preview = await hooks.tool.memory_reassign.execute({}, context(dirA, "a"));
    assert(
      !String(preview.output).includes("project B keeps this preference"),
      "memory_reassign offered another live project's memory as an orphan",
    );
    assert(
      String(preview.output).includes("a memory of a deleted project"),
      "memory_reassign did not offer the memory of a deleted project",
    );

    // A blanket confirm must not move project B's memory.
    const done = await hooks.tool.memory_reassign.execute({ confirm: true }, context(dirA, "a"));
    assert(done.metadata?.count === 1, "the blanket reassign did not move exactly the true orphan");
    const stillForeign = await hooks.tool.memory_remember.execute(
      { text: "project B keeps this preference" },
      context(dirB, "b"),
    );
    assert(stillForeign, "project B lost its memory to the blanket reassign");
    const visibleToA = String(await hooks.tool.memory_list.execute({}, context(dirA, "a")));
    assert(
      !visibleToA.includes("project B keeps this preference"),
      "project A took over project B's memory",
    );

    // The live project's memory stays reachable, but only by explicit id.
    const foreign = await hooks.tool.memory_reassign.execute({ includeForeign: true }, context(dirA, "a"));
    assert(
      String(foreign.output).includes("project B keeps this preference"),
      "includeForeign did not list the live project's memory",
    );
    const foreignId = String(foreign.output).match(/- ([0-9a-f-]{36})/)?.[1];
    assert(foreignId, "could not read the id of the live project's memory");
    const moved = await hooks.tool.memory_reassign.execute(
      { ids: [foreignId], confirm: true },
      context(dirA, "a"),
    );
    assert(moved.metadata?.count === 1, "an explicitly named foreign memory was not rebound");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 4b. The review list must not dump a live project's memories in full, and a
//     preview must describe exactly what the matching confirm will do.
// ---------------------------------------------------------------------------
{
  const root = await mkdtemp(join(tmpdir(), "openmind-v6-review-"));
  try {
    const dirA = join(root, "project-a");
    const dirB = join(root, "project-b");
    await mkdir(dirA, { recursive: true });
    await mkdir(dirB, { recursive: true });

    const hooks = await plugin({ directory: dirA, worktree: dirA }, { directory: dirA });
    const secret = `confidential-${"S".repeat(400)}-tail`;
    await hooks.tool.memory_remember.execute({ text: secret }, context(dirB, "b"));

    const review = await hooks.tool.memory_reassign.execute({ includeForeign: true }, context(dirA, "a"));
    const output = String(review.output);
    assert(
      !output.includes(secret),
      "the review list rendered a live project's memory in full",
    );
    assert(output.includes("confidential-"), "the review list did not show any excerpt of the memory");
    assert(
      !output.includes("tail"),
      "the review list rendered the end of a live project's memory",
    );

    // A preview that names ids reports the selected count, so the preview
    // always matches the confirm that follows it.
    const foreignId = output.match(/- ([0-9a-f-]{36})/)?.[1];
    assert(foreignId, "could not read the id of the live project's memory");
    const preview = await hooks.tool.memory_reassign.execute({ ids: [foreignId] }, context(dirA, "a"));
    assert(preview.metadata?.count === 1, "a filtered preview did not report the selected count");
    const done = await hooks.tool.memory_reassign.execute(
      { ids: [foreignId], confirm: true },
      context(dirA, "a"),
    );
    assert(
      done.metadata?.count === preview.metadata?.count,
      "the confirm moved a different number of memories than the preview showed",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 5. Legacy global-scope records must be reachable and adoptable.
// ---------------------------------------------------------------------------
{
  const root = await mkdtemp(join(tmpdir(), "openmind-v6-legacy-"));
  try {
    const storeDir = join(root, "store");
    const projectDir = join(root, "project");
    await mkdir(storeDir, { recursive: true });
    await mkdir(projectDir, { recursive: true });
    const stamp = new Date().toISOString();
    await writeFile(
      join(storeDir, "memories.jsonl"),
      `${JSON.stringify({
        id: "legacy-global-001",
        text: "legacy global preference from v4",
        tags: ["legacy"],
        scope: "global",
        project: null,
        source: null,
        pinned: false,
        createdAt: stamp,
        updatedAt: stamp,
      })}\n`,
    );

    const hooks = await plugin({ directory: projectDir, worktree: projectDir }, { directory: storeDir });
    const ctx = context(projectDir);

    // Still invisible to the project ...
    const listed = String(await hooks.tool.memory_list.execute({}, ctx));
    assert(!listed.includes("legacy global preference"), "a legacy global record leaked into a project");

    // ... but no longer dropped from the export.
    const exported = await hooks.tool.memory_export.execute({ scope: "all" }, ctx);
    assert(
      String(exported.output).includes("legacy global preference"),
      "a legacy global record was dropped from the full export",
    );
    assert(exported.metadata?.legacyGlobal === 1, "the export did not count the legacy global records");

    // And adoptable: it belongs to no project, so it is an orphan.
    const preview = await hooks.tool.memory_reassign.execute({}, ctx);
    assert(
      String(preview.output).includes("legacy global preference"),
      "a legacy global record was not offered for adoption",
    );
    const done = await hooks.tool.memory_reassign.execute({ confirm: true }, ctx);
    assert(done.metadata?.count === 1, "the legacy global record was not adopted");
    const after = String(await hooks.tool.memory_list.execute({}, ctx));
    assert(after.includes("legacy global preference"), "the adopted record is still invisible");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// 6. A session that was moved into another project must not be able to read
//    that project's memories.
//
//    OpenCode can move a session to another directory, and the agent driving
//    the session can ask for it. The project key therefore may not be derived
//    from the session's own location alone: a moved session would otherwise
//    inherit the other project's memories. The plugin instance's project is
//    the authority instead.
// ---------------------------------------------------------------------------
{
  const root = await mkdtemp(join(tmpdir(), "openmind-v6-moved-"));
  try {
    const storeDir = join(root, "store");
    const projectA = join(root, "project-a");
    const projectB = join(root, "project-b");
    await mkdir(storeDir, { recursive: true });
    await mkdir(projectA, { recursive: true });
    await mkdir(projectB, { recursive: true });

    // Project B's memory, written by a session that belongs to project B.
    const ctxB = v2Context({
      location: projectB,
      options: { directory: storeDir },
      projectID: "project-b-id",
      sessions: { "session-b": { directory: projectB, projectID: "project-b-id" } },
    });
    await pluginModule.setup(ctxB);
    await ctxB.tools.get("memory_remember").execute(
      { text: "project B private preference" },
      { sessionID: "session-b", agent: "a1", messageID: "m1", signal: new AbortController().signal },
    );

    // Project A's plugin instance. Its session "moved" now lives in project
    // B's directory, but it still belongs to project A.
    const ctxA = v2Context({
      location: projectA,
      options: { directory: storeDir },
      projectID: "project-a-id",
      sessions: {
        "session-a": { directory: projectA, projectID: "project-a-id" },
        "moved": { directory: projectB, projectID: "project-b-id" },
      },
    });
    await pluginModule.setup(ctxA);

    const movedEvent = { sessionID: "moved", messages: [], system: [] };
    await ctxA.hooks.get("context")(movedEvent);
    assert(
      !systemText(movedEvent).includes("project B private preference"),
      "a session moved into another project read that project's memories",
    );

    // And it cannot write into it either: the memory lands in the session's
    // own project.
    await ctxA.tools.get("memory_remember").execute(
      { text: "written by the moved session" },
      { sessionID: "moved", agent: "a1", messageID: "m1", signal: new AbortController().signal },
    );
    const store = await readStore(join(storeDir, "memories.jsonl"));
    const written = store.find((item) => item.text === "written by the moved session");
    assert(written, "the moved session's memory was not stored");
    assert(
      written.project === projectA,
      `the moved session wrote into ${written.project} instead of its own project`,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

console.log(
  "v6.0 regressions: PASS (session-keyed injection, write-path caps, negation-only recall, reassign ownership, legacy global recovery, moved-session isolation)",
);
