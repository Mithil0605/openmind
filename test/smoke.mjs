import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import plugin from "../index.js";

const directory = await mkdtemp(join(tmpdir(), "opencode-memory-test-"));

try {
  const hooks = await plugin(
    { directory, worktree: directory },
    { directory, autoInject: true, injectLimit: 5 },
  );
  const context = {
    sessionID: "smoke-session",
    messageID: "smoke-message",
    agent: "smoke-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };

  const saved = await hooks.tool.memory_remember.execute({
    text: "Smoke test memory for the portable OpenCode plugin",
    tags: ["smoke", "portable"],
    scope: "project",
    pinned: true,
  }, context);
  if (!saved.metadata?.id) throw new Error("memory_remember did not return an id");

  const recalled = await hooks.tool.memory_recall.execute({ query: "portable", limit: 5 }, context);
  if (!String(recalled).includes("portable OpenCode plugin")) throw new Error("memory_recall did not find saved memory");

  const output = { system: [] };
  await hooks["experimental.chat.system.transform"]({ sessionID: "smoke-session", model: {} }, output);
  if (!output.system.join("\n").includes("OpenMind saved preferences")) throw new Error("memory block was not injected");

  const exported = await hooks.tool.memory_export.execute({ scope: "visible" }, context);
  if (!String(exported.output).includes("portable OpenCode plugin")) throw new Error("memory_export did not include saved memory");

  const file = saved.metadata.file;
  const raw = await readFile(file, "utf8");
  if (!raw.includes("portable OpenCode plugin")) throw new Error("memory file was not written");

  const env = { env: {} };
  await hooks["shell.env"]({ cwd: directory }, env);
  if (env.env.OPENCODE_MEMORY_PROJECT !== directory) throw new Error("shell.env did not emit the correct project key");
  if (!env.env.OPENCODE_MEMORY_FILE) throw new Error("shell.env did not emit the memory file path");

  const globalAttempt = await hooks.tool.memory_remember.execute(
    { text: "Global-only preference should become a project memory", tags: ["smoke", "scope"], scope: "global" },
    context,
  );
  if (!String(globalAttempt.output).includes("(project")) throw new Error("global scope was not stored as project scope");

  const otherDirectory = join(dirname(directory), "opencode-memory-other-worktree");
  await mkdir(otherDirectory, { recursive: true });
  const otherContext = { ...context, directory: otherDirectory, worktree: otherDirectory };
  const crossList = await hooks.tool.memory_list.execute({}, otherContext);
  if (!String(crossList).includes("No memories")) throw new Error("project memory leaked into another worktree");
  await rm(otherDirectory, { recursive: true, force: true });

  const preview = await hooks.tool.memory_prune.execute({ tags: ["smoke"] }, context);
  if (preview.title !== "Deletion preview") throw new Error("memory_prune did not return a deletion preview");
  const pruned = await hooks.tool.memory_prune.execute({ tags: ["smoke"], confirm: true }, context);
  if (pruned.metadata?.count !== 2) throw new Error("memory_prune did not delete matching memories");
  try {
    await readFile(file, "utf8");
    throw new Error("empty memory store was not removed");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  await writeFile(file, `${JSON.stringify({ id: "legacy", text: "old session", scope: "session" })}\n`);
  const migrated = await plugin({ directory, worktree: directory }, { directory });
  const list = await migrated.tool.memory_list.execute({}, context);
  if (!String(list).includes("No memories")) throw new Error("legacy session data was not removed");

  // The injection budget: one oversized memory must not be able to spend the
  // whole context window, and short memories must still get through alongside it.
  const budgetDir = await mkdtemp(join(tmpdir(), "opencode-memory-budget-"));
  try {
    const budgeted = await plugin(
      { directory: budgetDir, worktree: budgetDir },
      { directory: budgetDir, autoInject: true, injectLimit: 10, injectMaxChars: 2000 },
    );
    const budgetCtx = { ...context, directory: budgetDir, worktree: budgetDir };

    await budgeted.tool.memory_remember.execute(
      { text: "O".repeat(8000), tags: ["huge"], pinned: true },
      budgetCtx,
    );
    for (let i = 0; i < 5; i += 1) {
      await budgeted.tool.memory_remember.execute({ text: `short preference ${i}`, tags: ["small"] }, budgetCtx);
    }

    const system = [];
    await budgeted["experimental.chat.system.transform"]({ sessionID: "budget", model: {} }, { system });
    const block = system.join("\n");

    if (!block.includes("OpenMind saved preferences")) throw new Error("budget test: nothing was injected");
    if (!block.includes("short preference 0")) throw new Error("budget test: short memories were crowded out");
    const longestRun = Math.max(0, ...(block.match(/O+/g) || []).map((run) => run.length));
    if (longestRun > 450) throw new Error(`budget test: 8000-char memory injected as a ${longestRun}-char run`);
    if (block.length > 2400) throw new Error(`budget test: injected ${block.length} chars, over the 2000 budget`);
  } finally {
    await rm(budgetDir, { recursive: true, force: true });
  }

  // The store must never persist an uncapped source or an unbounded tag, even
  // though the O(1) append path writes entries straight through.
  const capDir = await mkdtemp(join(tmpdir(), "opencode-memory-caps-"));
  try {
    const capped = await plugin({ directory: capDir, worktree: capDir }, { directory: capDir });
    const capCtx = { ...context, directory: capDir, worktree: capDir };
    const longTag = "z".repeat(500);
    await capped.tool.memory_remember.execute(
      { text: "cap probe", tags: [longTag, "ok"], source: "S".repeat(9000) },
      capCtx,
    );
    const capFile = await capped.tool.memory_export.execute({ scope: "all" }, capCtx);
    const record = JSON.parse(capFile.output).memories.find((m) => m.text === "cap probe");
    if (!record) throw new Error("caps test: memory was not saved");
    if (record.tags.length !== 2) throw new Error(`caps test: expected 2 tags, got ${record.tags.length}`);
    if (record.tags[0].length > 64) throw new Error(`caps test: tag was ${record.tags[0].length} chars, expected <= 64`);
    if (record.source.length > 2000) throw new Error(`caps test: source was ${record.source.length} chars, expected <= 2000`);
  } finally {
    await rm(capDir, { recursive: true, force: true });
  }

  // Orphans: records written under a project path that is no longer the current
  // worktree are invisible to every other tool, so memory_reassign must be able
  // to find and rebind them.
  const orphanStore = await mkdtemp(join(tmpdir(), "opencode-memory-orphan-"));
  try {
    const projectDir = join(orphanStore, "renamed-project");
    await mkdir(projectDir, { recursive: true });
    const storeDir = join(orphanStore, "store");
    await mkdir(storeDir, { recursive: true });
    const stamp = new Date().toISOString();
    const records = Array.from({ length: 3 }, (_, i) =>
      JSON.stringify({
        id: `orphan-${i}`,
        text: `legacy preference ${i}`,
        tags: ["legacy"],
        scope: "project",
        source: null,
        pinned: i === 0,
        project: "/somewhere/else",
        createdAt: stamp,
        updatedAt: stamp,
      }),
    );
    await writeFile(join(storeDir, "memories.jsonl"), `${records.join("\n")}\n`);

    const orphanHooks = await plugin(
      { directory: projectDir, worktree: projectDir },
      { directory: storeDir },
    );
    const orphanCtx = { ...context, directory: projectDir, worktree: projectDir };

    if (!String(await orphanHooks.tool.memory_list.execute({}, orphanCtx)).includes("No memories")) {
      throw new Error("orphan test: fixture should start invisible");
    }

    const preview = await orphanHooks.tool.memory_reassign.execute({}, orphanCtx);
    if (preview.metadata?.count !== 3) throw new Error("orphan test: preview did not find all 3 orphans");

    const single = await orphanHooks.tool.memory_reassign.execute({ ids: ["orphan-1"] }, orphanCtx);
    if (single.metadata?.count !== 3) throw new Error("orphan test: filtered preview lost the total orphan count");

    const done = await orphanHooks.tool.memory_reassign.execute({ confirm: true }, orphanCtx);
    if (done.metadata?.count !== 3) throw new Error("orphan test: reassignment did not move all 3");

    const visible = String(await orphanHooks.tool.memory_list.execute({}, orphanCtx));
    for (let i = 0; i < 3; i += 1) {
      if (!visible.includes(`legacy preference ${i}`)) throw new Error(`orphan test: memory ${i} still invisible`);
    }

    const system = [];
    await orphanHooks["experimental.chat.system.transform"]({ sessionID: "orphan", model: {} }, { system });
    if (!system.join("\n").includes("legacy preference 0")) throw new Error("orphan test: orphans still not injected");

    if (!String(await orphanHooks.tool.memory_reassign.execute({}, orphanCtx)).includes("No orphaned memories")) {
      throw new Error("orphan test: a second pass should find nothing left to reassign");
    }
  } finally {
    await rm(orphanStore, { recursive: true, force: true });
  }

  // Ranking: pinning must not hijack relevance. A pinned memory that matches one
  // incidental term must lose to an unpinned memory that matches the query.
  const rankDir = await mkdtemp(join(tmpdir(), "opencode-memory-rank-"));
  try {
    const ranked = await plugin({ directory: rankDir, worktree: rankDir }, { directory: rankDir });
    const rankCtx = { ...context, directory: rankDir, worktree: rankDir };

    await ranked.tool.memory_remember.execute(
      { text: "deployment notes mention a github repository and a handoff", pinned: true, dedupe: false },
      rankCtx,
    );
    await ranked.tool.memory_remember.execute(
      { text: "identity profile: sample user, github handle, personal projects", dedupe: false },
      rankCtx,
    );

    const hits = String(await ranked.tool.memory_recall.execute({ query: "identity sample", limit: 5 }, rankCtx));
    // formatMemory puts the id on the first line and the text on the second.
    const topEntry = hits.split("\n\n")[0];
    if (!topEntry.includes("identity profile")) {
      throw new Error(`rank test: pinned memory outranked the exact match; got: ${topEntry.replace(/\n/g, " ")}`);
    }
  } finally {
    await rm(rankDir, { recursive: true, force: true });
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
