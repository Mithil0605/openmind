import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
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
  if (!output.system.join("\n").includes("OpenMind saved preferences:")) throw new Error("memory block was not injected");

  const exported = await hooks.tool.memory_export.execute({ scope: "visible" }, context);
  if (!String(exported.output).includes("portable OpenCode plugin")) throw new Error("memory_export did not include saved memory");

  const file = saved.metadata.file;
  const raw = await readFile(file, "utf8");
  if (!raw.includes("portable OpenCode plugin")) throw new Error("memory file was not written");

  const preview = await hooks.tool.memory_prune.execute({ tags: ["smoke"] }, context);
  if (preview.title !== "Deletion preview") throw new Error("memory_prune did not return a deletion preview");
  const pruned = await hooks.tool.memory_prune.execute({ tags: ["smoke"], confirm: true }, context);
  if (pruned.metadata?.count !== 1) throw new Error("memory_prune did not delete matching memory");
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
} finally {
  await rm(directory, { recursive: true, force: true });
}
