import { mkdtemp, readFile, rm } from "node:fs/promises";
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
  if (!output.system.join("\n").includes("Persistent memory:")) throw new Error("memory block was not injected");

  const exported = await hooks.tool.memory_export.execute({ scope: "visible" }, context);
  if (!String(exported.output).includes("portable OpenCode plugin")) throw new Error("memory_export did not include saved memory");

  const file = saved.metadata.file;
  const raw = await readFile(file, "utf8");
  if (!raw.includes("portable OpenCode plugin")) throw new Error("memory file was not written");
} finally {
  await rm(directory, { recursive: true, force: true });
}
