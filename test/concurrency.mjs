import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import plugin from "../index.js";

const directory = await mkdtemp(join(tmpdir(), "opencode-memory-conc-"));

function context() {
  return {
    sessionID: "conc-session",
    messageID: "conc-message",
    agent: "conc-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

try {
  const hooks = await plugin({ directory, worktree: directory }, { directory });
  const ctx = context();
  const COUNT = 60;

  const jobs = [];
  for (let i = 0; i < COUNT; i += 1) {
    jobs.push(
      hooks.tool.memory_remember.execute(
        { text: `concurrent fact number ${i}`, tags: ["concurrent"], scope: "project" },
        ctx,
      ),
    );
  }
  const results = await Promise.all(jobs);
  if (results.some((result) => result.title !== "Memory saved"))
    throw new Error("concurrent save failed or deduped unexpectedly");

  const exported = JSON.parse((await hooks.tool.memory_export.execute({ scope: "all" }, ctx)).output);
  if (exported.count !== COUNT)
    throw new Error(`write lock lost rows: expected ${COUNT}, got ${exported.count}`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
