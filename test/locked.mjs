import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import plugin from "../index.js";

const exec = promisify(execFile);
const directory = await mkdtemp(join(tmpdir(), "opencode-memory-locked-"));

function context() {
  return {
    sessionID: "locked-session",
    messageID: "locked-message",
    agent: "locked-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

try {
  const entry = new URL("../index.js", import.meta.url).pathname;
  const creator = `import plugin from ${JSON.stringify(entry)};
const d = ${JSON.stringify(directory)};
(async () => {
  const hooks = await plugin({ directory: d, worktree: d }, { directory: d });
  await hooks.tool.memory_unlock.execute({ password: "hunter2" });
  await hooks.tool.memory_remember.execute({ text: "classified project fact", scope: "project" }, { directory: d, worktree: d });
})()`;
  await exec(process.execPath, ["--input-type=module", "-e", creator]);

  const hooks = await plugin({ directory, worktree: directory }, { directory });
  const ctx = context();

  const listed = await hooks.tool.memory_list.execute({}, ctx);
  if (!String(listed).includes("encrypted and locked"))
    throw new Error("locked store did not block tools: " + String(listed));

  const unlocked = await hooks.tool.memory_unlock.execute({ password: "hunter2" }, ctx);
  if (!String(unlocked).includes("unlocked")) throw new Error("correct password did not unlock the store");

  const recalled = await hooks.tool.memory_recall.execute({ query: "classified", limit: 5 }, ctx);
  if (!String(recalled).includes("classified project fact"))
    throw new Error("unlocked store did not expose saved memories");
} finally {
  await rm(directory, { recursive: true, force: true });
}
