import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import plugin from "../index.js";

const directory = await mkdtemp(join(tmpdir(), "opencode-memory-enc-"));

function context() {
  return {
    sessionID: "enc-session",
    messageID: "enc-message",
    agent: "enc-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

try {
  const hooks = await plugin(
    { directory, worktree: directory },
    { directory, autoInject: true, injectLimit: 5 },
  );
  const ctx = context();

  const saved = await hooks.tool.memory_remember.execute(
    { text: "secret preference alpha", tags: ["secret"], scope: "project" },
    ctx,
  );
  const file = saved.metadata.file;

  const migrated = await hooks.tool.memory_unlock.execute({ password: "hunter2" }, ctx);
  if (!String(migrated).includes("migrated")) throw new Error("memory_unlock did not migrate the store");

  const raw = await readFile(file, "utf8");
  if (!raw.startsWith("OPENMIND_ENC_V2")) throw new Error("store was not encrypted after unlock");
  if (raw.includes("secret preference")) throw new Error("plaintext leaked into the encrypted store");

  const duplicate = await hooks.tool.memory_remember.execute(
    { text: "secret preference alpha", tags: ["secret", "extra"], scope: "project" },
    ctx,
  );
  if (duplicate.title !== "Memory updated") throw new Error("dedupe did not update the existing memory");
  const listed = await hooks.tool.memory_list.execute({ limit: 50 }, ctx);
  if ((String(listed).match(/secret preference/g) || []).length !== 1) throw new Error("dedupe created a duplicate");

  const updated = await hooks.tool.memory_update.execute(
    { id: duplicate.metadata.id, text: "secret preference beta", pinned: true },
    ctx,
  );
  if (!String(updated.output).includes("secret preference beta")) throw new Error("memory_update did not apply");

  await hooks.tool.memory_remember.execute({ text: "secret note about wireshark", scope: "project" }, ctx);
  const recalled = await hooks.tool.memory_recall.execute({ query: "secret -beta", limit: 10 }, ctx);
  if (!String(recalled).includes("wireshark")) throw new Error("positive search term did not match");
  if (String(recalled).includes("beta")) throw new Error("negated term was not excluded");

  for (let i = 0; i < 5; i += 1) {
    await hooks.tool.memory_unlock.execute({ password: "wrong-password" }, ctx);
  }
  const next = await hooks.tool.memory_unlock.execute({ password: "wrong-password" }, ctx);
  if (!/locked/i.test(String(next))) throw new Error("rate limiter did not lock access: " + String(next));

  const exported = await hooks.tool.memory_export.execute({ scope: "all" }, ctx);
  if (!String(exported.output).includes('"encrypted": true')) throw new Error("export does not report encryption");
} finally {
  await rm(directory, { recursive: true, force: true });
}
