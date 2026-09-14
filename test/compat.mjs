import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import plugin from "../index.js";

const dir = await mkdtemp(join(tmpdir(), "openmind-compat-"));
function ctx(d = dir) { return { sessionID: "compat", messageID: "m", agent: "a", directory: d, worktree: d, abort: new AbortController().signal, metadata() {}, ask() {} }; }
function assert(c, m) { if (!c) throw new Error(m); }

// Simulate a v4-era plaintext store
const DATE = new Date().toISOString();
const v4line = JSON.stringify({
  id: "v4-memory-001",
  text: "V4 legacy memory about the test project",
  tags: ["legacy", "v4"],
  scope: "project",
  source: "v4 store",
  pinned: false,
  project: dir,
  createdAt: DATE,
  updatedAt: DATE,
});
const v4global = JSON.stringify({
  id: "v4-global-001",
  text: "This should be ignored by v5",
  tags: ["legacy"],
  scope: "global",
  project: null,
  createdAt: DATE,
  updatedAt: DATE,
});
await writeFile(join(dir, "memories.jsonl"), `${v4line}\n${v4global}\n`);

try {
  const hooks = await plugin({ directory: dir, worktree: dir }, { directory: dir });
  const list = await hooks.tool.memory_list.execute({}, ctx());
  const text = String(list);
  assert(text.includes("V4 legacy memory"), "v5 failed to read v4 project memory: " + text);
  assert(!text.includes("This should be ignored by v5"), "v5 leaked v4 global-scope memory");
  console.log("V4 compatibility: PASS (legacy project memory read, global legacy ignored)");

  // Encrypted v4-style store should migrate/read too
  const unlock = await hooks.tool.memory_unlock.execute({ password: "compat-pw" }, ctx());
  const after = await hooks.tool.memory_list.execute({}, ctx());
  assert(String(after).includes("V4 legacy memory"), "v5 lost v4 memory after encryption migration");
  const raw = await readFile(join(dir, "memories.jsonl"), "utf8");
  assert(raw.startsWith("OPENMIND_ENC_V2"), "store was not encrypted in v5 format");
  console.log("V4 encrypted migration: PASS");

  const recall = await hooks.tool.memory_recall.execute({ query: "test project", limit: 5 }, ctx());
  assert(String(recall).includes("V4 legacy memory"), "v5 failed to recall v4 memory");
  console.log("V4 recall compatibility: PASS");
} finally {
  await rm(dir, { recursive: true, force: true });
}
