// Store-scoped state: two plugin instances pointing at two different files must
// not share vault state, and deleting a store must not leave the wrong state
// behind. Also covers the delete_store lockfile/key-cache/lockout cleanup.
import { mkdtemp, readFile, rm, writeFile, mkdir, utimes } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { hostname, tmpdir } from "node:os";
import { MemoryPlugin as plugin } from "../index.js";

const directory = await mkdtemp(join(tmpdir(), "openmind-store-test-"));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

// Tools answer with a plain string in some branches and {output} in others.
function out(result) {
  return typeof result === "string" ? result : String(result?.output ?? "");
}

function context(dir = directory) {
  return {
    sessionID: "store-session",
    messageID: "store-message",
    agent: "store-agent",
    directory: dir,
    worktree: dir,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

const storeA = join(directory, "a");
const storeB = join(directory, "b");
const lockB = join(storeB, "memories.jsonl.lock");
await mkdir(storeA, { recursive: true });
await mkdir(storeB, { recursive: true });

try {
  // Two independent plugin instances rooted at two different store directories,
  // in one process.
  const hooksA = await plugin({ directory, worktree: directory }, { directory: storeA });
  const hooksB = await plugin({ directory, worktree: directory }, { directory: storeB });

  await hooksA.tool.memory_remember.execute({ text: "store A remembers this" }, context());
  await hooksB.tool.memory_remember.execute({ text: "store B remembers that" }, context());

  const listA = await hooksA.tool.memory_list.execute({ limit: 50 }, context());
  const listB = await hooksB.tool.memory_list.execute({ limit: 50 }, context());

  assert(/store A remembers this/.test(out(listA)), "store A lost its own memory");
  assert(!/store B remembers that/.test(out(listA)), "store A leaked store B's memory");
  assert(/store B remembers that/.test(out(listB)), "store B lost its own memory");
  assert(!/store A remembers this/.test(out(listB)), "store B leaked store A's memory");

  assert(existsSync(join(storeA, "memories.jsonl")) && existsSync(join(storeB, "memories.jsonl")), "one of the two stores was never written");

  // Dedupe must not cross the store boundary: the same text in both stores has
  // to stay two independent records.
  await hooksB.tool.memory_remember.execute({ text: "store A remembers this" }, context());
  const afterB = await hooksB.tool.memory_list.execute({ limit: 50 }, context());
  assert((out(afterB).match(/store A remembers this/g) || []).length === 1, "dedupe crossed store boundaries");

  console.log("  Store isolation tests...");

  // --- encryption state is per store ------------------------------------------
  // Encrypting store B must not touch store A, and A must stay readable.
  const encrypted = await hooksB.tool.memory_unlock.execute({ password: "correct horse battery" }, context());
  assert(/migrated to encryption|Created an encrypted/i.test(out(encrypted)), "store B was not encrypted");

  const listAAfter = await hooksA.tool.memory_list.execute({ limit: 50 }, context());
  assert(/store A remembers this/.test(out(listAAfter)), "encrypting B broke A");

  const rawA = await readFile(join(storeA, "memories.jsonl"), "utf8");
  assert(rawA.includes("store A remembers this"), "store A is not readable plaintext after B was encrypted");

  // B must now be ciphertext: no plaintext memory text on disk.
  const rawB = await readFile(join(storeB, "memories.jsonl"), "utf8");
  assert(!rawB.includes("store B remembers that"), "encrypted store leaked plaintext to disk");

  // (A fresh process must see B as locked: that is covered end-to-end in
  // test/locked.mjs, since in-process the unlocked state is deliberately cached.)

  const wrong = await hooksB.tool.memory_unlock.execute({ password: "nope" }, context());
  assert(/incorrect password/i.test(out(wrong)), "wrong password accepted");

  const right = await hooksB.tool.memory_unlock.execute({ password: "correct horse battery" }, context());
  assert(/unlocked/i.test(out(right)), "correct password rejected");

  const listBAfter = await hooksB.tool.memory_list.execute({ limit: 50 }, context());
  assert(/store B remembers that/.test(out(listBAfter)), "store B did not decrypt");

  console.log("    Isolation: PASS");

  // --- delete_store cleanup ----------------------------------------------------
  // A lock left behind by a crashed process (dead pid) must be reclaimed, and the
  // store must be fully usable again right after deletion.
  await writeFile(lockB, "999999999@some-other-host:deadbeef", "utf8");
  // Backdate it past the staleness window: a lock younger than that is given the
  // benefit of the doubt, which is exactly what stops a live writer losing its lock.
  const old = new Date(Date.now() - 10 * 60 * 1000);
  await utimes(lockB, old, old);
  const deleted = await hooksB.tool.memory_delete_store.execute({ confirm: true }, context());
  assert(/deleted/i.test(out(deleted)), "delete_store did not report success: " + out(deleted));
  assert(!existsSync(join(storeB, "memories.jsonl")), "store file still present after delete_store");
  assert(!existsSync(lockB), "delete_store left its own lockfile behind");

  await hooksB.tool.memory_remember.execute({ text: "recreated after deletion" }, context());
  const recreated = await hooksB.tool.memory_list.execute({ limit: 50 }, context());
  assert(/recreated after deletion/.test(out(recreated)), "store unusable after deletion");
  assert(!/store B remembers that/.test(out(recreated)), "deleted memories came back");

  // A lock that is provably alive must NOT be stolen, even once it is older than
  // the staleness window: mtime alone used to be enough to lose a live write.
  await writeFile(lockB, `${process.pid}@${hostname()}:live`, "utf8");
  await utimes(lockB, old, old);
  const contended = await hooksB.tool.memory_list.execute({ limit: 5 }, context());
  await rm(lockB, { force: true });
  assert(/OpenMind/.test(out(contended)), "a live lock was silently stolen, or the failure was not reported");

  console.log("    Cleanup: PASS");

  // --- errors surface as results, not exceptions -------------------------------
  // A store directory that cannot be written must produce a tool result the model
  // can read, not an unhandled exception that breaks the turn.
  const brokenDir = join(directory, "not-a-dir");
  await writeFile(brokenDir, "this is a file, not a directory", "utf8");
  const broken = await plugin({ directory, worktree: directory }, { directory: brokenDir });
  const brokenResult = await broken.tool.memory_remember.execute({ text: "into the void" }, context());
  assert(typeof brokenResult === "object" && brokenResult.metadata?.error === true, "a failing store did not return an error result");
  assert(/OpenMind/.test(out(brokenResult)), "error result did not explain itself: " + out(brokenResult));

  console.log("    Error handling: PASS");

  // --- injected system prompt --------------------------------------------------
  // The transform hook must inject this project's memories and nothing else.
  const other = await mkdtemp(join(tmpdir(), "openmind-store-other-"));
  await hooksA.tool.memory_remember.execute({ text: "a memory for the other worktree" }, context(other));
  const output = { messages: [], system: [] };
  await hooksA["experimental.chat.system.transform"]({ sessionID: "s" }, output);
  const block = output.system.join("\n");
  assert(/store A remembers this/.test(block), "own memory not injected");
  assert(!/a memory for the other worktree/.test(block), "another worktree's memory was injected");
  await rm(other, { recursive: true, force: true });

  console.log("    Cleanup and injection: PASS");
  console.log("store: all tests passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}
