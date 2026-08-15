import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import plugin from "../index.js";

const exec = promisify(execFile);
const directory = await mkdtemp(join(tmpdir(), "opencode-memory-sec-"));

function context(worktree = directory) {
  return {
    sessionID: "sec-session",
    messageID: "sec-message",
    agent: "sec-agent",
    directory: worktree,
    worktree,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

try {
  // -------------------------------------------------------------------------
  // 1. Input injection / fuzzing (plaintext store).
  // -------------------------------------------------------------------------
  const hooks = await plugin({ directory, worktree: directory }, { directory });
  const ctx = context();

  const injected = await hooks.tool.memory_remember.execute(
    { text: "line one\n{\"id\":\"forged\",\"scope\":\"global\"}", tags: ["inject"], scope: "project" },
    ctx,
  );
  const exported = JSON.parse((await hooks.tool.memory_export.execute({ scope: "all" }, ctx)).output);
  const injectedBack = exported.memories.find((m) => m.text.includes("forged"));
  assert(injectedBack && injectedBack.id === injected.metadata.id, "newline text injected a forged record");
  assert(exported.memories.length === 1, "injection created extra records");

  const poly = await hooks.tool.memory_remember.execute(
    { text: "prototype pollution probe", tags: ["__proto__", "constructor", "hasOwnProperty"], scope: "project" },
    ctx,
  );
  assert(({}).polluted === undefined && ({})["data-polluted"] === undefined, "prototype was polluted");

  const manyTags = await hooks.tool.memory_remember.execute(
    { text: "tag cap probe", tags: Array.from({ length: 200 }, (_, i) => `t${i}`), scope: "project" },
    ctx,
  );
  const manyTagsBack = JSON.parse((await hooks.tool.memory_export.execute({ scope: "all" }, ctx)).output)
    .memories.find((m) => m.text === "tag cap probe");
  assert(manyTagsBack.tags.length <= 50, "tags array was not capped");

  const wild = await hooks.tool.memory_recall.execute({ query: "[a-z]+ -no-{match} *?", limit: 5 }, ctx);
  assert(typeof wild === "string", "regex metacharacters crashed recall");

  await hooks.tool.memory_remember.execute({ text: "x".repeat(9000), scope: "project" }, ctx);
  const oversized = JSON.parse((await hooks.tool.memory_export.execute({ scope: "all" }, ctx)).output)
    .memories.find((m) => m.text.startsWith("xxxxx"));
  assert(!oversized || oversized.text.length <= 8000, "oversized memory text was not capped");

  // 2. Tampered / corrupt plaintext store must not crash the plugin.
  const file = (await hooks.tool.memory_export.execute({ scope: "all" }, ctx)).metadata.file;
  await writeFile(file, `not json at all\n${JSON.stringify({ id: "ok", text: "valid line", scope: "project", project: directory })}\n`);
  const survived = await hooks.tool.memory_list.execute({ limit: 50 }, ctx);
  assert(String(survived).includes("valid line"), "corrupt store line crashed the plugin");

  // -------------------------------------------------------------------------
  // 3. Symlink attack on the store file must not write through the link.
  // -------------------------------------------------------------------------
  const victim = join(directory, "victim.txt");
  await writeFile(victim, "original");
  await rm(file, { force: true });
  await symlink(victim, file);
  const hooks2 = await plugin({ directory, worktree: directory }, { directory });
  await hooks2.tool.memory_remember.execute({ text: "symlink write probe", scope: "project" }, ctx);
  const victimContent = await readFile(victim, "utf8");
  assert(victimContent === "original", "store write followed a symlink to a victim file");
  const fileInfo = await stat(file);
  assert(fileInfo.isFile() && !fileInfo.isSymbolicLink(), "store file is still a symlink after write");

  // 4. No leftover temp files after atomic writes.
  const leftovers = (await import("node:fs/promises")).readdir(directory);
  const tmpFiles = (await leftovers).filter((name) => name.endsWith(".tmp"));
  assert(tmpFiles.length === 0, "atomic write left temp files behind");

  // -------------------------------------------------------------------------
  // 5. Encryption: tampered ciphertext must fail authentication.
  // -------------------------------------------------------------------------
  const secure = join(directory, "secure");
  const secureHooks = await plugin({ directory: secure, worktree: secure }, { directory: secure });
  const secureCtx = context(secure);
  await secureHooks.tool.memory_unlock.execute({ password: "hunter2" }, secureCtx);
  await secureHooks.tool.memory_remember.execute({ text: "top secret value", scope: "project" }, secureCtx);
  const secureFile = join(secure, "memories.jsonl");
  const rawEnc = (await readFile(secureFile, "utf8")).split("\n");
  const body = rawEnc[1];
  const parts = body.split(":");
  const cipher = parts[parts.length - 1];
  const mid = Math.floor(cipher.length / 2);
  parts[parts.length - 1] =
    cipher.slice(0, mid) + (cipher[mid] === "A" ? "B" : "A") + cipher.slice(mid + 1);
  rawEnc[1] = parts.join(":");
  await writeFile(secureFile, rawEnc.join("\n"));
  const reread = await readFile(secureFile, "utf8");
  assert(reread.split("\n")[1] !== body, "tamper did not change the ciphertext");

  const tampered = await secureHooks.tool.memory_unlock.execute({ password: "hunter2" }, secureCtx);
  assert(/incorrect/i.test(String(tampered)), "tampered ciphertext was not rejected by GCM");

  // 6. Permissions: file 0600, directory 0700.
  const fileMode = (await stat(secureFile)).mode & 0o777;
  const dirMode = (await stat(secure)).mode & 0o777;
  assert(fileMode === 0o600, `store file mode is ${fileMode.toString(8)}, expected 600`);
  assert(dirMode <= 0o700, `store dir mode is ${dirMode.toString(8)}, expected <=700`);

  // 7. Locked encrypted store must not disclose contents.
  const lockedDir = join(directory, "locked");
  await mkdir(lockedDir, { recursive: true });
  const creator = `import plugin from ${JSON.stringify(new URL("../index.js", import.meta.url).pathname)};
const d = ${JSON.stringify(lockedDir)};
(async () => {
  const h = await plugin({ directory: d, worktree: d }, { directory: d });
  await h.tool.memory_unlock.execute({ password: "hunter2" });
  await h.tool.memory_remember.execute({ text: "CLASSIFIED-SECRET-CONTENT", scope: "project" }, { directory: d, worktree: d });
})()`;
  await exec(process.execPath, ["--input-type=module", "-e", creator]);

  const lockedHooks = await plugin({ directory: lockedDir, worktree: lockedDir }, { directory: lockedDir });
  const lockedCtx = context(lockedDir);
  for (const [name, call] of Object.entries({
    remember: () => lockedHooks.tool.memory_remember.execute({ text: "probe", scope: "project" }, lockedCtx),
    recall: () => lockedHooks.tool.memory_recall.execute({ query: "CLASSIFIED", limit: 5 }, lockedCtx),
    list: () => lockedHooks.tool.memory_list.execute({}, lockedCtx),
    update: () => lockedHooks.tool.memory_update.execute({ id: "x", text: "probe" }, lockedCtx),
    forget: () => lockedHooks.tool.memory_forget.execute({ id: "x" }, lockedCtx),
    prune: () => lockedHooks.tool.memory_prune.execute({ tags: ["x"], confirm: true }, lockedCtx),
    export: () => lockedHooks.tool.memory_export.execute({ scope: "all" }, lockedCtx),
  })) {
    const out = String(await call());
    assert(/encrypted and locked/i.test(out), `${name} on a locked store leaked data: ${out.slice(0, 80)}`);
    assert(!out.includes("CLASSIFIED-SECRET-CONTENT"), `${name} leaked memory content while locked`);
  }

  // 8. delete_store without confirmation is refused.
  const refused = await lockedHooks.tool.memory_delete_store.execute({}, lockedCtx);
  assert(/confirm: true/i.test(String(refused)), "store deletion without confirmation was not refused");

  // 9. Cross-process concurrent writes never corrupt the file format.
  const xproc = join(directory, "xproc");
  await mkdir(xproc, { recursive: true });
  const writer = `import plugin from ${JSON.stringify(new URL("../index.js", import.meta.url).pathname)};
const d = ${JSON.stringify(xproc)};
const c = { directory: d, worktree: d };
(async () => {
  const h = await plugin(c, { directory: d });
  for (let i = 0; i < 25; i += 1) await h.tool.memory_remember.execute({ text: "proc " + process.pid + " " + i, scope: "project" }, c);
})()`;
  await Promise.all([
    exec(process.execPath, ["--input-type=module", "-e", writer]),
    exec(process.execPath, ["--input-type=module", "-e", writer]),
  ]);
  const xprocFile = join(xproc, "memories.jsonl");
  const xraw = (await readFile(xprocFile, "utf8")).split("\n").filter(Boolean);
  const validLines = xraw.filter((line) => {
    try { JSON.parse(line); return true; } catch { return false; }
  });
  assert(validLines.length === xraw.length, "cross-process writes corrupted the JSONL format");

  console.log("VAPT: all penetration tests passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}
