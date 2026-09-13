import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import plugin from "../index.js";

const exec = promisify(execFile);
const directory = await mkdtemp(join(tmpdir(), "openmind-vapt-test-"));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function context() {
  return {
    sessionID: "vapt-session",
    messageID: "vapt-message",
    agent: "vapt-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

try {
  const hooks = await plugin({ directory, worktree: directory }, { directory });

  // -------------------------------------------------------------------------
  // 1. SSRF: private / loopback / cloud-metadata hosts must be blocked and
  //    the local service must never receive a request.
  // -------------------------------------------------------------------------
  const hits = [];
  const server = createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(200, { "Content-Type": "image/png" });
    res.end(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  for (const target of [
    `http://127.0.0.1:${port}/steal.png`,
    `http://169.254.169.254/latest/meta-data/iam/security-credentials`,
    "http://10.0.0.1/x.png",
    "http://192.168.1.1/x.png",
    `http://[::1]:${port}/steal.png`,
  ]) {
    const out = await hooks.tool.image_read.execute({ target, ocr: false }, context());
    const text = String(out.output || out);
    assert(/blocked|refused|public/i.test(text), `SSRF guard did not block ${target}: ${text}`);
  }
  assert(hits.length === 0, "SSRF reached a local/private service");

  server.close();
  await new Promise((resolve) => server.close(resolve));

  // -------------------------------------------------------------------------
  // 2. Command injection: create REAL hostile filenames (so any shell-based
  //    call in the pipeline would execute) and prove nothing runs. The helper
  //    uses subprocess argument arrays, so the payloads must stay inert bytes.
  // -------------------------------------------------------------------------
  const envHost = process.env.HOSTNAME || process.env.HOST || "";
  const probeFiles = [
    "x.png; id",
    "$(whoami).png",
    "$(uname -a).png",
    "foo`uname`bar.png",
    "sq | hostname | sort.png",
    "a&&id&&b.png",
    "x>planted.png",
  ];
  for (const name of probeFiles) {
    const probePath = join(directory, name);
    await writeFile(probePath, "payload text, not an image");
    const out = await hooks.tool.image_read.execute({ target: probePath, ocr: false }, context());
    const text = String(out.output || out);
    assert(/Not a recognized image format/.test(text), `hostile payload file was not refused: ${name}`);
    assert(!/uid=\d+|gid=\d+/.test(text), `injection executed id: ${name}`);
    assert(!/\bLinux\b/.test(text), `injection executed a command: ${name}`);
    assert(!/^root$/m.test(text), `injection executed whoami: ${name}`);
    if (envHost) assert(!text.includes(envHost), `injection executed hostname: ${name}`);
  }
  const planted = await import("node:fs").then((fs) => fs.existsSync(join(directory, "planted.png"))).catch(() => false);
  if (planted) await rm(join(directory, "planted.png"), { force: true });
  assert(!planted, "shell redirect payload created a file");

  // -------------------------------------------------------------------------
  // 3. The helper process is spawned without a shell: verify no shell usage.
  // -------------------------------------------------------------------------
  const entry = fileURLToPath(new URL("../index.js", import.meta.url));
  const indexSrc = await readFile(entry, "utf8");
  assert(!/shell\s*:\s*true/.test(indexSrc), "plugin spawns processes via a shell");

  // -------------------------------------------------------------------------
  // 4. No private system info reaches tool output for normal reads.
  // -------------------------------------------------------------------------
  const png = join(directory, "safe.png");
  await writeFile(png, Buffer.from(
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 73, 72,
     68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0, 0x90, 0x77, 0x53, 0xde,
     0, 0, 0, 12, 73, 68, 65, 84, 8, 0xc4, 0xc4, 0x00, 0x12, 0x00, 0x00, 0x19,
     0x8f, 0x09, 0x49, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
     0x42, 0x60, 0x82],
  ));
  const out = await hooks.tool.image_read.execute({ target: png, ocr: false }, context());
  const text = String(out.output || out);
  assert(/PNG \(raster\)/.test(text), "valid 1x1 PNG was not read");
  if (envHost) assert(!text.includes(envHost), "tool output leaked the hostname");
  const home = process.env.HOME || "";
  if (home) assert(!text.includes(home), "tool output leaked the home path");

  // -------------------------------------------------------------------------
  // 5. Locked encrypted store must still refuse reads and never leak.
  //    (Run in a child process so vault state starts fresh and locked.)
  // -------------------------------------------------------------------------
  const secure = join(directory, "secure");
  await mkdir(secure, { recursive: true });
  const secureCtx = context();
  secureCtx.directory = secure;
  secureCtx.worktree = secure;
  const seed = `import plugin from ${JSON.stringify(new URL("../index.js", import.meta.url).pathname)};
const d = ${JSON.stringify(secure)};
const c = { directory: d, worktree: d };
(async () => {
  const h = await plugin(c, { directory: d });
  await h.tool.memory_unlock.execute({ password: "hunter2" }, c);
  await h.tool.memory_remember.execute({ text: "SECRET-CLASSIFIED-993", scope: "project" }, c);
})()`;
  await exec(process.execPath, ["--input-type=module", "-e", seed]);
  const probe = `import plugin from ${JSON.stringify(new URL("../index.js", import.meta.url).pathname)};
const d = ${JSON.stringify(secure)};
const c = { directory: d, worktree: d };
(async () => {
  const h = await plugin(c, { directory: d });
  const out = await h.tool.memory_list.execute({}, c);
  console.log("RESULT:" + JSON.stringify(String(out)));
  process.exit(!/encrypted and locked/i.test(String(out)) || String(out).includes("SECRET-CLASSIFIED-993") ? 1 : 0);
})()`;
  const { stdout } = await exec(process.execPath, ["--input-type=module", "-e", probe]);
  assert(/RESULT:.*encrypted and locked/i.test(stdout), "locked store did not refuse reads");
  assert(!stdout.includes("SECRET-CLASSIFIED-993"), "locked store leaked content");

  // -------------------------------------------------------------------------
  // 6. Cross-process concurrency on memory writes leaves valid JSONL.
  // -------------------------------------------------------------------------
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
  const xraw = (await readFile(join(xproc, "memories.jsonl"), "utf8")).split("\n").filter(Boolean);
  assert(xraw.every((line) => { try { JSON.parse(line); return true; } catch { return false; } }),
    "cross-process memory writes corrupted the JSONL format");

  console.log("VAPT: all penetration tests passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}