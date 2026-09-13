import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deflateSync } from "node:zlib";
import plugin from "../index.js";

const directory = await mkdtemp(join(tmpdir(), "openmind-image-test-"));

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function makePng(width, height, byte = 0x2e) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2; // RGB
  const bpp = 3;
  const raw = Buffer.alloc(height * (1 + width * bpp));
  for (let y = 0; y < height; y += 1) {
    raw[y * (1 + width * bpp)] = 0;
    for (let x = 0; x < width; x += 1) {
      const o = y * (1 + width * bpp) + 1 + x * bpp;
      raw[o] = byte;
      raw[o + 1] = byte ^ 0x40;
      raw[o + 2] = byte ^ 0x80;
    }
  }
  return Buffer.concat([sig, pngChunk("IHDR", ihdr), pngChunk("IDAT", deflateSync(raw)), pngChunk("IEND", Buffer.alloc(0))]);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function context() {
  return {
    sessionID: "img-session",
    messageID: "img-message",
    agent: "img-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

try {
  const hooks = await plugin({ directory, worktree: directory }, { directory, autoInject: true });
  const ctx = context();

  // 1. PNG metadata (OCR disabled for a deterministic check).
  const png = join(directory, "sample.png");
  await writeFile(png, makePng(640, 480));
  const noOcr = await hooks.tool.image_read.execute({ target: png, ocr: false }, ctx);
  const noOcrText = String(noOcr.output || noOcr);
  assert(/PNG \(raster\)/.test(noOcrText), "PNG type was not detected");
  assert(/640x480/.test(noOcrText), "PNG dimensions were not reported");
  assert(!/python3 is not installed/i.test(noOcrText), "unexpected fallback path with python available");

  // 2. OCR path runs (tesseract may be present or not) and never crashes.
  const withOcr = await hooks.tool.image_read.execute({ target: png }, ctx);
  const withOcrText = String(withOcr.output || withOcr);
  assert(/\[ocr\]/.test(withOcrText) || /OCR skipped/.test(withOcrText), "OCR path did not run cleanly");

  // 3. SVG is dumped as text.
  const svg = join(directory, "diagram.svg");
  await writeFile(svg, '<svg width="100" height="50"><rect width="100" height="50" fill="red"/></svg>');
  const svgOut = String((await hooks.tool.image_read.execute({ target: svg, ocr: false }, ctx)).output);
  assert(/<svg/.test(svgOut), "SVG markup was not surfaced as text");

  // 4. Large image path is accepted (default max), result still returns.
  const big = join(directory, "big.png");
  await writeFile(big, makePng(2600, 1800, 0x7a));
  const bigOut = String((await hooks.tool.image_read.execute({ target: big, ocr: false }, ctx)).output);
  assert(/\[resize\]/.test(bigOut), "large image was not downscaled");

  // 5. Explicit max is honored without crashing.
  const maxOut = String((await hooks.tool.image_read.execute({ target: big, ocr: false, max: 500 }, ctx)).output);
  assert(/\[resize\]/.test(maxOut), "custom max did not run");

  // 6. Missing file -> clean message.
  const missing = await hooks.tool.image_read.execute({ target: join(directory, "nope.png") }, ctx);
  assert(/No such image file/.test(String(missing.output || missing)), "missing file did not produce a clean message");

  // 7. Flag-like target is rejected before anything runs.
  const flag = await hooks.tool.image_read.execute({ target: "-force" }, ctx);
  assert(/not a flag/.test(String(flag)), "flag-like target was not rejected");

  // 8. Control characters are rejected.
  const ctl = await hooks.tool.image_read.execute({ target: "../x\nreboot" }, ctx);
  assert(/control characters/.test(String(ctl.output || ctl)), "control-character target was not rejected");

  // 9. Non-image files are refused WITHOUT leaking contents.
  const secret = join(directory, "memo.txt");
  const marker = "TOP-SECRET-MARKER-9461";
  await writeFile(secret, `hello ${marker}\n`);
  const refused = await hooks.tool.image_read.execute({ target: secret, ocr: false }, ctx);
  const refusedText = String(refused.output || refused);
  assert(/Not a recognized image format/.test(refusedText), "non-image file was not refused");
  assert(!refusedText.includes(marker), "non-image file contents leaked into tool output");

  // 10. Output never includes the machine home path (identity redaction).
  const home = process.env.HOME || "";
  assert(!noOcrText.includes(home), "tool output leaked the home directory path");

  // 11. Relative path resolves against the project directory.
  const rel = await hooks.tool.image_read.execute({ target: "sample.png", ocr: false }, ctx);
  assert(/640x480/.test(String(rel.output || rel)), "relative target did not resolve inside the project");

  console.log("image tests passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}