import { mkdtemp, readdir, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deflateSync } from "node:zlib";
import { MemoryPlugin as plugin } from "../index.js";

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

// A minimal, valid multi-page PDF with real text operators, built by hand so
// the test needs no PDF library: a rasterizer must be able to open it.
function makePdf(labels) {
  const count = labels.length;
  const fontId = 3 + count * 2;
  const pageId = (i) => 3 + i * 2;
  const contentId = (i) => 4 + i * 2;
  const objects = [];
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${labels.map((_, i) => `${pageId(i)} 0 R`).join(" ")}] /Count ${count} >>`;
  labels.forEach((label, i) => {
    objects[pageId(i)] =
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] ` +
      `/Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId(i)} 0 R >>`;
    const stream = `BT /F1 28 Tf 40 100 Td (${label}) Tj ET`;
    objects[contentId(i)] = `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`;
  });
  objects[fontId] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

  let out = "%PDF-1.4\n";
  const offsets = [];
  for (let id = 1; id <= objects.length; id += 1) {
    offsets[id] = out.length;
    out += `${id} 0 obj\n${objects[id]}\nendobj\n`;
  }
  const startxref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let id = 1; id <= objects.length; id += 1) {
    out += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
  }
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${startxref}\n%%EOF\n`;
  return Buffer.from(out, "latin1");
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

  // 12. The model must receive the image itself, not only a description of it.
  //     ToolResult.attachments is the only channel that carries pixels.
  const attached = await hooks.tool.image_read.execute({ target: png, ocr: false }, ctx);
  const atts = attached.attachments || [];
  assert(atts.length === 1, "image_read returned no attachment");
  assert(atts[0].type === "file" && atts[0].mime === "image/png", "attachment is not a PNG file part");
  assert(/^data:image\/png;base64,iVBORw0KGgo/.test(atts[0].url), "attachment url is not a PNG data URL");
  assert(attached.metadata?.attached === true, "attachment was not reported in metadata");
  assert(/\[attach\]/.test(String(attached.output)), "attachment was not explained in the text output");

  // 13. attach:false must still work and must say the image was not attached.
  const noAttach = await hooks.tool.image_read.execute({ target: png, ocr: false, attach: false }, ctx);
  assert((noAttach.attachments || []).length === 0, "attach:false still attached an image");
  assert(/attach:false|attach was disabled/.test(String(noAttach.output)), "attach:false did not explain itself");
  assert(/640x480/.test(String(noAttach.output)), "attach:false lost the metadata");

  // 14. PDFs are rasterized, not refused with a dead-end hint.
  const pdfPath = join(directory, "doc.pdf");
  await writeFile(pdfPath, makePdf(["ALPHA", "BETA"]));
  const pdfOut = await hooks.tool.image_read.execute({ target: pdfPath, pages: 2 }, ctx);
  const pdfText = String(pdfOut.output || pdfOut);
  assert(/\[type\] PDF \(document\)/.test(pdfText), "PDF was not recognized as a document");
  const rasterized = /PDF page 1\/2/.test(pdfText) && /\[raster\] \d+x\d+/.test(pdfText);
  if (/rasterization needs one of/.test(pdfText)) {
    assert(/pdftoppm/.test(pdfText), "missing-PDF hint does not name a rasterizer");
  } else {
    assert(rasterized, "PDF pages were not rasterized");
    assert(/\[ocr\]/.test(pdfText), "rasterized PDF pages were not OCR'd");
    assert((pdfOut.attachments || []).length === 1, "rasterized PDF page 1 was not attached");
  }
  // The emitted temp PNG must not be left behind in the temp dir.
  const leftovers = (await readdir(tmpdir())).filter((name) => name.startsWith(`openmind-img-${process.pid}-`));
  assert(leftovers.length === 0, `image_read leaked ${leftovers.length} temp attachment file(s)`);

  // 15. A single PDF page by default: pages must not be fetched implicitly.
  const onePage = await hooks.tool.image_read.execute({ target: pdfPath }, ctx);
  assert(/PDF page 1\/1/.test(String(onePage.output || onePage)), "default PDF page count is not 1");

  console.log("image tests passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}