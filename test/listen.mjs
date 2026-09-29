import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import plugin, { buildAnalysis } from "../index.js";

const directory = await mkdtemp(join(tmpdir(), "openmind-listen-test-"));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function context() {
  return {
    sessionID: "listen-session",
    messageID: "listen-message",
    agent: "listen-agent",
    directory,
    worktree: directory,
    abort: new AbortController().signal,
    metadata() {},
    ask() {},
  };
}

const SAMPLE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Test Page - OpenMind Listen</title>
  <meta name="description" content="A test page for OpenMind listen analysis">
  <meta name="author" content="Test Author">
  <meta name="keywords" content="test, openmind, listen">
  <meta property="og:title" content="Test OG Title">
  <meta property="og:description" content="Test OG Description">
  <meta property="og:image" content="https://example.com/og-image.png">
</head>
<body>
  <h1>Welcome to Test Page</h1>
  <h2>Section One</h2>
  <p>This is a paragraph with <a href="https://example.com/link1">Link 1</a> and <a href="https://example.com/link2">Link 2</a>.</p>
  <h3>Code Example</h3>
  <pre><code>const x = 42;\nconst y = 100;</code></pre>
  <ul>
    <li>Item A</li>
    <li>Item B</li>
    <li>Item C</li>
  </ul>
  <ol>
    <li>First</li>
    <li>Second</li>
  </ol>
  <table>
    <tr><th>Name</th><th>Value</th></tr>
    <tr><td>foo</td><td>1</td></tr>
    <tr><td>bar</td><td>2</td></tr>
  </table>
  <img src="https://example.com/photo.jpg" alt="A photo">
  <img src="https://example.com/logo.png" alt="">
  <a href="#top">Back to top</a>
  <a href="javascript:void(0)">JS link</a>
</body>
</html>`;

try {
  const hooks = await plugin({ directory, worktree: directory }, { directory });
  const ctx = context();

  // =========================================================================
  // PART 1: SSRF guard tests (no network needed)
  // =========================================================================
  console.log("  SSRF guard tests...");

  // Test blocked: cloud metadata
  const ssrf1 = await hooks.tool.listen_analyze.execute({ url: "http://169.254.169.254/latest/meta-data/" }, ctx);
  assert(/blocked|private|loopback/i.test(String(ssrf1.output || ssrf1)), "cloud metadata not blocked");

  // Test blocked: localhost
  const ssrf2 = await hooks.tool.listen_analyze.execute({ url: "http://localhost:8080/secret" }, ctx);
  assert(/blocked|private|loopback/i.test(String(ssrf2.output || ssrf2)), "localhost not blocked");

  // Test blocked: 10.x
  const ssrf3 = await hooks.tool.listen_analyze.execute({ url: "http://10.0.0.1/internal" }, ctx);
  assert(/blocked|private/i.test(String(ssrf3.output || ssrf3)), "10.x not blocked");

  // Test blocked: 192.168.x
  const ssrf4 = await hooks.tool.listen_analyze.execute({ url: "http://192.168.1.1/admin" }, ctx);
  assert(/blocked|private/i.test(String(ssrf4.output || ssrf4)), "192.168 not blocked");

  // Test blocked: link-local IPv6
  const ssrf5 = await hooks.tool.listen_analyze.execute({ url: "http://[fe80::1]/steal" }, ctx);
  assert(/blocked|private/i.test(String(ssrf5.output || ssrf5)), "link-local IPv6 not blocked");

  // Test blocked: .local domain
  const ssrf6 = await hooks.tool.listen_analyze.execute({ url: "http://mydevice.local/api" }, ctx);
  assert(/blocked|local/i.test(String(ssrf6.output || ssrf6)), ".local domain not blocked");

  // Test blocked: .internal domain
  const ssrf7 = await hooks.tool.listen_analyze.execute({ url: "http://service.internal/data" }, ctx);
  assert(/blocked|internal/i.test(String(ssrf7.output || ssrf7)), ".internal domain not blocked");

  // Test blocked: non-http protocol
  const ssrf8 = await hooks.tool.listen_analyze.execute({ url: "file:///etc/passwd" }, ctx);
  assert(/only http|blocked|invalid/i.test(String(ssrf8.output || ssrf8)), "file:// protocol not blocked");

  // Test blocked: ftp protocol
  const ssrf9 = await hooks.tool.listen_analyze.execute({ url: "ftp://example.com/file" }, ctx);
  assert(/only http|blocked|invalid/i.test(String(ssrf9.output || ssrf9)), "ftp:// protocol not blocked");

  console.log("    SSRF: PASS (9 tests)");

  // =========================================================================
  // PART 2: Input validation tests
  // =========================================================================
  console.log("  Input validation tests...");

  // Empty URL
  const inv1 = await hooks.tool.listen_analyze.execute({ url: "" }, ctx);
  assert(/provide|url/i.test(String(inv1.output || inv1)), "empty URL not rejected");

  // Flag-like URL
  const inv2 = await hooks.tool.listen_analyze.execute({ url: "-r http://evil.com" }, ctx);
  assert(/not a flag/i.test(String(inv2.output || inv2)), "flag-like URL not rejected");

  // Control characters
  const inv3 = await hooks.tool.listen_analyze.execute({ url: "http://evil.com/\x00steal" }, ctx);
  assert(/control characters/i.test(String(inv3.output || inv3)), "control chars not rejected");

  // URL too long
  const inv4 = await hooks.tool.listen_analyze.execute({ url: "http://example.com/" + "a".repeat(2500) }, ctx);
  assert(/too long/i.test(String(inv4.output || inv4)), "long URL not rejected");

  // Invalid URL format
  const inv5 = await hooks.tool.listen_analyze.execute({ url: "not-a-url" }, ctx);
  assert(/Invalid URL|invalid|SSRF/i.test(String(inv5.output || inv5)), "invalid URL not rejected");

  console.log("    Input: PASS (5 tests)");

  // =========================================================================
  // PART 3: HTML analysis function tests (pure, no network)
  // =========================================================================
  console.log("  HTML analysis function tests...");

  // data: URLs must be rejected before any fetch is attempted.
  const nonHtml = await hooks.tool.listen_analyze.execute(
    { url: "data:text/plain,hello" },
    ctx,
  );
  assert(/blocked|invalid|only http/i.test(String(nonHtml.output || nonHtml)), "data: URL not rejected");

  // buildAnalysis is exported so the parser can be tested directly, without a
  // live server (the SSRF guard blocks loopback on purpose).
  const analysis = buildAnalysis("https://example.com/pricing", SAMPLE_HTML, {
    "content-type": "text/html; charset=utf-8",
  });

  assert(analysis.includes("# Website Analysis: https://example.com/pricing"), "analysis header missing");
  assert(analysis.includes("**Title:** Test Page - OpenMind Listen"), "title meta not extracted");
  assert(/A test page for OpenMind listen analysis/.test(analysis), "description meta not extracted");
  assert(analysis.includes("Test Author"), "author meta not extracted");

  // Open Graph entries must be surfaced separately from the plain meta tags.
  assert(/## Open Graph Data/.test(analysis), "Open Graph section missing");
  assert(analysis.includes("Test OG Title"), "og:title not extracted");

  assert(analysis.includes("- Welcome to Test Page"), "headings not extracted");
  assert(analysis.includes("https://example.com/link1"), "links not extracted");
  assert(analysis.includes("https://example.com/photo.jpg"), "images not extracted");
  assert(/const x = 42/.test(analysis), "code block not extracted");
  assert(analysis.includes("| Name | Value |"), "table not extracted");
  assert(/Item A/.test(analysis), "list items not extracted");
  assert(/Welcome to Test Page/.test(analysis), "visible body text not extracted");
  assert(!/This is a paragraph with\s*<\/p>/.test(analysis), "stray markup in text section");

  // javascript: hrefs must never be emitted as actionable links.
  assert(!analysis.includes("](javascript:"), "javascript: link was not stripped");

  // A page with no recognizable framework markers should not invent any.
  const bare = buildAnalysis("https://example.com/", "<html><body><p>hi</p></body></html>", {
    "content-type": "text/html",
  });
  assert(!/## Detected Technology Stack/.test(bare), "tech stack invented for a bare page");
  assert(bare.includes("hi"), "bare page text not extracted");

  // Meta-less, tag-less input must not throw.
  const junk = buildAnalysis("https://example.com/", "", { "content-type": "text/html" });
  assert(typeof junk === "string" && junk.length > 0, "empty HTML produced no analysis");

  console.log("    HTML analysis: PASS");

  // =========================================================================
  // PART 4: Tool metadata and options tests
  // =========================================================================
  console.log("  Tool metadata tests...");

  // Verify the tool exists and has correct schema
  assert(typeof hooks.tool.listen_analyze === "object", "listen_analyze tool not found");
  assert(typeof hooks.tool.listen_analyze.execute === "function", "listen_analyze.execute not a function");

  console.log("    Metadata: PASS");

  // =========================================================================
  // PART 5: Edge cases
  // =========================================================================
  console.log("  Edge case tests...");

  // Double-slash protocol (should be caught as invalid or blocked)
  const edge1 = await hooks.tool.listen_analyze.execute({ url: "http://" }, ctx);
  assert(String(edge1.output || edge1).length > 0, "empty hostname not handled");

  // Port scan attempt
  const edge2 = await hooks.tool.listen_analyze.execute({ url: "http://127.0.0.1:9999/scan" }, ctx);
  assert(/blocked|private|loopback/i.test(String(edge2.output || edge2)), "port scan on loopback not blocked");

  console.log("    Edge cases: PASS");

  console.log("listen: all tests passed");
} finally {
  await rm(directory, { recursive: true, force: true });
}
