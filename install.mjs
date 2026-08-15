#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const isWindows = process.platform === "win32";
const extraBin = join(homedir(), ".opencode", "bin");
process.env.PATH = extraBin + delimiter + (process.env.PATH || "");

function command(name) {
  return isWindows ? name + ".cmd" : name;
}

function run(name, args, options = {}) {
  return spawnSync(command(name), args, {
    cwd: options.cwd || root,
    stdio: options.quiet ? "pipe" : "inherit",
    shell: false,
    encoding: "utf8",
  });
}

function fail(message) {
  console.error("\nSetup stopped: " + message);
  process.exit(1);
}

function versionNumber(text) {
  const match = String(text).match(/(\d+)\.(\d+)\.(\d+)/);
  return match ? match.slice(1).map(Number) : null;
}

console.log("OpenMind v2 setup");
console.log("=================");

const nodeVersion = versionNumber(process.version);
if (!nodeVersion || nodeVersion[0] < 22) {
  fail("Node.js 22 or newer is required. Current version: " + process.version + ". Install Node.js from https://nodejs.org/ and run this setup again.");
}
console.log("OK Node.js " + process.version);

const opencodeCheck = run("opencode", ["--version"], { quiet: true });
if (opencodeCheck.status !== 0) {
  fail("OpenCode was not found. Install OpenCode first, then run this setup again.");
}
console.log("OK OpenCode " + String(opencodeCheck.stdout || opencodeCheck.stderr).trim());

if (!existsSync(resolve(root, "package.json"))) {
  fail("package.json was not found. Run setup from the extracted openmind-v2 folder.");
}

console.log("Installing plugin dependencies...");
const install = run("npm", ["install", "--omit=dev"]);
if (install.status !== 0) fail("npm install failed. Check the messages above, then run setup again.");

console.log("Registering plugin with OpenCode...");
const register = run("opencode", ["plugin", root, "--global", "--force"]);
if (register.status !== 0) fail("OpenCode plugin registration failed. Check the messages above, then run setup again.");

console.log("\nSetup complete.");
console.log("Restart OpenCode, then try:");
console.log("  Remember for this project that I prefer short answers.");
console.log("  What do you remember about this project?");
console.log("\nOpenMind v2 does not save session data. Durable memory is opt-in, project-scoped, and can be deleted at any time.");
console.log("Memory file location can be changed later with OPENCODE_MEMORY_DIR.");
