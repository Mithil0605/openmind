#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { delimiter, dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const isWindows = process.platform === "win32";
const extraBin = join(homedir(), ".opencode", "bin");
process.env.PATH = extraBin + delimiter + (process.env.PATH || "");

// `--commands project` installs into <cwd>/.opencode/commands instead of the
// global config dir; `none` skips them.
const commandMode = (() => {
  const flag = process.argv.find((arg) => arg.startsWith("--commands"));
  if (flag && flag.includes("=")) return flag.split("=")[1].trim();
  const index = process.argv.indexOf("--commands");
  if (index !== -1 && process.argv[index + 1]) return process.argv[index + 1].trim();
  return "global";
})();

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

console.log("OpenMind v5 setup");
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
  fail("package.json was not found. Run setup from the extracted openmind-v5 folder.");
}

console.log("Installing plugin dependencies...");
const install = run("npm", ["install", "--omit=dev"]);
if (install.status !== 0) fail("npm install failed. Check the messages above, then run setup again.");

console.log("Registering plugin with OpenCode...");
const register = run("opencode", ["plugin", root, "--global", "--force"]);
if (register.status !== 0) fail("OpenCode plugin registration failed. Check the messages above, then run setup again.");

// Slash commands (/listen, /imgread, /remember, /recall, /forget, /stats) ship with
// the package. Without this step the README advertised commands that no install
// ever delivered.
// OpenCode scans both `command/` and `commands/` under a config directory.
function configDir() {
  if (process.env.OPENCODE_CONFIG_DIR) return resolve(process.env.OPENCODE_CONFIG_DIR);
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, "opencode");
}

if (commandMode !== "none") {
  const source = join(root, "commands");
  if (!existsSync(source)) {
    console.log("SKIP slash commands: the package has no commands/ directory.");
  } else {
    const target =
      commandMode === "project"
        ? join(process.cwd(), ".opencode", "commands")
        : join(configDir(), "commands");
    try {
      mkdirSync(target, { recursive: true });
      let copied = 0;
      for (const entry of readdirSync(source)) {
        if (!entry.endsWith(".md")) continue;
        copyFileSync(join(source, entry), join(target, entry));
        copied += 1;
      }
      console.log(`OK ${copied} slash command(s) installed to ${target}`);
    } catch (err) {
      console.log("WARN slash commands could not be installed: " + String(err.message || err));
      console.log("     Copy the files in " + source + " into .opencode/commands/ by hand.");
    }
  }
}

console.log("\nSetup complete.");
console.log("Restart OpenCode, then try:");
console.log("  Remember for this project that I prefer short answers.");
console.log("  What do you remember about this project?");
console.log("  /listen https://example.com");
console.log("  /imgread screenshot.png");
console.log("  /remember I prefer short answers");
console.log("  /recall authentication");
console.log("  /stats");
console.log("  /forget <id>");
console.log("\nOpenMind v5 does not save session data. Durable memory is opt-in, project-scoped, and can be deleted at any time.");
console.log("Memory file location can be changed later with OPENCODE_MEMORY_DIR.");
