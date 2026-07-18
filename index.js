import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { homedir, platform } from "node:os";
import { randomUUID } from "node:crypto";
import { tool } from "@opencode-ai/plugin";

const STORE_FILE = "memories.jsonl";
const MAX_TEXT_LENGTH = 8000;

function defaultDirectory() {
  if (process.env.OPENCODE_MEMORY_DIR) return process.env.OPENCODE_MEMORY_DIR;
  if (platform() === "win32") {
    const base = process.env.APPDATA || join(homedir(), "AppData", "Roaming");
    return join(base, "opencode-memory");
  }
  const base = process.env.XDG_DATA_HOME || join(homedir(), ".local", "share");
  return join(base, "opencode-memory");
}

function now() {
  return new Date().toISOString();
}

function asArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String).map((item) => item.trim()).filter(Boolean);
  return String(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function normalizeScope(scope) {
  if (scope === "global") return scope;
  return "project";
}

function storagePath(options) {
  const dir = typeof options?.directory === "string" && options.directory.trim()
    ? options.directory.trim().replace(/^~(?=$|[/\\])/, homedir())
    : defaultDirectory();
  return join(resolve(dir), STORE_FILE);
}

function projectKey(context) {
  return context.worktree || context.directory || process.cwd();
}

function compactProject(path) {
  if (!path) return null;
  const home = homedir();
  return path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

async function readMemories(file) {
  if (!existsSync(file)) return [];
  const raw = await readFile(file, "utf8");
  return raw
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter((item) => item && item.deleted !== true && item.scope !== "session");
}

async function appendMemory(file, memory) {
  await mkdir(dirname(file), { recursive: true });
  const line = `${JSON.stringify(memory)}\n`;
  await writeFile(file, line, { flag: "a", mode: 0o600 });
}

async function replaceMemories(file, memories) {
  if (memories.length === 0) {
    await rm(file, { force: true });
    return;
  }
  await mkdir(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  const body = memories.map((memory) => JSON.stringify(memory)).join("\n");
  await writeFile(tmp, body ? `${body}\n` : "", { mode: 0o600 });
  await rename(tmp, file);
}

function visibleTo(memory, context) {
  if (memory.scope === "global") return true;
  return memory.project === projectKey(context);
}

async function removeLegacySessionData(file) {
  if (!existsSync(file)) return;
  const raw = await readFile(file, "utf8");
  const entries = raw
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    })
    .filter((item) => item && item.deleted !== true && item.scope !== "session");
  await replaceMemories(file, entries);
}

function scoreMemory(memory, query, tags) {
  let score = memory.pinned ? 25 : 0;
  const haystack = [
    memory.text,
    memory.source,
    ...(memory.tags || []),
    memory.project,
  ].join(" ").toLowerCase();

  for (const tag of tags) {
    if ((memory.tags || []).map((item) => item.toLowerCase()).includes(tag.toLowerCase())) score += 10;
  }

  for (const token of query.toLowerCase().split(/\s+/).filter(Boolean)) {
    if (token.length < 2) continue;
    if (haystack.includes(token)) score += token.length;
  }

  return score;
}

function filterMemories(memories, context, args = {}) {
  const tags = asArray(args.tags);
  const query = String(args.query || "").trim();
  const limit = Math.max(1, Math.min(Number(args.limit || 10), 50));
  const candidates = memories.filter((memory) => visibleTo(memory, context));

  return candidates
    .map((memory) => ({ memory, score: scoreMemory(memory, query, tags) }))
    .filter((entry) => !query && tags.length === 0 ? true : entry.score > 0)
    .sort((a, b) => b.score - a.score || b.memory.updatedAt.localeCompare(a.memory.updatedAt))
    .slice(0, limit)
    .map((entry) => entry.memory);
}

function formatMemory(memory) {
  const tags = memory.tags?.length ? ` [${memory.tags.join(", ")}]` : "";
  const pin = memory.pinned ? " pinned" : "";
  const project = memory.scope === "project" ? ` project=${compactProject(memory.project)}` : "";
  return `- ${memory.id}${tags}${pin} (${memory.scope}${project}, ${memory.updatedAt})\n  ${memory.text}`;
}

function memoryBlock(memories) {
  if (memories.length === 0) return "";
  return [
    "OpenMind saved preferences:",
    ...memories.map((memory) => {
      const tags = memory.tags?.length ? ` [${memory.tags.join(", ")}]` : "";
      return `- ${memory.text}${tags}`;
    }),
  ].join("\n");
}

export const MemoryPlugin = async (_input, options = {}) => {
  const file = storagePath(options);
  // One-time v2 migration: erase formerly persisted session-only entries.
  await removeLegacySessionData(file);
  const autoInject = options.autoInject !== false;
  const injectLimit = Math.max(1, Math.min(Number(options.injectLimit || 8), 25));

  return {
    tool: {
      memory_remember: tool({
        description: "Explicitly save a durable OpenMind preference or project fact. Never use this for conversational/session details; sessions are not saved by OpenMind v2.",
        args: {
          text: tool.schema.string().min(1).max(MAX_TEXT_LENGTH).describe("The fact, preference, decision, or instruction to remember."),
          tags: tool.schema.array(tool.schema.string()).optional().describe("Optional tags for later recall."),
          scope: tool.schema.enum(["project", "global"]).optional().describe("project is default; global applies everywhere. Session saving is intentionally unavailable."),
          source: tool.schema.string().optional().describe("Optional source or reason for this memory."),
          pinned: tool.schema.boolean().optional().describe("Pinned memories are shown first during recall and auto injection."),
        },
        async execute(args, context) {
          const timestamp = now();
          const scope = normalizeScope(args.scope);
          const memory = {
            id: randomUUID(),
            text: args.text.trim(),
            tags: asArray(args.tags),
            scope,
            source: args.source?.trim() || null,
            pinned: Boolean(args.pinned),
            project: scope === "project" ? projectKey(context) : null,
            createdAt: timestamp,
            updatedAt: timestamp,
          };

          await appendMemory(file, memory);
          return {
            title: "Memory saved",
            output: formatMemory(memory),
            metadata: { id: memory.id, file },
          };
        },
      }),

      memory_recall: tool({
        description: "Search saved OpenMind preferences visible to this project.",
        args: {
          query: tool.schema.string().optional().describe("Search text."),
          tags: tool.schema.array(tool.schema.string()).optional().describe("Only prefer memories matching these tags."),
          limit: tool.schema.number().int().min(1).max(50).optional().describe("Maximum memories to return."),
        },
        async execute(args, context) {
          const memories = filterMemories(await readMemories(file), context, args);
          return memories.length
            ? memories.map(formatMemory).join("\n")
            : "No matching memories found.";
        },
      }),

      memory_list: tool({
        description: "List recent saved OpenMind preferences visible to this project.",
        args: {
          limit: tool.schema.number().int().min(1).max(50).optional().describe("Maximum memories to return."),
        },
        async execute(args, context) {
          const limit = Math.max(1, Math.min(Number(args.limit || 20), 50));
          const memories = (await readMemories(file))
            .filter((memory) => visibleTo(memory, context))
            .sort((a, b) => Number(b.pinned) - Number(a.pinned) || b.updatedAt.localeCompare(a.updatedAt))
            .slice(0, limit);
          return memories.length
            ? memories.map(formatMemory).join("\n")
            : "No memories saved yet.";
        },
      }),

      memory_forget: tool({
        description: "Permanently delete one saved memory by id. If it is the last item, its backing store is removed too.",
        args: {
          id: tool.schema.string().min(1).describe("The memory id to delete."),
        },
        async execute(args, context) {
          const memories = await readMemories(file);
          const index = memories.findIndex((memory) => memory.id === args.id && visibleTo(memory, context));
          if (index === -1) return `No visible memory found with id ${args.id}.`;
          const [removed] = memories.splice(index, 1);
          await replaceMemories(file, memories);
          return {
            title: "Memory deleted",
            output: formatMemory(removed),
            metadata: { id: args.id, file },
          };
        },
      }),

      memory_prune: tool({
        description: "Permanently delete saved memories the user no longer wants or needs. Match by IDs, exact text search, or tags. A deletion preview is returned unless confirm is true.",
        args: {
          ids: tool.schema.array(tool.schema.string()).optional().describe("Memory IDs to delete."),
          query: tool.schema.string().optional().describe("Case-insensitive text to match."),
          tags: tool.schema.array(tool.schema.string()).optional().describe("Delete memories having any of these tags."),
          confirm: tool.schema.boolean().optional().describe("Set true only after the user has approved the matching deletion."),
        },
        async execute(args, context) {
          const ids = new Set(asArray(args.ids));
          const query = String(args.query || "").trim().toLowerCase();
          const tags = asArray(args.tags).map((tag) => tag.toLowerCase());
          if (ids.size === 0 && !query && tags.length === 0) return "Choose at least one id, query, or tag before deleting memories.";
          const memories = await readMemories(file);
          const matches = memories.filter((memory) => {
            if (!visibleTo(memory, context)) return false;
            if (ids.has(memory.id)) return true;
            if (query && [memory.text, memory.source, ...(memory.tags || [])].filter(Boolean).join(" ").toLowerCase().includes(query)) return true;
            return tags.some((tag) => (memory.tags || []).some((memoryTag) => memoryTag.toLowerCase() === tag));
          });
          if (matches.length === 0) return "No visible memories match that deletion request.";
          if (args.confirm !== true) return { title: "Deletion preview", output: `Set confirm: true to permanently delete ${matches.length} memory item(s).\n${matches.map(formatMemory).join("\n")}`, metadata: { count: matches.length } };
          const matchedIDs = new Set(matches.map((memory) => memory.id));
          await replaceMemories(file, memories.filter((memory) => !matchedIDs.has(memory.id)));
          return { title: "Memories deleted", output: `Permanently deleted ${matches.length} memory item(s).`, metadata: { count: matches.length, file } };
        },
      }),

      memory_delete_store: tool({
        description: "Permanently delete every OpenMind saved memory and remove the on-disk storage file. Requires explicit confirmation.",
        args: {
          confirm: tool.schema.boolean().optional().describe("Set true only when the user explicitly requests deletion of all OpenMind memory."),
        },
        async execute(args) {
          if (args.confirm !== true) return "This permanently removes all OpenMind memory and its storage file. Set confirm: true only after the user explicitly approves it.";
          const count = (await readMemories(file)).length;
          await rm(file, { force: true });
          return { title: "OpenMind storage deleted", output: `Deleted ${count} saved memory item(s) and removed the OpenMind storage file.`, metadata: { count, file } };
        },
      }),

      memory_export: tool({
        description: "Show the memory store location and export visible memories as JSON.",
        args: {
          scope: tool.schema.enum(["visible", "all"]).optional().describe("visible is default; all includes memories from other projects."),
        },
        async execute(args, context) {
          const memories = await readMemories(file);
          const exported = args.scope === "all" ? memories : memories.filter((memory) => visibleTo(memory, context));
          return {
            title: "Memory export",
            output: JSON.stringify({ file, count: exported.length, memories: exported }, null, 2),
            metadata: { file, count: exported.length },
          };
        },
      }),
    },

    async "experimental.chat.system.transform"(input, output) {
      if (!autoInject) return;
      const context = {
        sessionID: input.sessionID,
        directory: _input.directory,
        worktree: _input.worktree,
      };
      const memories = (await readMemories(file))
        .filter((memory) => visibleTo(memory, context))
        .sort((a, b) => Number(b.pinned) - Number(a.pinned) || b.updatedAt.localeCompare(a.updatedAt))
        .slice(0, injectLimit);
      const block = memoryBlock(memories);
      if (block) output.system.push(block);
    },

    async "shell.env"(input, output) {
      output.env.OPENCODE_MEMORY_FILE = file;
      if (input.cwd) {
        output.env.OPENCODE_MEMORY_PROJECT = relative(input.cwd, projectKey({ directory: input.cwd, worktree: input.cwd })) || ".";
      }
    },
  };
};

export default MemoryPlugin;
