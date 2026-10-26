import js from "@eslint/js";
import globals from "globals";

export default [
  {
    // `.tests-local` holds the local verification suites, which are deliberately
    // not part of the published repository.
    ignores: ["node_modules/**", "*.tgz", ".tests-local/**"],
  },
  js.configs.recommended,
  {
    files: ["index.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: globals.node,
    },
    rules: {
      // A duplicated helper declaration silently shadowed a whole block of
      // tools in v5. Catch redeclaration and undefined references at lint time
      // instead of at runtime.
      "no-redeclare": "error",
      "no-undef": "error",
      // Bare `catch {}` is the deliberate idiom here: a malformed lockout file,
      // an unreadable lockfile, and a non-symlink probe must all fall through.
      "no-empty": ["error", { allowEmptyCatch: true }],
      // The URL/target validators intentionally match C0 controls + DEL to
      // reject them, which is exactly what no-control-regex flags.
      "no-control-regex": "off",
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
      "no-dupe-keys": "error",
      "no-dupe-else-if": "error",
      "no-duplicate-imports": "error",
      "no-self-compare": "error",
      "no-const-assign": "error",
      "no-fallthrough": "error",
      "no-unreachable": "error",
      eqeqeq: ["error", "smart"],
      "no-var": "error",
      "prefer-const": "off",
    },
  },
  {
    files: ["install.mjs"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: globals.node,
    },
    rules: {
      "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
    },
  },
];
