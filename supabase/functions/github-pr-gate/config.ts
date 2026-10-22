export const CHECK_NAME = "SJ Standards Gate";

export const HANDLED_PR_ACTIONS = [
  "opened",
  "synchronize",
  "reopened",
  "ready_for_review",
] as const;

export const REQUIRED_FILES = [
  "README.md",
  "CLAUDE.md",
  "ARCHITECTURE.md",
  ".cursor/rules/sji-coding-standards.mdc",
];

export const BRANCH_PATTERN = /^(feat|fix|chore)\/[A-Za-z0-9._-]+$/;

export const SKIP_PATH_PREFIXES = ["node_modules/", "dist/", ".git/"];

export const SKIP_FILE_NAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
]);

export const SKIP_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".pdf",
  ".woff",
  ".woff2",
  ".zip",
  ".gz",
  ".tgz",
  ".wasm",
]);

export const MAX_FILE_BYTES = 512_000;
