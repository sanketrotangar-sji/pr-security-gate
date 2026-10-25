export const CHECK_NAME = "SJ Standards Gate";

export const HANDLED_PR_ACTIONS = [
  "opened",
  "synchronize",
  "reopened",
  "ready_for_review",
  "edited",
] as const;

export const PROTECTED_BASE_BRANCH = "main";

export const REQUIRED_FILES = [
  "README.md",
  "CLAUDE.md",
  "ARCHITECTURE.md",
  ".cursor/rules/sji-coding-standards.mdc",
];

export const STANDARDS_FILE_PATH = ".cursor/rules/sji-coding-standards.mdc";

// SHA-256 of the approved standards stub. Update this pin when the stub is
// intentionally changed in the deployed gate, not by a PR under review.
export const STANDARDS_FILE_SHA256 =
  "d090d1185001fa938c1c1e111c247c62a1a74bd4f35fc73ef91f3a2d1511f522";

export const BRANCH_PATTERN = /^(feat|fix|chore)\/[A-Za-z0-9._-]+$/;

export const SKIP_PATH_PREFIXES = [
  "node_modules/",
  "dist/",
  ".git/",
  "supabase/functions/github-pr-gate/secrets/",
];

export const SKIP_FILE_NAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "gitleaks-rules.ts",
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
export const SCAN_TIMEOUT_MS = 25_000;
export const DEFAULT_ALLOWED_REPOS = ["sanketrotangar-sji/pr-security-gate"];
