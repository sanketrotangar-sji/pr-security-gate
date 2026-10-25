const PLACEHOLDER_VALUES = new Set([
  "changeme",
  "change-me",
  "your-key-here",
  "your_key_here",
  "placeholder",
  "example",
  "examplekey",
  "dummy",
  "dummykey",
  "todo",
  "tbd",
  "xxx",
  "xxxx",
  "password",
  "secret",
  "test",
  "testing",
  "sample",
  "none",
  "null",
  "undefined",
]);

const SKIP_PATH_PATTERNS = [
  /^node_modules\//,
  /^dist\//,
  /^\.git\//,
  /^bower_components\//,
  /^vendor\//,
  /^supabase\/functions\/github-pr-gate\/secrets\//,
  /\.example$/i,
  /\.example\./i,
];

const SKIP_FILE_NAMES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "deno.lock",
  "poetry.lock",
  "gitleaks.toml",
  "gitleaks-rules.ts",
]);

export function isAllowlistedPath(path: string): boolean {
  const base = path.split("/").pop() ?? path;
  if (SKIP_FILE_NAMES.has(base)) return true;
  return SKIP_PATH_PATTERNS.some((pattern) => pattern.test(path));
}

export function isPlaceholderValue(value: string): boolean {
  const trimmed = value.trim().replace(/^['"]|['"]$/g, "").toLowerCase();
  if (!trimmed) return true;
  if (PLACEHOLDER_VALUES.has(trimmed)) return true;
  if (/^(x+|your[-_ ].+)$/i.test(trimmed)) return true;
  return false;
}
