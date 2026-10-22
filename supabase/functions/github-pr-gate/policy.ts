import {
  BRANCH_PATTERN,
  MAX_FILE_BYTES,
  REQUIRED_FILES,
  SKIP_EXTENSIONS,
  SKIP_FILE_NAMES,
  SKIP_PATH_PREFIXES,
} from "./config.ts";
import type { GitHubClient } from "./github.ts";

export type Finding = {
  rule: string;
  message: string;
  path?: string;
  line?: number;
};

export type PolicyResult = {
  findings: Finding[];
};

type PullFile = {
  filename: string;
  status: string;
  size?: number;
};

type GitTree = {
  truncated?: boolean;
  tree: Array<{ path?: string; type?: string }>;
};

type FileContent = {
  type?: string;
  encoding?: string;
  content?: string;
  size?: number;
};

const SECRET_RULES: Array<{ rule: string; pattern: RegExp }> = [
  { rule: "github-pat", pattern: /\bghp_[A-Za-z0-9]{36}\b/ },
  { rule: "stripe-live-key", pattern: /\bsk_live_[A-Za-z0-9]{16,}\b/ },
  { rule: "aws-access-key", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  {
    rule: "slack-token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  },
  {
    rule: "generic-api-key",
    pattern:
      /\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*['"][A-Za-z0-9/_+=.-]{16,}['"]/i,
  },
];

const EMPTY_TICKET = new Set(["tbd", "todo", "n/a", "-", "none", "xxx"]);

export async function runPolicy(
  github: GitHubClient,
  input: {
    owner: string;
    repo: string;
    prNumber: number;
    headSha: string;
    branch: string;
    body: string | null;
  },
): Promise<PolicyResult> {
  const findings: Finding[] = [];
  findings.push(...checkBranchName(input.branch));
  findings.push(...checkPullRequestBody(input.body ?? ""));
  findings.push(
    ...(await checkRequiredFiles(
      github,
      input.owner,
      input.repo,
      input.headSha,
    )),
  );
  findings.push(
    ...(await scanPullRequestFiles(
      github,
      input.owner,
      input.repo,
      input.prNumber,
      input.headSha,
    )),
  );
  return { findings };
}

export function checkBranchName(branch: string): Finding[] {
  if (BRANCH_PATTERN.test(branch)) return [];
  return [{
    rule: "branch-name",
    message:
      `Branch "${branch}" must match feat|fix|chore followed by a slash, e.g. feat/AC-123-add-health.`,
  }];
}

export function checkPullRequestBody(body: string): Finding[] {
  const findings: Finding[] = [];
  const ticket = body.match(/^\s*Ticket:\s*(.+?)\s*$/im);
  const ticketValue = ticket?.[1]?.trim() ?? "";
  if (!ticketValue || EMPTY_TICKET.has(ticketValue.toLowerCase())) {
    findings.push({
      rule: "pr-ticket",
      message: "PR body must include a filled Ticket: field.",
    });
  }

  const checkboxes = [...body.matchAll(/^\s*[-*]\s*\[([ xX])\]\s+\S+/gm)];
  if (checkboxes.length === 0) {
    findings.push({
      rule: "pr-checklist",
      message: "PR body must include a markdown checklist.",
    });
    return findings;
  }
  const unchecked = checkboxes.filter((match) => match[1] === " ").length;
  if (unchecked > 0) {
    findings.push({
      rule: "pr-checklist",
      message: `PR checklist has ${unchecked} unchecked item(s).`,
    });
  }
  return findings;
}

export function scanTextForSecrets(path: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { rule, pattern } of SECRET_RULES) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        findings.push({
          rule,
          path,
          line: i + 1,
          message: `Possible secret detected in ${path}:${i + 1}.`,
        });
      }
    }
  }
  return findings;
}

async function checkRequiredFiles(
  github: GitHubClient,
  owner: string,
  repo: string,
  headSha: string,
): Promise<Finding[]> {
  const tree = await github.request<GitTree>(
    `/repos/${owner}/${repo}/git/trees/${headSha}?recursive=1`,
  );
  const paths = new Set(
    (tree.tree ?? []).filter((item) => item.type === "blob" && item.path)
      .map((item) => item.path as string),
  );

  const missing: string[] = [];
  for (const required of REQUIRED_FILES) {
    if (paths.has(required)) continue;
    if (tree.truncated) {
      const exists = await fileExists(github, owner, repo, required, headSha);
      if (!exists) missing.push(required);
      continue;
    }
    missing.push(required);
  }

  return missing.map((path) => ({
    rule: "required-file",
    path,
    message: `Required file missing: ${path}`,
  }));
}

async function scanPullRequestFiles(
  github: GitHubClient,
  owner: string,
  repo: string,
  prNumber: number,
  headSha: string,
): Promise<Finding[]> {
  const files = await listPullFiles(github, owner, repo, prNumber);
  const findings: Finding[] = [];
  for (const file of files) {
    if (file.status === "removed" || file.status === "unchanged") continue;
    if (shouldSkipPath(file.filename)) continue;
    const content = await readFileText(
      github,
      owner,
      repo,
      file.filename,
      headSha,
    );
    if (content == null) continue;
    findings.push(...scanTextForSecrets(file.filename, content));
  }
  return findings;
}

async function listPullFiles(
  github: GitHubClient,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<PullFile[]> {
  const files: PullFile[] = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await github.request<PullFile[]>(
      `/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100&page=${page}`,
    );
    files.push(...batch);
    if (batch.length < 100) break;
  }
  return files;
}

async function readFileText(
  github: GitHubClient,
  owner: string,
  repo: string,
  path: string,
  ref: string,
): Promise<string | null> {
  try {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    const data = await github.request<FileContent>(
      `/repos/${owner}/${repo}/contents/${encoded}?ref=${encodeURIComponent(ref)}`,
    );
    if (data.type !== "file" || data.encoding !== "base64" || !data.content) {
      return null;
    }
    if ((data.size ?? 0) > MAX_FILE_BYTES) return null;
    return decodeBase64(data.content);
  } catch {
    return null;
  }
}

async function fileExists(
  github: GitHubClient,
  owner: string,
  repo: string,
  path: string,
  ref: string,
): Promise<boolean> {
  try {
    const encoded = path.split("/").map(encodeURIComponent).join("/");
    await github.request(
      `/repos/${owner}/${repo}/contents/${encoded}?ref=${encodeURIComponent(ref)}`,
    );
    return true;
  } catch {
    return false;
  }
}

function shouldSkipPath(path: string): boolean {
  const base = path.split("/").pop() ?? path;
  if (SKIP_FILE_NAMES.has(base)) return true;
  if (SKIP_PATH_PREFIXES.some((prefix) => path.startsWith(prefix))) return true;
  const dot = base.lastIndexOf(".");
  if (dot >= 0 && SKIP_EXTENSIONS.has(base.slice(dot).toLowerCase())) {
    return true;
  }
  return false;
}

function decodeBase64(content: string): string {
  const cleaned = content.replace(/\s/g, "");
  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

export function formatFindings(findings: Finding[]): string {
  if (findings.length === 0) {
    return "Branch name, PR template, required files, and regex secret scan passed.";
  }
  return findings.map((finding) => {
    const loc = finding.path
      ? ` (${finding.path}${finding.line ? `:${finding.line}` : ""})`
      : "";
    return `- **${finding.rule}**${loc}: ${finding.message}`;
  }).join("\n");
}
