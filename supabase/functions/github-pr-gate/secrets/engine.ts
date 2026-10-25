import type { Finding } from "../types.ts";
import { isAllowlistedPath, isPlaceholderValue } from "./allowlist.ts";
import { GITLEAKS_RULES } from "./gitleaks-rules.ts";

type CompiledRule = {
  id: string;
  pattern: RegExp;
  keywords: string[];
  entropy?: number;
};

const compiledRules: CompiledRule[] = [];
for (const rule of GITLEAKS_RULES) {
  try {
    compiledRules.push({
      id: rule.id,
      pattern: new RegExp(rule.regex, rule.flags),
      keywords: rule.keywords.map((keyword) => keyword.toLowerCase()),
      entropy: rule.entropy,
    });
  } catch {
    // Skip Go-only patterns that cannot compile in JS.
  }
}

const ASSIGNMENT =
  /\b([A-Za-z_][A-Za-z0-9_]*?(?:api[_-]?key|secret|token|password|passwd|credential)s?)\s*[:=]\s*([^\s,;]+)/gi;

const ASSIGNMENT_SUFFIX =
  /\b([A-Z][A-Z0-9_]{2,}(?:_KEY|_SECRET|_TOKEN|_PASSWORD|_PASSWD|_CREDENTIALS?))\s*[:=]\s*([^\s,;]+)/g;

const EXACT_ENV =
  /\b(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|CREDENTIALS?)\s*[:=]\s*([^\s,;]+)/gi;

const PEM_BLOCK =
  /-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/g;

const ENTROPY_HINT =
  /\b(?:api[_-]?key|secret|token|password|passwd|credential|auth)\b/i;
const ENTROPY_TOKEN = /['"]?([A-Za-z0-9/+=._-]{20,})['"]?/g;
const ENTROPY_THRESHOLD = 3.5;

export function scanTextForSecrets(path: string, text: string): Finding[] {
  if (isAllowlistedPath(path)) return [];
  const findings: Finding[] = [];
  findings.push(...scanPem(path, text));
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;
    findings.push(...scanAssignments(path, lineNo, line));
    findings.push(...scanGitleaksLine(path, lineNo, line));
    findings.push(...scanEntropy(path, lineNo, line));
  }
  return dedupe(findings);
}

function scanPem(path: string, text: string): Finding[] {
  PEM_BLOCK.lastIndex = 0;
  if (!PEM_BLOCK.test(text)) return [];
  const line = text.split(/\r?\n/).findIndex((row) =>
    row.includes("BEGIN") && row.includes("PRIVATE KEY")
  );
  return [{
    rule: "private-key-pem",
    path,
    line: line >= 0 ? line + 1 : 1,
    message: `Possible private key block detected in ${path}.`,
  }];
}

function scanAssignments(path: string, line: number, text: string): Finding[] {
  const findings: Finding[] = [];
  for (const pattern of [ASSIGNMENT, ASSIGNMENT_SUFFIX, EXACT_ENV]) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const value = stripQuotes(match[2] ?? "");
      if (value.length < 12) continue;
      if (isPlaceholderValue(value)) continue;
      findings.push({
        rule: "generic-assignment-secret",
        path,
        line,
        message: `Possible assigned secret detected in ${path}:${line}.`,
      });
    }
  }
  return findings;
}

function scanGitleaksLine(path: string, line: number, text: string): Finding[] {
  const lower = text.toLowerCase();
  const findings: Finding[] = [];
  for (const rule of compiledRules) {
    if (
      rule.keywords.length > 0 &&
      !rule.keywords.some((keyword) => lower.includes(keyword))
    ) {
      continue;
    }
    rule.pattern.lastIndex = 0;
    const match = rule.pattern.exec(text);
    if (!match) continue;
    const captured = match[1] ?? match[0];
    if (rule.entropy != null && shannonEntropy(captured) < rule.entropy) {
      continue;
    }
    if (isPlaceholderValue(captured)) continue;
    findings.push({
      rule: rule.id,
      path,
      line,
      message: `Possible secret detected in ${path}:${line}.`,
    });
  }
  return findings;
}

function scanEntropy(path: string, line: number, text: string): Finding[] {
  if (!ENTROPY_HINT.test(text)) return [];
  const findings: Finding[] = [];
  ENTROPY_TOKEN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = ENTROPY_TOKEN.exec(text)) !== null) {
    const token = match[1];
    if (isPlaceholderValue(token)) continue;
    if (shannonEntropy(token) < ENTROPY_THRESHOLD) continue;
    findings.push({
      rule: "high-entropy-secret",
      path,
      line,
      message: `High-entropy credential-like token detected in ${path}:${line}.`,
    });
    break;
  }
  return findings;
}

function stripQuotes(value: string): string {
  return value.replace(/^['"`]+/, "").replace(/['"`;]+$/, "");
}

function shannonEntropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    const key = `${finding.rule}|${finding.path ?? ""}|${finding.line ?? 0}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}

export function compiledRuleCount(): number {
  return compiledRules.length;
}
