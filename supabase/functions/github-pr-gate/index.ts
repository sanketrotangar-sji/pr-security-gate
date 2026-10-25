import {
  completeCheck,
  createInProgressCheck,
  publishFailureCheck,
} from "./checks.ts";
import { HANDLED_PR_ACTIONS, SCAN_TIMEOUT_MS } from "./config.ts";
import {
  allowedRepos,
  claimDelivery,
  isAllowedInstallation,
  isAllowedRepo,
} from "./dedup.ts";
import {
  getInstallationToken,
  GitHubClient,
  requireEnv,
} from "./github.ts";
import { formatFindings, runPolicy } from "./policy.ts";
import {
  normalizeWebhookSecret,
  verifyGithubSignature,
} from "./verify.ts";

type PullRequestPayload = {
  action?: string;
  installation?: { id?: number };
  repository?: {
    name?: string;
    owner?: { login?: string };
  };
  pull_request?: {
    number?: number;
    body?: string | null;
    head?: { sha?: string; ref?: string };
    base?: { ref?: string };
  };
};

type PullRequest = {
  head?: { sha?: string };
  body?: string | null;
};

Deno.serve(async (req) => {
  if (req.method === "GET") {
    return json({ ok: true, name: "github-pr-gate" });
  }
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const webhookSecret = normalizeWebhookSecret(
    requireEnv("GITHUB_WEBHOOK_SECRET"),
  );
  const rawBody = await req.text();
  const signature = req.headers.get("x-hub-signature-256");
  if (!signature) {
    return new Response("Missing X-Hub-Signature-256", { status: 401 });
  }
  const valid = await verifyGithubSignature(rawBody, signature, webhookSecret);
  if (!valid) {
    return new Response("Invalid signature", { status: 401 });
  }

  const event = req.headers.get("x-github-event") ?? "";
  if (event === "ping") {
    return json({ ok: true, ping: true });
  }
  if (event !== "pull_request") {
    return json({ ok: true, ignored: event });
  }

  const deliveryId = req.headers.get("x-github-delivery");
  const claim = await claimDelivery(deliveryId);
  if (claim === "duplicate") {
    return json({ ok: true, duplicate: true });
  }

  let payload: PullRequestPayload;
  try {
    payload = JSON.parse(rawBody) as PullRequestPayload;
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  const action = payload.action ?? "";
  if (!(HANDLED_PR_ACTIONS as readonly string[]).includes(action)) {
    return json({ ok: true, ignored: action });
  }

  const owner = payload.repository?.owner?.login;
  const repo = payload.repository?.name;
  const prNumber = payload.pull_request?.number;
  const headSha = payload.pull_request?.head?.sha;
  const branch = payload.pull_request?.head?.ref;
  const baseRef = payload.pull_request?.base?.ref ?? "";
  if (!owner || !repo || !prNumber || !headSha || !branch) {
    return new Response("Malformed pull_request payload", { status: 400 });
  }

  if (!isAllowedRepo(owner, repo)) {
    return json({ ok: true, ignored: "repo", allowed: allowedRepos() });
  }

  const installationId = payload.installation?.id ??
    Number(Deno.env.get("GITHUB_INSTALLATION_ID") ?? "");
  if (!Number.isFinite(installationId) || installationId <= 0) {
    return new Response("Missing installation id", { status: 500 });
  }
  if (!isAllowedInstallation(installationId)) {
    return json({ ok: true, ignored: "installation" });
  }

  return await scanAndPublish({
    owner,
    repo,
    prNumber,
    headSha,
    branch,
    baseRef,
    body: payload.pull_request?.body ?? "",
    event,
    action,
    installationId,
  }, 0);
});

async function scanAndPublish(input: {
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  branch: string;
  baseRef: string;
  body: string;
  event: string;
  action: string;
  installationId: number;
}, depth: number): Promise<Response> {
  if (depth > 1) {
    return json({ ok: false, conclusion: "failure", error: "sha-churn" });
  }
  let github: GitHubClient | undefined;
  let checkId: number | undefined;
  let activeSha = input.headSha;
  try {
    github = new GitHubClient(
      await getInstallationToken(
        requireEnv("GITHUB_APP_ID"),
        requireEnv("GITHUB_APP_PRIVATE_KEY"),
        input.installationId,
      ),
    );
    checkId = await createInProgressCheck(
      github,
      input.owner,
      input.repo,
      activeSha,
    );
    const { findings } = await withTimeout(
      runPolicy(github, {
        owner: input.owner,
        repo: input.repo,
        prNumber: input.prNumber,
        headSha: activeSha,
        branch: input.branch,
        baseRef: input.baseRef,
        body: input.body,
      }),
      SCAN_TIMEOUT_MS,
    );

    const latest = await github.request<PullRequest>(
      `/repos/${input.owner}/${input.repo}/pulls/${input.prNumber}`,
    );
    const latestSha = latest.head?.sha;
    if (latestSha && latestSha !== activeSha) {
      await completeCheck(
        github,
        input.owner,
        input.repo,
        checkId,
        "failure",
        "Superseded",
        "Head SHA changed during the scan. A new run is required on the latest commit.",
      );
      return await scanAndPublish({
        ...input,
        headSha: latestSha,
        body: latest.body ?? input.body,
      }, depth + 1);
    }

    const failed = findings.length > 0;
    const title = failed
      ? `${findings.length} check(s) failed`
      : "All checks passed";
    await completeCheck(
      github,
      input.owner,
      input.repo,
      checkId,
      failed ? "failure" : "success",
      title,
      formatFindings(findings),
    );
    console.log(JSON.stringify({
      event: input.event,
      action: input.action,
      owner: input.owner,
      repo: input.repo,
      pr: input.prNumber,
      sha: activeSha,
      conclusion: failed ? "failure" : "success",
      findings: findings.length,
    }));
    return json({ ok: true, conclusion: failed ? "failure" : "success" });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    console.error(JSON.stringify({
      event: input.event,
      action: input.action,
      owner: input.owner,
      repo: input.repo,
      pr: input.prNumber,
      sha: activeSha,
      error: message,
    }));
    try {
      if (!github) {
        return json({ ok: false, conclusion: "failure", error: "auth" });
      }
      const summary =
        "The gate failed closed due to an internal error. The PR was not approved.";
      if (checkId) {
        await completeCheck(
          github,
          input.owner,
          input.repo,
          checkId,
          "failure",
          "Scanner error",
          summary,
        );
      } else {
        await publishFailureCheck(
          github,
          input.owner,
          input.repo,
          activeSha,
          "Scanner error",
          summary,
        );
      }
      return json({ ok: false, conclusion: "failure" });
    } catch {
      return json({ ok: false, conclusion: "failure" });
    }
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("scan timeout")), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
