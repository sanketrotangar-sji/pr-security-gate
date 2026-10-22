import {
  completeCheck,
  createInProgressCheck,
  publishFailureCheck,
} from "./checks.ts";
import { HANDLED_PR_ACTIONS } from "./config.ts";
import {
  getInstallationToken,
  GitHubClient,
  requireEnv,
} from "./github.ts";
import { formatFindings, runPolicy } from "./policy.ts";
import { verifyGithubSignature } from "./verify.ts";

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
  };
};

Deno.serve(async (req) => {
  if (req.method === "GET") {
    return json({ ok: true, name: "github-pr-gate" });
  }
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const webhookSecret = requireEnv("GITHUB_WEBHOOK_SECRET");
  const rawBody = await req.text();
  const signature = req.headers.get("x-hub-signature-256");
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
  if (!owner || !repo || !prNumber || !headSha || !branch) {
    return new Response("Malformed pull_request payload", { status: 400 });
  }

  const installationId = payload.installation?.id ??
    Number(requireEnv("GITHUB_INSTALLATION_ID"));
  if (!Number.isFinite(installationId) || installationId <= 0) {
    return new Response("Missing installation id", { status: 500 });
  }

  const github = new GitHubClient(
    await getInstallationToken(
      requireEnv("GITHUB_APP_ID"),
      requireEnv("GITHUB_APP_PRIVATE_KEY"),
      installationId,
    ),
  );

  let checkId: number | undefined;
  try {
    checkId = await createInProgressCheck(github, owner, repo, headSha);
    const { findings } = await runPolicy(github, {
      owner,
      repo,
      prNumber,
      headSha,
      branch,
      body: payload.pull_request?.body ?? "",
    });
    const failed = findings.length > 0;
    const title = failed
      ? `${findings.length} v1 check(s) failed`
      : "All v1 checks passed";
    await completeCheck(
      github,
      owner,
      repo,
      checkId,
      failed ? "failure" : "success",
      title,
      formatFindings(findings),
    );
    console.log(JSON.stringify({
      event,
      action,
      owner,
      repo,
      pr: prNumber,
      sha: headSha,
      conclusion: failed ? "failure" : "success",
      findings: findings.length,
    }));
    return json({ ok: true, conclusion: failed ? "failure" : "success" });
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown error";
    console.error(JSON.stringify({
      event,
      action,
      owner,
      repo,
      pr: prNumber,
      sha: headSha,
      error: message,
    }));
    try {
      const summary =
        "The gate failed closed due to an internal error. The PR was not approved.";
      if (checkId) {
        await completeCheck(
          github,
          owner,
          repo,
          checkId,
          "failure",
          "Scanner error",
          summary,
        );
      } else {
        await publishFailureCheck(
          github,
          owner,
          repo,
          headSha,
          "Scanner error",
          summary,
        );
      }
      return json({ ok: false, conclusion: "failure" });
    } catch {
      return new Response("Internal error", { status: 500 });
    }
  }
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
