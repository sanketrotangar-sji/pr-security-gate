import { CHECK_NAME } from "./config.ts";
import type { GitHubClient } from "./github.ts";

type CheckRun = { id: number };

export async function createInProgressCheck(
  github: GitHubClient,
  owner: string,
  repo: string,
  headSha: string,
): Promise<number> {
  const created = await github.request<CheckRun>(
    `/repos/${owner}/${repo}/check-runs`,
    {
      method: "POST",
      body: JSON.stringify({
        name: CHECK_NAME,
        head_sha: headSha,
        status: "in_progress",
        output: {
          title: "Scanning PR",
          summary: "Running v1 policy checks and regex secret scan.",
        },
      }),
    },
  );
  return created.id;
}

export async function completeCheck(
  github: GitHubClient,
  owner: string,
  repo: string,
  checkId: number,
  conclusion: "success" | "failure",
  title: string,
  summary: string,
): Promise<void> {
  await github.request(`/repos/${owner}/${repo}/check-runs/${checkId}`, {
    method: "PATCH",
    body: JSON.stringify({
      name: CHECK_NAME,
      status: "completed",
      conclusion,
      output: { title, summary },
    }),
  });
}

export async function publishFailureCheck(
  github: GitHubClient,
  owner: string,
  repo: string,
  headSha: string,
  title: string,
  summary: string,
): Promise<void> {
  await github.request(`/repos/${owner}/${repo}/check-runs`, {
    method: "POST",
    body: JSON.stringify({
      name: CHECK_NAME,
      head_sha: headSha,
      status: "completed",
      conclusion: "failure",
      output: { title, summary },
    }),
  });
}
