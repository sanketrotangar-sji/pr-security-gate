export async function claimDelivery(
  deliveryId: string | null,
): Promise<"claimed" | "duplicate" | "skipped"> {
  if (!deliveryId) return "skipped";
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return "skipped";

  const res = await fetch(`${url}/rest/v1/webhook_deliveries`, {
    method: "POST",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({ delivery_id: deliveryId }),
  });
  if (res.status === 409 || res.status === 23505) return "duplicate";
  if (!res.ok) {
    const text = await res.text();
    if (text.includes("duplicate") || res.status === 409) return "duplicate";
    console.error(JSON.stringify({
      dedup: "insert-failed",
      status: res.status,
    }));
    return "skipped";
  }

  const cutoff = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();
  fetch(
    `${url}/rest/v1/webhook_deliveries?received_at=lt.${
      encodeURIComponent(cutoff)
    }`,
    {
      method: "DELETE",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
      },
    },
  ).catch(() => {});

  return "claimed";
}

export function allowedRepos(): string[] {
  const raw = Deno.env.get("ALLOWED_REPOS");
  if (!raw?.trim()) return ["sanketrotangar-sji/pr-security-gate"];
  return raw.split(",").map((item) => item.trim()).filter(Boolean);
}

export function isAllowedRepo(owner: string, repo: string): boolean {
  const full = `${owner}/${repo}`;
  return allowedRepos().some((allowed) => allowed.toLowerCase() === full.toLowerCase());
}

export function isAllowedInstallation(installationId: number): boolean {
  const raw = Deno.env.get("ALLOWED_INSTALLATION_IDS");
  if (!raw?.trim()) return true;
  const allowed = raw.split(",").map((item) => Number(item.trim())).filter((
    id,
  ) => Number.isFinite(id) && id > 0);
  if (allowed.length === 0) return true;
  return allowed.includes(installationId);
}
