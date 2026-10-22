export function requireEnv(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing env ${name}`);
  return value;
}

export function normalizePem(value: string): string {
  let pem = value.trim();
  if (
    (pem.startsWith('"') && pem.endsWith('"')) ||
    (pem.startsWith("'") && pem.endsWith("'"))
  ) {
    pem = pem.slice(1, -1);
  }
  return pem.replace(/\\n/g, "\n").replace(/\r\n/g, "\n").trim();
}

export async function getInstallationToken(
  appId: string,
  privateKeyPem: string,
  installationId: number,
): Promise<string> {
  const jwt = await signGitHubAppJwt(appId, privateKeyPem);
  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: githubHeaders(jwt),
    },
  );
  if (!res.ok) {
    throw new Error(`installation token failed: ${res.status}`);
  }
  const data = await res.json() as { token?: string };
  if (!data.token) throw new Error("installation token missing");
  return data.token;
}

export class GitHubClient {
  constructor(private token: string) {}

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    for (const [key, value] of Object.entries(githubHeaders(this.token))) {
      if (!headers.has(key)) headers.set(key, value);
    }
    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const res = await fetch(`https://api.github.com${path}`, {
      ...init,
      headers,
    });
    if (!res.ok) {
      throw new Error(
        `GitHub ${init.method ?? "GET"} ${path} failed: ${res.status}`,
      );
    }
    if (res.status === 204) return undefined as T;
    return await res.json() as T;
  }
}

async function signGitHubAppJwt(
  appId: string,
  privateKeyPem: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlJson({ alg: "RS256", typ: "JWT" });
  const payload = b64urlJson({
    iat: now - 60,
    exp: now + 9 * 60,
    iss: appId,
  });
  const unsigned = `${header}.${payload}`;
  const key = await importRsaPrivateKey(privateKeyPem);
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode(unsigned),
    ),
  );
  return `${unsigned}.${b64url(signature)}`;
}

async function importRsaPrivateKey(pem: string): Promise<CryptoKey> {
  const normalized = normalizePem(pem);
  const der = pemToDer(normalized);
  const pkcs8 = normalized.includes("BEGIN RSA PRIVATE KEY")
    ? wrapPkcs1AsPkcs8(der)
    : der;
  return await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem.replace(/-----[-A-Z ]+-----/g, "").replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function wrapPkcs1AsPkcs8(pkcs1: Uint8Array): Uint8Array {
  const oid = Uint8Array.from([
    0x30,
    0x0d,
    0x06,
    0x09,
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
  ]);
  const version = Uint8Array.from([0x02, 0x01, 0x00]);
  const inner = concat(version, oid, encodeAsn1(0x04, pkcs1));
  return encodeAsn1(0x30, inner);
}

function encodeAsn1(tag: number, value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  const out = new Uint8Array(1 + length.length + value.length);
  out[0] = tag;
  out.set(length, 1);
  out.set(value, 1 + length.length);
  return out;
}

function encodeLength(length: number): Uint8Array {
  if (length < 128) return Uint8Array.from([length]);
  const bytes: number[] = [];
  let rest = length;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest >>= 8;
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function githubHeaders(token: string): Record<string, string> {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "sj-pr-security-gate",
  };
}

function b64urlJson(value: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(value)));
}

function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
