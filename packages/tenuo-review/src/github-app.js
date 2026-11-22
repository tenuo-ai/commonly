// Minimal GitHub App client: app JWT, installation tokens, REST and GraphQL.
// No dependencies beyond Node's crypto and fetch.

import { createHmac, createSign, timingSafeEqual } from "node:crypto";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

export function appJwt({ appId, privateKeyPem, now = Math.floor(Date.now() / 1000) }) {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  // iat backdated for clock drift; GitHub caps exp at 10 minutes.
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(appId) }));
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(privateKeyPem))}`;
}

/** Constant-time check of `X-Hub-Signature-256` over the raw request body. */
export function verifyWebhookSignature({ secret, rawBody, signatureHeader }) {
  if (typeof signatureHeader !== "string" || !signatureHeader.startsWith("sha256=")) return false;
  const expected = Buffer.from(`sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`);
  const given = Buffer.from(signatureHeader);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

export function createGitHubApp({ appId, privateKeyPem, apiUrl = "https://api.github.com", fetchImpl = fetch }) {
  const tokens = new Map(); // installationId -> { token, expiresAt }

  async function call(method, path, { token, body } = {}) {
    const res = await fetchImpl(`${apiUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text.slice(0, 300)}`);
    return text ? JSON.parse(text) : null;
  }

  async function installationIdFor(repo) {
    const jwt = appJwt({ appId, privateKeyPem });
    return (await call("GET", `/repos/${repo}/installation`, { token: jwt })).id;
  }

  async function tokenFor(repo) {
    const id = await installationIdFor(repo);
    const cached = tokens.get(id);
    if (cached && cached.expiresAt - Date.now() > 5 * 60 * 1000) return cached.token;
    const jwt = appJwt({ appId, privateKeyPem });
    const t = await call("POST", `/app/installations/${id}/access_tokens`, { token: jwt });
    tokens.set(id, { token: t.token, expiresAt: Date.parse(t.expires_at) });
    return t.token;
  }

  return {
    async getPull(repo, number) {
      return call("GET", `/repos/${repo}/pulls/${number}`, { token: await tokenFor(repo) });
    },
    async createCheckRun(repo, body) {
      return call("POST", `/repos/${repo}/check-runs`, { token: await tokenFor(repo), body });
    },
    /** Entries in the merge queue for `branch`, in queue order. */
    async mergeQueueEntries(repo, branch) {
      const [owner, name] = repo.split("/");
      const query = `query($owner:String!,$name:String!,$branch:String!){
        repository(owner:$owner,name:$name){ mergeQueue(branch:$branch){ entries(first:100){ nodes{
          position headCommit{ oid } pullRequest{ number headRefOid author{ login } } } } } } }`;
      const res = await call("POST", "/graphql", {
        token: await tokenFor(repo),
        body: { query, variables: { owner, name, branch } },
      });
      if (res.errors) throw new Error(`graphql: ${JSON.stringify(res.errors).slice(0, 300)}`);
      return (res.data?.repository?.mergeQueue?.entries?.nodes ?? []).map((n) => ({
        position: n.position,
        headSha: n.headCommit?.oid ?? null,
        pr: n.pullRequest?.number,
        prHeadSha: n.pullRequest?.headRefOid,
        authorLogin: n.pullRequest?.author?.login,
      }));
    },
  };
}
