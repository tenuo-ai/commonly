#!/usr/bin/env node
// Test harness for the verifier without a GitHub App. It polls open pull
// requests and the merge queue with a personal token, and reports
// `tenuo/agent-review` as a commit status instead of an App check run.
// Same verifier logic as bin/verifier-app.js. Not for production: a status
// can be posted by anyone with write access, which is why production uses an
// App pinned by a ruleset.
//
// Env: GITHUB_TOKEN, TENUO_REVIEW_TRUSTED_ROOT, REPO (owner/name),
//      BRANCH (default main), PORT (default 8787), POLL_SECONDS (default 5),
//      TENUO_REVIEW_AGENT_LOGINS, TENUO_REVIEW_REVIEWERS (see src/verifier.js).
import { createServer } from "node:http";
import { createVerifier, verifierConfig, MergeRequestRejected } from "../src/verifier.js";

const env = (n, d) => process.env[n] ?? d ?? (() => { throw new Error(`${n} is required`); })();
const TOKEN = env("GITHUB_TOKEN");
const REPO = env("REPO");
const BRANCH = env("BRANCH", "main");
const API = "https://api.github.com";
const log = (line) => console.log(new Date().toISOString(), line);

async function call(method, path, body) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { Authorization: `Bearer ${TOKEN}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

const github = {
  getPull: (repo, n) => call("GET", `/repos/${repo}/pulls/${n}`),
  // Report as a commit status: same name, same verdict, no App.
  createCheckRun: (repo, body) =>
    call("POST", `/repos/${repo}/statuses/${body.head_sha}`, {
      state: body.conclusion === "success" ? "success" : "failure",
      context: body.name,
      description: body.output.title.slice(0, 140),
    }),
  async mergeQueueEntries(repo, branch) {
    const [owner, name] = repo.split("/");
    const query = `query($owner:String!,$name:String!,$branch:String!){ repository(owner:$owner,name:$name){
      mergeQueue(branch:$branch){ entries(first:100){ nodes{ position state headCommit{ oid } pullRequest{ number headRefOid author{ login } } } } } } }`;
    const res = await call("POST", "/graphql", { query, variables: { owner, name, branch } });
    if (res.errors) throw new Error(`graphql: ${JSON.stringify(res.errors).slice(0, 300)}`);
    return (res.data?.repository?.mergeQueue?.entries?.nodes ?? []).map((n) => ({
      position: n.position, state: n.state, headSha: n.headCommit?.oid ?? null, pr: n.pullRequest?.number, prHeadSha: n.pullRequest?.headRefOid, authorLogin: n.pullRequest?.author?.login,
    }));
  },
};

const verifier = createVerifier({ trustedRootHex: env("TENUO_REVIEW_TRUSTED_ROOT"), github, log, ...verifierConfig(process.env) });
const seenHeads = new Set();
const seenGroups = new Set();

// Polling can't see who pushed a commit, so every head here counts as pushed
// by an agent and needs a review. The App learns pushers from webhooks.
async function poll() {
  const pulls = await call("GET", `/repos/${REPO}/pulls?state=open&base=${BRANCH}&per_page=100`);
  for (const p of pulls) {
    const key = `${p.number}@${p.head.sha}`;
    if (seenHeads.has(key)) continue;
    seenHeads.add(key);
    await verifier.onPullRequest({ action: "synchronize", repository: { full_name: REPO }, pull_request: { number: p.number, head: { sha: p.head.sha }, user: p.user } });
  }
  const entries = await github.mergeQueueEntries(REPO, BRANCH);
  for (const e of entries) {
    if (!e.headSha || seenGroups.has(e.headSha)) continue;
    seenGroups.add(e.headSha);
    log(`queue: #${e.pr} position ${e.position} state ${e.state} group ${e.headSha.slice(0, 7)} pr head ${String(e.prHeadSha).slice(0, 7)}`);
    await verifier.onMergeGroup({ action: "checks_requested", repository: { full_name: REPO }, merge_group: { head_sha: e.headSha, base_ref: `refs/heads/${BRANCH}` } });
  }
}

const loop = async () => {
  try { await poll(); } catch (e) { log(`poll error: ${e.message}`); }
  setTimeout(loop, Number(env("POLL_SECONDS", "5")) * 1000);
};
loop();

createServer(async (req, res) => {
  const send = (status, body) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
  if (req.method !== "POST" || req.url !== "/merge-requests") return send(404, { error: "not found" });
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    const record = await verifier.requestMerge(body);
    seenHeads.add(`${body.pr}@${body.headSha}`);
    log(`authorized #${body.pr} at ${body.headSha.slice(0, 7)} by ${record.approvers.join(", ")}`);
    send(200, record);
  } catch (e) {
    if (e instanceof MergeRequestRejected) { log(`rejected #${"?"}: ${e.code} ${e.message}`); return send(403, { error: e.message, code: e.code }); }
    log(`error: ${e.message}`);
    send(500, { error: "internal error" });
  }
}).listen(Number(env("PORT", "8787")), () => log(`verifier (local harness) for ${REPO} on :${env("PORT", "8787")}`));
