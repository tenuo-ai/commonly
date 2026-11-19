import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, createVerify } from "node:crypto";
import { createTenuo } from "@tenuo/core";
import {
  generateAgentKey, generateIssuerKey, issueMergeWarrant, requestApproval, signApproval, presentMerge,
} from "../src/index.js";
import { createVerifier, MergeRequestRejected } from "../src/verifier.js";
import { appJwt, verifyWebhookSignature } from "../src/github-app.js";

const repo = "tenuo-ai/demo-day";
const sha = (c) => c.repeat(40);

function fakeGitHub() {
  const pulls = new Map();
  const checks = [];
  let queue = [];
  return {
    pulls, checks,
    setQueue: (q) => { queue = q; },
    async getPull(r, n) {
      const p = pulls.get(Number(n));
      if (!p) throw new Error("404");
      return p;
    },
    async createCheckRun(r, body) { checks.push({ repo: r, ...body }); return { id: checks.length }; },
    async mergeQueueEntries() { return queue; },
  };
}

function world() {
  const issuer = generateIssuerKey();
  const author = generateAgentKey();
  const reviewer = generateAgentKey();
  const outsider = generateAgentKey();
  const warrant = issueMergeWarrant({
    issuerSecretHex: issuer.secretHex, authorPublicHex: author.publicHex, reviewerPublicHex: [reviewer.publicHex], repo,
  });
  const github = fakeGitHub();
  const verifier = createVerifier({ trustedRootHex: issuer.publicHex, github });
  const base = { trustedRootHex: issuer.publicHex, warrant, authorSecretHex: author.secretHex, repo };
  const approve = (key, name, pr, headSha) => signApproval({
    request: requestApproval({ ...base, pr, headSha }), reviewerSecretHex: key.secretHex, reviewerName: name, expect: { repo, pr, headSha },
  });
  const ask = (pr, headSha, approvals) =>
    verifier.requestMerge({ repo, pr, headSha, presented: presentMerge({ ...base, pr, headSha, approvals }) });
  return { issuer, author, reviewer, outsider, warrant, github, verifier, base, approve, ask };
}

const rejected = async (p) => p.then(() => "ok", (e) => (e instanceof MergeRequestRejected ? e.code : `unexpected: ${e.message}`));
const last = (github) => github.checks.at(-1);

test("a reviewer-approved merge request is verified, recorded and reported on the head", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("a") } });
  const record = await w.ask(7, sha("a"), [w.approve(w.reviewer, "sprint-review", 7, sha("a"))]);
  assert.deepEqual(record.approvers, ["sprint-review"]);
  assert.equal(last(w.github).conclusion, "success");
  assert.equal(last(w.github).head_sha, sha("a"));
});

test("without a valid approval the author cannot even produce a merge request", () => {
  const w = world();
  const req = requestApproval({ ...w.base, pr: 7, headSha: sha("a") });
  const self = createTenuo.signApproval(req, createTenuo.holderKeyFromHex(w.author.secretHex), { externalId: "pod-architect" });
  for (const approvals of [[], [self], [w.approve(w.outsider, "outsider", 7, sha("a"))]]) {
    assert.throws(() => presentMerge({ ...w.base, pr: 7, headSha: sha("a"), approvals }), /approval/i);
  }
});

test("the verifier rejects a good request whose approvals were swapped out, and reports nothing", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("a") } });
  const good = presentMerge({ ...w.base, pr: 7, headSha: sha("a"), approvals: [w.approve(w.reviewer, "sprint-review", 7, sha("a"))] });
  const req = requestApproval({ ...w.base, pr: 7, headSha: sha("a") });
  const self = createTenuo.signApproval(req, createTenuo.holderKeyFromHex(w.author.secretHex), { externalId: "pod-architect" });
  const outsider = w.approve(w.outsider, "outsider", 7, sha("a"));
  const send = (approvals) => w.verifier.requestMerge({ repo, pr: 7, headSha: sha("a"), presented: { ...good, approvals } });
  assert.equal(await rejected(send([])), "TENUO_APPROVAL_REQUIRED");
  assert.equal(await rejected(send([self])), "TENUO_INSUFFICIENT_APPROVALS");
  assert.equal(await rejected(send([outsider])), "TENUO_INSUFFICIENT_APPROVALS");
  assert.equal(w.github.checks.length, 0);
});

test("a request for anything but the current head is rejected", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("b") } });
  assert.equal(await rejected(w.ask(7, sha("a"), [w.approve(w.reviewer, "sprint-review", 7, sha("a"))])), "STALE_HEAD");
  w.github.pulls.set(8, { state: "closed", head: { sha: sha("a") } });
  assert.equal(await rejected(w.ask(8, sha("a"), [w.approve(w.reviewer, "sprint-review", 8, sha("a"))])), "NOT_OPEN");
});

test("a presentation cannot be pointed at another pull request or commit", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("a") } });
  w.github.pulls.set(9, { state: "open", head: { sha: sha("c") } });
  const presented = presentMerge({ ...w.base, pr: 7, headSha: sha("a"), approvals: [w.approve(w.reviewer, "sprint-review", 7, sha("a"))] });
  assert.notEqual(await rejected(w.verifier.requestMerge({ repo, pr: 9, headSha: sha("c"), presented })), "ok");
});

test("a presentation from a key the warrant was not issued to is rejected", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("a") } });
  const thief = generateAgentKey();
  const approval = w.approve(w.reviewer, "sprint-review", 7, sha("a"));
  assert.throws(() => presentMerge({ ...w.base, authorSecretHex: thief.secretHex, pr: 7, headSha: sha("a"), approvals: [approval] }));
});

test("a new push fails the check until the new head is approved", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("a") } });
  await w.ask(7, sha("a"), [w.approve(w.reviewer, "sprint-review", 7, sha("a"))]);
  const push = { action: "synchronize", repository: { full_name: repo }, pull_request: { number: 7, head: { sha: sha("b") } } };
  await w.verifier.onPullRequest(push);
  assert.equal(last(w.github).conclusion, "failure");
  assert.equal(last(w.github).head_sha, sha("b"));
  w.github.pulls.set(7, { state: "open", head: { sha: sha("b") } });
  await w.ask(7, sha("b"), [w.approve(w.reviewer, "sprint-review", 7, sha("b"))]);
  assert.equal(last(w.github).conclusion, "success");
});

test("merge group passes only when every pull request in it is authorized at its queued head", async () => {
  const w = world();
  for (const [n, c] of [[7, "a"], [8, "b"]]) {
    w.github.pulls.set(n, { state: "open", head: { sha: sha(c) } });
    await w.ask(n, sha(c), [w.approve(w.reviewer, "sprint-review", n, sha(c))]);
  }
  w.github.pulls.set(9, { state: "open", head: { sha: sha("c") } });
  const group = (head) => ({ action: "checks_requested", repository: { full_name: repo }, merge_group: { head_sha: head, base_ref: "refs/heads/main" } });
  w.github.setQueue([
    { position: 1, headSha: sha("1"), pr: 7, prHeadSha: sha("a") },
    { position: 2, headSha: sha("2"), pr: 8, prHeadSha: sha("b") },
    { position: 3, headSha: sha("3"), pr: 9, prHeadSha: sha("c") },
  ]);
  await w.verifier.onMergeGroup(group(sha("2")));
  assert.equal(last(w.github).conclusion, "success");
  assert.equal(last(w.github).head_sha, sha("2"));
  await w.verifier.onMergeGroup(group(sha("3")));
  assert.equal(last(w.github).conclusion, "failure");
  assert.match(last(w.github).output.title, /#9/);
  await w.verifier.onMergeGroup(group(sha("f")));
  assert.equal(last(w.github).conclusion, "failure");
});

test("merge group fails when a queued pull request's head differs from the authorized one", async () => {
  const w = world();
  w.github.pulls.set(7, { state: "open", head: { sha: sha("a") } });
  await w.ask(7, sha("a"), [w.approve(w.reviewer, "sprint-review", 7, sha("a"))]);
  w.github.setQueue([{ position: 1, headSha: sha("1"), pr: 7, prHeadSha: sha("d") }]);
  await w.verifier.onMergeGroup({ action: "checks_requested", repository: { full_name: repo }, merge_group: { head_sha: sha("1"), base_ref: "refs/heads/main" } });
  assert.equal(last(w.github).conclusion, "failure");
});

test("webhook signatures are checked in constant time over the raw body", () => {
  const body = Buffer.from('{"a":1}');
  const good = `sha256=${createHmac("sha256", "s3cret").update(body).digest("hex")}`;
  assert.ok(verifyWebhookSignature({ secret: "s3cret", rawBody: body, signatureHeader: good }));
  assert.ok(!verifyWebhookSignature({ secret: "other", rawBody: body, signatureHeader: good }));
  assert.ok(!verifyWebhookSignature({ secret: "s3cret", rawBody: Buffer.from('{"a":2}'), signatureHeader: good }));
  assert.ok(!verifyWebhookSignature({ secret: "s3cret", rawBody: body, signatureHeader: undefined }));
});

test("app JWT is RS256-signed and short-lived", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwt = appJwt({ appId: 42, privateKeyPem: privateKey.export({ type: "pkcs1", format: "pem" }), now: 1000 });
  const [h, p, s] = jwt.split(".");
  const v = createVerify("RSA-SHA256");
  v.update(`${h}.${p}`);
  assert.ok(v.verify(publicKey, Buffer.from(s, "base64url")));
  assert.deepEqual(JSON.parse(Buffer.from(p, "base64url")), { iat: 940, exp: 1540, iss: "42" });
});
