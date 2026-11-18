import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateAgentKey, generateIssuerKey, issueMergeWarrant, requestApproval, signApproval, verifyMerge,
} from "../src/index.js";

const repo = "tenuo-ai/demo-day";
const sha1 = "a".repeat(40);
const sha2 = "b".repeat(40);

function setup() {
  const issuer = generateIssuerKey();
  const author = generateAgentKey(); // pod-architect
  const reviewer = generateAgentKey(); // sprint-review
  const outsider = generateAgentKey();
  const warrant = issueMergeWarrant({
    issuerSecretHex: issuer.secretHex, authorPublicHex: author.publicHex,
    reviewerPublicHex: [reviewer.publicHex, author.publicHex], repo,
  });
  const base = { trustedRootHex: issuer.publicHex, warrant, authorSecretHex: author.secretHex, repo, pr: 792 };
  return { issuer, author, reviewer, outsider, warrant, base };
}

const code = async (p) => p.then(() => "ALLOW", (e) => e.code ?? e.message);

test("another agent's signed approval allows the merge", async () => {
  const { reviewer, base } = setup();
  const request = requestApproval({ ...base, headSha: sha1 });
  const approval = signApproval({ request, reviewerSecretHex: reviewer.secretHex, reviewerName: "sprint-review", expect: { repo, pr: 792, headSha: sha1 } });
  assert.equal(await code(verifyMerge({ ...base, headSha: sha1, approvals: [approval] })), "ALLOW");
});

test("no approval: approval required", async () => {
  const { base } = setup();
  assert.equal(await code(verifyMerge({ ...base, headSha: sha1, approvals: [] })), "TENUO_APPROVAL_REQUIRED");
});

test("the author's own approval does not count, even forced past the helper", async () => {
  const { author, base } = setup();
  const request = requestApproval({ ...base, headSha: sha1 });
  assert.throws(() => signApproval({ request, reviewerSecretHex: author.secretHex, reviewerName: "pod-architect", expect: { repo, pr: 792, headSha: sha1 } }), /own merge/);
  const { createTenuo } = await import("@tenuo/core");
  const forced = createTenuo.signApproval(request, createTenuo.holderKeyFromHex(author.secretHex), { externalId: "pod-architect" });
  assert.equal(await code(verifyMerge({ ...base, headSha: sha1, approvals: [forced] })), "TENUO_INSUFFICIENT_APPROVALS");
});

test("an agent not named in the warrant cannot approve", async () => {
  const { outsider, base } = setup();
  const request = requestApproval({ ...base, headSha: sha1 });
  const approval = signApproval({ request, reviewerSecretHex: outsider.secretHex, reviewerName: "outsider", expect: { repo, pr: 792, headSha: sha1 } });
  assert.equal(await code(verifyMerge({ ...base, headSha: sha1, approvals: [approval] })), "TENUO_INSUFFICIENT_APPROVALS");
});

test("an approval of an older commit does not cover a new push", async () => {
  const { reviewer, base } = setup();
  const request = requestApproval({ ...base, headSha: sha1 });
  const approval = signApproval({ request, reviewerSecretHex: reviewer.secretHex, reviewerName: "sprint-review", expect: { repo, pr: 792, headSha: sha1 } });
  assert.equal(await code(verifyMerge({ ...base, headSha: sha2, approvals: [approval] })), "TENUO_INSUFFICIENT_APPROVALS");
});

test("the warrant does not reach another repository, even with an approval", async () => {
  const { reviewer, base } = setup();
  const other = { ...base, repo: "Team-Commonly/commonly" };
  const request = requestApproval({ ...other, headSha: sha1 });
  const approval = signApproval({ request, reviewerSecretHex: reviewer.secretHex, reviewerName: "sprint-review", expect: { repo: other.repo, pr: 792, headSha: sha1 } });
  const result = await code(verifyMerge({ ...other, headSha: sha1, approvals: [approval] }));
  assert.notEqual(result, "ALLOW");
  console.log("other repo:", result);
});

test("a reviewer refuses to sign a request for a merge it did not review", () => {
  const { reviewer, base } = setup();
  const request = requestApproval({ ...base, headSha: sha2 });
  assert.throws(() => signApproval({ request, reviewerSecretHex: reviewer.secretHex, reviewerName: "sprint-review", expect: { repo, pr: 792, headSha: sha1 } }), /does not match/);
});

test("a warrant from an untrusted issuer is refused", async () => {
  const { reviewer, base } = setup();
  const rogue = generateIssuerKey();
  const request = requestApproval({ ...base, headSha: sha1 });
  const approval = signApproval({ request, reviewerSecretHex: reviewer.secretHex, reviewerName: "sprint-review", expect: { repo, pr: 792, headSha: sha1 } });
  assert.notEqual(await code(verifyMerge({ ...base, trustedRootHex: rogue.publicHex, headSha: sha1, approvals: [approval] })), "ALLOW");
});
