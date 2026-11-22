// Signed agent reviews with Tenuo warrants.
//
// Three roles, three keys:
//   - the instance (control plane) holds the issuer key and issues warrants;
//   - each agent holds its own holder key, generated where it runs;
//   - nothing else holds a secret. The GitHub check trusts only the issuer's
//     public key.
//
// The author agent receives a merge warrant for one repository. The warrant
// gates `merge_pr` on a signed approval from a listed reviewer key, and the
// author's own key is never listed, so self-approval cannot satisfy it. An
// approval commits to (warrant id, tool, args, holder), and args carry the
// repository, the pull request and the head commit, so a new push needs a new
// approval.

import { createTenuo, exact, pattern } from "@tenuo/core";

export const TOOL = "merge_pr";
const T = createTenuo;

export function generateAgentKey() {
  const secret = T.generateHolderKey();
  return { secretHex: Buffer.from(secret).toString("hex"), publicHex: T.publicKeyFromHolderKey(secret).hex };
}

export function generateIssuerKey() {
  const secret = T.generateIssuerKey();
  const cp = createTenuo({ root: T.issuerKeyFromBytes(secret) });
  return { secretHex: Buffer.from(secret).toString("hex"), publicHex: cp.issuerPublicKey().hex };
}

export function mergeArgs({ repo, pr, headSha }) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) throw new Error(`bad repo: ${repo}`);
  if (!/^\d+$/.test(String(pr))) throw new Error(`bad pr: ${pr}`);
  if (!/^[0-9a-f]{40}$/.test(headSha)) throw new Error(`bad head sha: ${headSha}`);
  return { repo, pr: String(pr), head_sha: headSha };
}

/**
 * Control plane: issue the author agent a merge warrant for one repository,
 * gated on `minApprovals` signed approvals from `reviewerPublicHex`.
 * The author's key is refused as a reviewer.
 */
export function issueMergeWarrant({ issuerSecretHex, authorPublicHex, reviewerPublicHex, repo, ttlSeconds = 3600, minApprovals = 1 }) {
  const reviewers = [...new Set(reviewerPublicHex)].filter((k) => k !== authorPublicHex);
  if (reviewers.length < minApprovals) throw new Error("not enough reviewers other than the author");
  const cp = createTenuo({ root: T.issuerKeyFromHex(issuerSecretHex) });
  const session = cp.session({
    allow: { [TOOL]: { repo: exact(repo), pr: pattern("*"), head_sha: pattern("*") } },
    holder: T.publicKeyFromHex(authorPublicHex),
    ttlSeconds,
    requireApproval: {
      approvers: reviewers.map((k) => T.publicKeyFromHex(k)),
      min: minApprovals,
      tools: [TOOL],
    },
  });
  return session.toWireString();
}

function authorSession({ trustedRootHex, warrant, authorSecretHex }) {
  const t = createTenuo({ trustedRoots: [T.publicKeyFromHex(trustedRootHex)] });
  return { t, session: t.sessionFromWire({ warrant, holderKey: T.holderKeyFromHex(authorSecretHex) }) };
}

/** Author: what a reviewer needs to approve this exact merge. */
export function requestApproval({ trustedRootHex, warrant, authorSecretHex, repo, pr, headSha }) {
  const { t, session } = authorSession({ trustedRootHex, warrant, authorSecretHex });
  return t.approvalRequest(session, TOOL, mergeArgs({ repo, pr, headSha }));
}

/**
 * Reviewer: sign an approval of the request, after checking it describes the
 * merge the reviewer actually reviewed.
 */
export function signApproval({ request, reviewerSecretHex, reviewerName, expect, ttlSeconds = 3600 }) {
  if (request.tool !== TOOL) throw new Error(`refusing to approve tool ${request.tool}`);
  const want = mergeArgs(expect);
  for (const k of Object.keys(want)) {
    if (String(request.args[k]) !== want[k]) throw new Error(`request ${k}=${request.args[k]} does not match the reviewed ${k}=${want[k]}`);
  }
  const mine = T.publicKeyFromHolderKey(T.holderKeyFromHex(reviewerSecretHex)).hex;
  if (mine === request.holderPublicKey) throw new Error("an agent cannot approve its own merge");
  // An approval never outlives the warrant it approves a call under.
  return T.signApproval(request, T.holderKeyFromHex(reviewerSecretHex), {
    externalId: reviewerName,
    ttlSeconds,
    warrantExpiresAt: request.warrantExpiresAt,
  });
}

/**
 * Author: ask to merge. Produces the warrant chain, a fresh proof-of-possession
 * over this exact merge, and the reviewers' approvals. Send it to the verifier
 * right away: the proof is only fresh for a short window.
 */
export function presentMerge({ trustedRootHex, warrant, authorSecretHex, repo, pr, headSha, approvals }) {
  const { t, session } = authorSession({ trustedRootHex, warrant, authorSecretHex });
  return t.present(session, TOOL, mergeArgs({ repo, pr, headSha }), { approvals });
}

/**
 * Verifier: authorize a presented merge with Tenuo's `verify()`, trusting only
 * the issuer key. The arguments come from the caller (who read them from
 * GitHub), never from the presentation. Resolves with the keys of the
 * approvals that satisfy the warrant, and when the earliest of them expires
 * (unix seconds; a merge authorized by them is good until then). Name
 * approvers from their keys, not from `externalId`, which each reviewer sets
 * for itself. Rejects with a Tenuo error code
 * (TENUO_APPROVAL_REQUIRED, TENUO_INSUFFICIENT_APPROVALS, TENUO_INVALID_POP,
 * TENUO_CONSTRAINT_VIOLATION, ...) otherwise.
 */
export async function authorizeMerge({ trustedRootHex, presented, repo, pr, headSha }) {
  const verifier = createTenuo({ trustedRoots: [T.publicKeyFromHex(trustedRootHex)] });
  const args = mergeArgs({ repo, pr, headSha });
  await verifier.verify(presented, TOOL, args);
  // Find the approvals that count on their own. The proof-of-possession is
  // checked again on each try, so this only narrows the list.
  const counted = [];
  for (const approval of presented.approvals ?? []) {
    try {
      await verifier.verify({ ...presented, approvals: [approval] }, TOOL, args);
      counted.push(T.inspectApproval(approval));
    } catch {
      // does not satisfy the warrant on its own
    }
  }
  if (counted.length === 0) {
    // Several approvals are needed together (min > 1): keep the valid ones.
    for (const approval of presented.approvals ?? []) {
      const info = T.inspectApproval(approval);
      if (info.signatureValid && !info.expired) counted.push(info);
    }
  }
  return {
    approverKeys: [...new Set(counted.map((a) => a.approverPublicKey))].sort(),
    expiresAt: Math.min(...counted.map((a) => a.expiresAt)),
  };
}

/** Present and verify in one process (tests, or a broker that holds both sides). */
export async function verifyMerge({ trustedRootHex, warrant, authorSecretHex, repo, pr, headSha, approvals }) {
  const presented = presentMerge({ trustedRootHex, warrant, authorSecretHex, repo, pr, headSha, approvals });
  return authorizeMerge({ trustedRootHex, presented, repo, pr, headSha });
}

export function inspectApproval(envelope) {
  return T.inspectApproval(envelope);
}

/** PR comment bodies the GitHub check reads. Comments carry no trust; signatures do. */
export function warrantComment({ warrant, agent }) {
  return [
    "<!-- tenuo:merge-warrant v1 -->",
    `Merge warrant for \`${agent}\`: merging needs a signed approval from another agent named in it.`,
    "",
    "```json",
    JSON.stringify({ warrant }),
    "```",
  ].join("\n");
}

export function approvalComment({ approval, reviewer, headSha }) {
  return [
    "<!-- tenuo:approval v1 -->",
    `Signed approval from \`${reviewer}\` for commit \`${headSha.slice(0, 7)}\`. A new push needs a new approval.`,
    "",
    "```json",
    JSON.stringify({ approval }),
    "```",
  ].join("\n");
}
