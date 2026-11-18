// Writes a cross-language fixture for the Python gate in the gated repo.
import { writeFileSync } from "node:fs";
import { createTenuo } from "@tenuo/core";
import { generateAgentKey, generateIssuerKey, issueMergeWarrant, requestApproval, signApproval, warrantComment, approvalComment } from "../src/index.js";
const repo = "tenuo-ai/demo-day", pr = 7, sha = "a".repeat(40), sha2 = "b".repeat(40);
const issuer = generateIssuerKey(), rogue = generateIssuerKey();
const author = generateAgentKey(), reviewer = generateAgentKey(), outsider = generateAgentKey();
const LONG = 90 * 86400; // protocol maximum; regenerate the committed fixture before it expires
const warrant = issueMergeWarrant({ issuerSecretHex: issuer.secretHex, authorPublicHex: author.publicHex, reviewerPublicHex: [reviewer.publicHex], repo, ttlSeconds: LONG });
const rogueWarrant = issueMergeWarrant({ issuerSecretHex: rogue.secretHex, authorPublicHex: author.publicHex, reviewerPublicHex: [reviewer.publicHex], repo, ttlSeconds: LONG });
const base = { trustedRootHex: issuer.publicHex, warrant, authorSecretHex: author.secretHex, repo, pr };
const req = requestApproval({ ...base, headSha: sha });
const approve = (k, n, r = req, h = sha) => signApproval({ request: r, reviewerSecretHex: k.secretHex, reviewerName: n, expect: { repo, pr, headSha: h }, ttlSeconds: LONG });
const self = createTenuo.signApproval(req, createTenuo.holderKeyFromHex(author.secretHex), { externalId: "pod-architect", ttlSeconds: LONG });
const rogueReq = requestApproval({ trustedRootHex: rogue.publicHex, warrant: rogueWarrant, authorSecretHex: author.secretHex, repo, pr, headSha: sha });
const c = (approval, who) => approvalComment({ approval, reviewer: who, headSha: sha });
writeFileSync(process.argv[2], JSON.stringify({
  trusted_roots: [issuer.publicHex], repo, pr, head_sha: sha, other_sha: sha2,
  comments: {
    warrant: warrantComment({ warrant, agent: "pod-architect" }),
    rogue_warrant: warrantComment({ warrant: rogueWarrant, agent: "pod-architect" }),
    good: c(approve(reviewer, "sprint-review"), "sprint-review"),
    self: c(self, "pod-architect"),
    outsider: c(approve(outsider, "outsider"), "outsider"),
    rogue_good: c(approve(reviewer, "sprint-review", rogueReq), "sprint-review"),
  },
}, null, 1));
