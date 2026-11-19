// The verifier the instance runs. It is the only thing that reports the
// required `tenuo/agent-review` check, under its own GitHub App, which can
// write checks and read pull requests but cannot push or merge.
//
// 1. An agent asks to merge: it sends a presented `merge_pr` call (warrant
//    chain, fresh proof-of-possession, reviewers' approvals). The verifier
//    checks the pull request is open at that head, runs Tenuo's `verify()`,
//    records "PR n at commit x is authorized to merge", and reports success
//    on that commit.
// 2. A new push gets a new head commit, so no record: the check fails until
//    the agent asks again with an approval of the new head.
// 3. The merge queue asks for the check on its own commit (`merge_group`). It
//    passes only if every pull request in that group has a record at the
//    head commit the queue took.

import { authorizeMerge, mergeArgs } from "./index.js";

export const CHECK_NAME = "tenuo/agent-review";

export class MergeRequestRejected extends Error {
  constructor(reason, code) {
    super(reason);
    this.code = code;
  }
}

export function memoryStore() {
  const records = new Map();
  return {
    get: (key) => records.get(key),
    set: (key, value) => records.set(key, value),
  };
}

const recordKey = (repo, pr, headSha) => `${repo.toLowerCase()}#${pr}@${headSha}`;

export function createVerifier({ trustedRootHex, github, store = memoryStore(), checkName = CHECK_NAME, log = () => {} }) {
  async function report(repo, headSha, passed, title, summary) {
    await github.createCheckRun(repo, {
      name: checkName,
      head_sha: headSha,
      status: "completed",
      conclusion: passed ? "success" : "failure",
      output: { title: title.slice(0, 250), summary: summary || title },
    });
    log(`${repo}@${headSha.slice(0, 7)} ${passed ? "success" : "failure"}: ${title}`);
  }

  function recordFor(repo, pr, headSha) {
    return store.get(recordKey(repo, pr, headSha));
  }

  return {
    /** Step 1. Throws MergeRequestRejected; reports success only after verify(). */
    async requestMerge({ repo, pr, headSha, presented }) {
      try {
        mergeArgs({ repo, pr, headSha });
      } catch (e) {
        throw new MergeRequestRejected(e.message, "BAD_REQUEST");
      }
      const pull = await github.getPull(repo, pr);
      if (pull.state !== "open") throw new MergeRequestRejected("pull request is not open", "NOT_OPEN");
      if (pull.head.sha !== headSha) {
        throw new MergeRequestRejected(`head ${headSha.slice(0, 7)} is not the pull request's current head ${pull.head.sha.slice(0, 7)}`, "STALE_HEAD");
      }
      let result;
      try {
        result = await authorizeMerge({ trustedRootHex, presented, repo, pr, headSha });
      } catch (e) {
        throw new MergeRequestRejected(e.message, e.code ?? "DENIED");
      }
      const record = { repo, pr: Number(pr), headSha, approvers: result.approvers, verifiedAt: new Date().toISOString() };
      store.set(recordKey(repo, pr, headSha), record);
      await report(repo, headSha, true, `merge authorized: approved by ${result.approvers.join(", ")}`);
      return record;
    },

    /** Step 2. `pull_request` webhook: opened, reopened, synchronize. */
    async onPullRequest(payload) {
      if (!["opened", "reopened", "synchronize"].includes(payload.action)) return;
      const repo = payload.repository.full_name;
      const pr = payload.pull_request.number;
      const headSha = payload.pull_request.head.sha;
      const record = recordFor(repo, pr, headSha);
      if (record) {
        await report(repo, headSha, true, `merge authorized: approved by ${record.approvers.join(", ")}`);
      } else {
        await report(repo, headSha, false, "no authorized merge request for this commit",
          "The author agent asks to merge with its warrant and a reviewer's signed approval of this commit. A new push needs a new approval.");
      }
    },

    /** Step 3. `merge_group` webhook, action `checks_requested`. */
    async onMergeGroup(payload) {
      if (payload.action !== "checks_requested") return;
      const repo = payload.repository.full_name;
      const group = payload.merge_group;
      const branch = group.base_ref.replace(/^refs\/heads\//, "");
      const entries = await github.mergeQueueEntries(repo, branch);
      const mine = entries.find((e) => e.headSha === group.head_sha);
      if (!mine) {
        await report(repo, group.head_sha, false, "could not match this merge group to the merge queue");
        return;
      }
      // The group commit for an entry contains that entry and every entry ahead of it.
      const included = entries.filter((e) => e.position <= mine.position);
      const missing = included.filter((e) => !recordFor(repo, e.pr, e.prHeadSha));
      if (missing.length > 0) {
        const list = missing.map((e) => `#${e.pr} at ${String(e.prHeadSha).slice(0, 7)}`).join(", ");
        await report(repo, group.head_sha, false, `no authorized merge request for ${list}`);
        return;
      }
      const names = included.map((e) => `#${e.pr} (${recordFor(repo, e.pr, e.prHeadSha).approvers.join(", ")})`).join("; ");
      await report(repo, group.head_sha, true, `merge authorized for ${names}`);
    },
  };
}
