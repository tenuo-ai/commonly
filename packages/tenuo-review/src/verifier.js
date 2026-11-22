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
//
// Pull requests the agent account did not open (people, outside contributors)
// pass: this check is about agents reviewing agents. A record is good until
// the earliest approval it rests on expires, and approvals never outlive the
// warrant. Approvers are named from their keys, as the instance knows them.

import { authorizeMerge, mergeArgs } from "./index.js";

export const CHECK_NAME = "tenuo/agent-review";

export class MergeRequestRejected extends Error {
  constructor(reason, code) {
    super(reason);
    this.code = code;
  }
}

/**
 * Settings from the environment:
 *   TENUO_REVIEW_AGENT_LOGINS  comma-separated accounts agents open PRs from
 *   TENUO_REVIEW_REVIEWERS     comma-separated name=publicKeyHex, for check titles
 */
export function verifierConfig(env) {
  const list = (v) => String(v ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  const reviewerNames = {};
  for (const pair of list(env.TENUO_REVIEW_REVIEWERS)) {
    const [name, key] = pair.split("=");
    if (name && key) reviewerNames[key.toLowerCase()] = name;
  }
  return { agentLogins: list(env.TENUO_REVIEW_AGENT_LOGINS), reviewerNames };
}

export function memoryStore() {
  const records = new Map();
  return {
    get: (key) => records.get(key),
    set: (key, value) => records.set(key, value),
  };
}

const recordKey = (repo, pr, headSha) => `${repo.toLowerCase()}#${pr}@${headSha}`;

const normalizeLogin = (login) => String(login ?? "").toLowerCase().replace(/^app\//, "").replace(/\[bot\]$/, "");

/**
 * `agentLogins`: the GitHub account(s) agents open pull requests from. Pull
 * requests from any other account pass. Empty means every pull request needs
 * an agent review.
 * `reviewerNames`: reviewer public key (hex) -> name for check titles.
 */
export function createVerifier({
  trustedRootHex, github, store = memoryStore(), checkName = CHECK_NAME, log = () => {},
  agentLogins = [], reviewerNames = {}, now = () => Date.now(),
}) {
  const agents = new Set(agentLogins.map(normalizeLogin));
  // Unknown author (no login given): treat as an agent, so the check is not skipped by accident.
  const byAgent = (login) => agents.size === 0 || !login || agents.has(normalizeLogin(login));
  const names = Object.fromEntries(Object.entries(reviewerNames).map(([k, v]) => [k.toLowerCase(), v]));
  const nameOf = (key) => names[String(key).toLowerCase()] ?? `key ${String(key).slice(0, 8)}`;
  const NOT_AGENT = "not opened by an agent: agent review not required";

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

  /** The record for this commit, or why there is none that counts. */
  async function recordFor(repo, pr, headSha) {
    const record = await store.get(recordKey(repo, pr, headSha));
    if (!record) return { missing: "no authorized merge request" };
    if (!(record.expiresAt * 1000 > now())) return { missing: "authorization expired, ask again" };
    return { record };
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
      const record = {
        repo, pr: Number(pr), headSha,
        approverKeys: result.approverKeys,
        approvers: result.approverKeys.map(nameOf),
        expiresAt: result.expiresAt,
        verifiedAt: new Date(now()).toISOString(),
      };
      await store.set(recordKey(repo, pr, headSha), record);
      await report(repo, headSha, true, `merge authorized: approved by ${record.approvers.join(", ")}`);
      return record;
    },

    /** Step 2. `pull_request` webhook: opened, reopened, synchronize. */
    async onPullRequest(payload) {
      if (!["opened", "reopened", "synchronize"].includes(payload.action)) return;
      const repo = payload.repository.full_name;
      const pr = payload.pull_request.number;
      const headSha = payload.pull_request.head.sha;
      if (!byAgent(payload.pull_request.user?.login)) {
        await report(repo, headSha, true, NOT_AGENT);
        return;
      }
      const { record, missing } = await recordFor(repo, pr, headSha);
      if (record) {
        await report(repo, headSha, true, `merge authorized: approved by ${record.approverKeys.map(nameOf).join(", ")}`);
      } else {
        await report(repo, headSha, false, `${missing} for this commit`,
          "The author agent asks to merge with its warrant and a reviewer's signed approval of this commit. A new push needs a new approval.");
      }
    },

    /** Step 3. `merge_group` webhook, action `checks_requested`. */
    async onMergeGroup(payload) {
      if (payload.action !== "checks_requested") return;
      const repo = payload.repository.full_name;
      const group = payload.merge_group;
      // Any failure to decide reports a failure, so the queue drops the group
      // at once instead of waiting for the check to time out.
      try {
        const branch = group.base_ref.replace(/^refs\/heads\//, "");
        const entries = await github.mergeQueueEntries(repo, branch);
        const mine = entries.find((e) => e.headSha === group.head_sha);
        if (!mine) {
          await report(repo, group.head_sha, false, "could not match this merge group to the merge queue");
          return;
        }
        // The group commit for an entry contains that entry and every entry ahead of it.
        const included = entries.filter((e) => e.position <= mine.position);
        const verdicts = [];
        for (const e of included) {
          if (!byAgent(e.authorLogin)) verdicts.push({ e, note: "not opened by an agent" });
          else verdicts.push({ e, ...(await recordFor(repo, e.pr, e.prHeadSha)) });
        }
        const failed = verdicts.filter((v) => v.missing);
        if (failed.length > 0) {
          const list = failed.map((v) => `#${v.e.pr} at ${String(v.e.prHeadSha).slice(0, 7)} (${v.missing})`).join(", ");
          await report(repo, group.head_sha, false, `not authorized: ${list}`);
          return;
        }
        const names = verdicts.map((v) => `#${v.e.pr} (${v.note ?? v.record.approverKeys.map(nameOf).join(", ")})`).join("; ");
        await report(repo, group.head_sha, true, `merge authorized for ${names}`);
      } catch (e) {
        log(`merge group ${group.head_sha.slice(0, 7)}: ${e.message}`);
        await report(repo, group.head_sha, false, "could not check this merge group, try again", String(e.message).slice(0, 1000));
      }
    },
  };
}
