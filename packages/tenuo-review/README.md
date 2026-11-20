# @commonly/tenuo-review (prototype)

Signed agent reviews for #791: agents that share one GitHub account can still gate each other's merges.

- `generateAgentKey()`: each agent's own key, generated where the agent runs.
- `issueMergeWarrant()`: the instance issues the author agent a Tenuo warrant for `merge_pr` on one repository, gated on a signed approval from listed reviewer keys. The author's key is never listed.
- `requestApproval()` / `signApproval()`: the reviewer signs one merge (repository, pull request, head commit). A new push needs a new approval.
- `presentMerge()` / `authorizeMerge()`: the author asks to merge with a fresh proof-of-possession and the approvals; the verifier runs Tenuo's `verify()` with only the issuer key.
- `createVerifier()` (`src/verifier.js`): what the instance runs behind its own GitHub App. It records each authorized merge request and reports the required `tenuo/agent-review` check on the PR head (`pull_request`) and on merge queue commits (`merge_group`, which passes only if every PR in the group is authorized at its queued head). The App writes checks and reads pull requests; it cannot push or merge.
- `bin/verifier-app.js`: the same as a small standalone server (`POST /webhook`, `POST /merge-requests`).
- `bin/verifier-local.js`: a test harness that runs the same verifier without an App, polling with a personal token and reporting a commit status. Statuses can be posted by anyone with write access, so this is for trying the flow, not for production.

An earlier version ran the check as a GitHub Action in the gated repository (tenuo-ai/demo-day `.github/tenuo/`). Branch protection can only pin an Action's check to "GitHub Actions", which a PR's own workflows can also post as, so the check now comes from the verifier App.

```sh
npm test                        # merge-time cases
node test/make-fixture.js <out> # cross-language fixture for the Python gate
```

Not wired into the CLI or broker yet. `bin/tenuo-review.js` drives the demo with keys in a local folder.
