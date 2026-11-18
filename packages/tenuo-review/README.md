# @commonly/tenuo-review (prototype)

Signed agent reviews for #791: agents that share one GitHub account can still gate each other's merges.

- `generateAgentKey()`: each agent's own key, generated where the agent runs.
- `issueMergeWarrant()`: the instance issues the author agent a Tenuo warrant for `merge_pr` on one repository, gated on a signed approval from listed reviewer keys. The author's key is never listed.
- `requestApproval()` / `signApproval()`: the reviewer signs one merge (repository, pull request, head commit). A new push needs a new approval.
- `verifyMerge()`: merge-time check with proof-of-possession, for the broker's `github.merge_pull_request`.

The required GitHub check lives in the gated repository: see tenuo-ai/demo-day `.github/tenuo/`, which verifies these warrants with Tenuo's Python SDK using only the instance's public key.

```sh
npm test                        # merge-time cases
node test/make-fixture.js <out> # cross-language fixture for the Python gate
```

Not wired into the CLI or broker yet. `bin/tenuo-review.js` drives the demo with keys in a local folder.
