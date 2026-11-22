#!/usr/bin/env node
// Prototype verifier server. In Commonly this would be a backend route plus a
// webhook handler; here it is a small standalone server.
//
//   POST /webhook          GitHub App webhooks (pull_request, merge_group)
//   POST /merge-requests   { repo, pr, headSha, presented } from an agent
//
// Env: TENUO_REVIEW_APP_ID, TENUO_REVIEW_APP_KEY (PEM file path),
//      TENUO_REVIEW_WEBHOOK_SECRET, TENUO_REVIEW_TRUSTED_ROOT (issuer public key hex),
//      PORT (default 8787), TENUO_REVIEW_STORE (optional JSON file),
//      TENUO_REVIEW_AGENT_LOGINS, TENUO_REVIEW_REVIEWERS (see src/verifier.js).
import { createServer } from "node:http";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createGitHubApp, verifyWebhookSignature } from "../src/github-app.js";
import { createVerifier, verifierConfig, MergeRequestRejected } from "../src/verifier.js";

const env = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is required`);
  return v;
};

function fileStore(path) {
  const records = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {};
  return {
    get: (key) => records[key],
    set: (key, value) => {
      records[key] = value;
      writeFileSync(path, JSON.stringify(records, null, 1), { mode: 0o600 });
    },
  };
}

const github = createGitHubApp({ appId: env("TENUO_REVIEW_APP_ID"), privateKeyPem: readFileSync(env("TENUO_REVIEW_APP_KEY"), "utf8") });
const secret = env("TENUO_REVIEW_WEBHOOK_SECRET");
const verifier = createVerifier({
  trustedRootHex: env("TENUO_REVIEW_TRUSTED_ROOT"),
  github,
  ...(process.env.TENUO_REVIEW_STORE ? { store: fileStore(process.env.TENUO_REVIEW_STORE) } : {}),
  log: (line) => console.log(new Date().toISOString(), line),
  ...verifierConfig(process.env),
});

const MAX_BODY = 1024 * 1024;
const readBody = (req) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) reject(new Error("body too large"));
      else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });

const send = (res, status, body) => {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
};

createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/healthz") return send(res, 200, { ok: true });
    if (req.method !== "POST") return send(res, 404, { error: "not found" });
    const raw = await readBody(req);
    if (req.url === "/webhook") {
      if (!verifyWebhookSignature({ secret, rawBody: raw, signatureHeader: req.headers["x-hub-signature-256"] })) {
        return send(res, 401, { error: "bad signature" });
      }
      const event = req.headers["x-github-event"];
      const payload = JSON.parse(raw.toString("utf8"));
      if (event === "pull_request") await verifier.onPullRequest(payload);
      else if (event === "merge_group") await verifier.onMergeGroup(payload);
      return send(res, 200, { ok: true });
    }
    if (req.url === "/merge-requests") {
      const body = JSON.parse(raw.toString("utf8"));
      const record = await verifier.requestMerge(body);
      return send(res, 200, record);
    }
    return send(res, 404, { error: "not found" });
  } catch (e) {
    if (e instanceof MergeRequestRejected) return send(res, 403, { error: e.message, code: e.code });
    console.error(new Date().toISOString(), e);
    return send(res, 500, { error: "internal error" });
  }
}).listen(Number(process.env.PORT ?? 8787), () => console.log(`verifier listening on ${process.env.PORT ?? 8787}`));
