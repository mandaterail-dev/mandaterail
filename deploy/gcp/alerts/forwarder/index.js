// R48-P2-2 / R49: Pub/Sub -> ntfy, outside Google. Handles three payloads on the topic:
//   - a log-sink entry (protoPayload), - a Cloud Monitoring Pub/Sub incident ({incident}), - the daily heartbeat.
// NTFY_URL and HC_URL come from Secret Manager; they are capabilities and are never logged.
const functions = require("@google-cloud/functions-framework");

functions.cloudEvent("forward", async (ev) => {
  const raw = Buffer.from(ev.data?.message?.data ?? "", "base64").toString("utf8");
  let e = {};
  try { e = JSON.parse(raw); } catch { /* page anyway with the raw text */ }
  const hb = e.heartbeat === true;
  let title, body;
  if (hb) { title = "mr-signer GCP alerts heartbeat"; body = "forwarder alive"; }
  else if (e.incident) {
    const i = e.incident;
    title = `GCP alert ${i.policy_name ?? "?"} (${i.state ?? "?"})`;
    body = JSON.stringify({ policy: i.policy_name, condition: i.condition_name, state: i.state, summary: i.summary, url: i.url }).slice(0, 3500);
  } else {
    const p = e.protoPayload ?? {};
    title = `GCP ${p.methodName ?? "event"} by ${p.authenticationInfo?.principalEmail ?? "?"}`;
    body = JSON.stringify({
      method: p.methodName, service: p.serviceName, principal: p.authenticationInfo?.principalEmail,
      callerIp: p.requestMetadata?.callerIp, callerNetwork: p.requestMetadata?.callerNetwork, resource: p.resourceName, ts: e.timestamp, insertId: e.insertId,
    }).slice(0, 3500);
    if (!e.protoPayload) body = raw.slice(0, 3500);
  }
  const r = await fetch(process.env.NTFY_URL, {
    method: "POST", body, redirect: "error",
    headers: { Title: title.slice(0, 200).replace(/[^\x20-\x7e]/g, "?"), Priority: hb ? "min" : "urgent", Tags: hb ? "heartbeat" : "rotating_light" },
  });
  if (!r.ok) throw new Error(`ntfy ${r.status}`); // non-2xx -> Pub/Sub retries
  if (hb && process.env.HC_URL) {
    const h = await fetch(process.env.HC_URL, { redirect: "error" });
    if (!h.ok) throw new Error(`healthchecks ${h.status}`);
  }
});
