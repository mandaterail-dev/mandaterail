/**
 * R50-P2: GCP access token for the verifier's reconcile reads, minted from the verifier's AWS instance role via
 * Workload Identity Federation (deploy/gcp/alerts/wif.tf). No GCP key file exists anywhere.
 *
 *   IMDSv2 role creds → SigV4-signed sts:GetCallerIdentity (not sent to AWS; handed to Google as the subject
 *   token) → sts.googleapis.com token exchange → iamcredentials generateAccessToken for the read-only
 *   mr-reconcile-reader SA (roles/logging.privateLogViewer only, scope logging.read) → MR_GCP_TOKEN_FILE (0600,
 *   atomic). Run by mr-gcp-token.timer every 20 min; tokens live 60 min. Errors never include tokens.
 */
import { closeSync, constants, fsyncSync, openSync, renameSync, writeSync } from "node:fs";
import { sigV4 } from "../sinks/s3.js";

type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ status: number; json(): Promise<unknown>; text(): Promise<string> }>;
export interface GcpTokenConfig {
  awsRegion: string; roleName: string;
  /** projects/<NUMBER>/locations/global/workloadIdentityPools/<pool>/providers/<provider> */
  wifProvider: string;
  readerSa: string; // mr-reconcile-reader@<project>.iam.gserviceaccount.com
  imdsBase?: string; stsBase?: string; iamBase?: string; timeoutMs?: number;
}
export class GcpTokenError extends Error {}

export async function mintGcpToken(c: GcpTokenConfig, f: Fetch = fetch as unknown as Fetch, now = () => new Date()): Promise<{ token: string; expiresAt: number }> {
  if (!/^projects\/\d+\/locations\/global\/workloadIdentityPools\/[a-z0-9-]+\/providers\/[a-z0-9-]+$/.test(c.wifProvider)) throw new GcpTokenError("wifProvider is not a full provider resource name");
  if (!/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/.test(c.readerSa)) throw new GcpTokenError("readerSa is not a service account email");
  const sig = () => AbortSignal.timeout(c.timeoutMs ?? 10_000);
  const call = async (u: string, i: Parameters<Fetch>[1], what: string) => { try { return await f(u, { ...i, signal: sig() }); } catch (e) { throw new GcpTokenError(`${what} unreachable (${(e as Error).name})`); } };
  // 1. IMDSv2 role credentials (pinned role)
  const base = c.imdsBase ?? "http://169.254.169.254";
  const t = await call(`${base}/latest/api/token`, { method: "PUT", headers: { "X-aws-ec2-metadata-token-ttl-seconds": "300" } }, "IMDSv2");
  if (t.status !== 200) throw new GcpTokenError(`IMDSv2 token status ${t.status}`);
  const h = { "X-aws-ec2-metadata-token": (await t.text()).trim() };
  const cr = await call(`${base}/latest/meta-data/iam/security-credentials/${c.roleName}`, { headers: h }, "IMDSv2");
  const j = (cr.status === 200 ? await cr.json() : null) as { Code?: string; AccessKeyId?: string; SecretAccessKey?: string; Token?: string } | null;
  if (!j || j.Code !== "Success" || !j.AccessKeyId || !j.SecretAccessKey || !j.Token) throw new GcpTokenError(`IMDSv2 role credentials unavailable (status ${cr.status})`);
  // 2. the signed GetCallerIdentity request is the subject token
  const audience = `//iam.googleapis.com/${c.wifProvider}`;
  const url = new URL(`https://sts.${c.awsRegion}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15`);
  const signed = sigV4({ region: c.awsRegion, accessKeyId: j.AccessKeyId, secretAccessKey: j.SecretAccessKey }, "POST", url,
    { "x-amz-security-token": j.Token, "x-goog-cloud-target-resource": audience }, "", now(), "sts");
  const subject = encodeURIComponent(JSON.stringify({ url: url.toString(), method: "POST", headers: Object.entries(signed).map(([key, value]) => ({ key, value })) }));
  // 3. Google STS exchange
  const form = new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", audience, scope: "https://www.googleapis.com/auth/cloud-platform",
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token", subject_token_type: "urn:ietf:params:aws:token-type:aws4_request", subject_token: subject });
  const s = await call(`${c.stsBase ?? "https://sts.googleapis.com"}/v1/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form.toString() }, "Google STS");
  if (s.status !== 200) throw new GcpTokenError(`Google STS status ${s.status}`);
  const fed = ((await s.json()) as { access_token?: string }).access_token;
  if (!fed) throw new GcpTokenError("Google STS returned no token");
  // 4. impersonate the read-only reader SA, narrow scope
  const g = await call(`${c.iamBase ?? "https://iamcredentials.googleapis.com"}/v1/projects/-/serviceAccounts/${c.readerSa}:generateAccessToken`, {
    method: "POST", headers: { authorization: `Bearer ${fed}`, "content-type": "application/json" },
    body: JSON.stringify({ scope: ["https://www.googleapis.com/auth/logging.read"], lifetime: "3600s" }) }, "IAM Credentials");
  if (g.status !== 200) throw new GcpTokenError(`generateAccessToken status ${g.status}`);
  const r = (await g.json()) as { accessToken?: string; expireTime?: string };
  if (!r.accessToken || !Number.isFinite(Date.parse(r.expireTime ?? ""))) throw new GcpTokenError("generateAccessToken returned no token");
  return { token: r.accessToken, expiresAt: Date.parse(r.expireTime!) };
}

/** Atomic 0600 write (tmp + fsync + rename). */
export function writeTokenFile(file: string, token: string): void {
  const tmp = `${file}.tmp`;
  const fd = openSync(tmp, constants.O_CREAT | constants.O_TRUNC | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { writeSync(fd, token); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(tmp, file);
}

if (process.argv[1] && /verifier[\\/]gcp-token\.(ts|js)$/.test(process.argv[1])) {
  const env = process.env;
  const cfg: GcpTokenConfig = { awsRegion: env.MR_AWS_REGION ?? "", roleName: env.MR_AWS_ROLE ?? "", wifProvider: env.MR_GCP_WIF_PROVIDER ?? "", readerSa: env.MR_GCP_READER_SA ?? "" };
  mintGcpToken(cfg).then(({ token, expiresAt }) => { writeTokenFile(env.MR_GCP_TOKEN_FILE ?? "", token); process.stdout.write(`gcp token refreshed, expires ${new Date(expiresAt).toISOString()}\n`); },
    (e) => { process.stderr.write(`gcp token refresh failed: ${(e as Error).message}\n`); process.exit(1); });
}
