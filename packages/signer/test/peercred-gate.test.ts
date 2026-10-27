import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const root = path.resolve(__dirname, "../../..");
describe("R43-P2-4 helper socket: peer-uid gate and systemd socket", () => {
  it("mr-peercred-gate: the allowed uid passes, any other uid is refused before a byte is read", async () => {
    const { stdout } = await promisify(execFile)("bash", [path.join(root, "ops/signer/test-gate.sh")]);
    expect(stdout).toMatch(/allowed uid passes, other uid refused/);
  });
  it("the socket unit is mr-piv:mr-signer 0660, Accept=yes, one connection; the service runs the gate", () => {
    const sock = readFileSync(path.join(root, "deploy/signer/mr-piv-sign.socket"), "utf8");
    for (const l of ["SocketUser=mr-piv", "SocketGroup=mr-signer", "SocketMode=0660", "Accept=yes", "MaxConnections=1"]) expect(sock).toContain(l);
    const svc = readFileSync(path.join(root, "deploy/signer/mr-piv-sign@.service"), "utf8");
    expect(svc).toMatch(/ExecStart=\/usr\/local\/bin\/mr-peercred-gate @MR_SIGNER_UID@ /);
    expect(svc).toContain("User=mr-piv");
    expect(svc).toContain("IPAddressDeny=any");
  });
});
