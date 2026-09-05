import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAgentBlueprint,
  SECURITY_AGENTS,
  validateCveInputs,
  type AgentScanInput,
} from "./agent-contract.ts";
import { validateHarnessEvidence } from "./agent-evidence.ts";

function scan(runtimeObserved = false): AgentScanInput {
  return {
    id: "scan-fixture",
    repository: "fixture/api",
    workspaceSnapshot: `sha256:${"b".repeat(64)}`,
    findings: [{
      id: "finding-1",
      ruleId: "AEG-CMD-001",
      severity: "high",
      evidenceState: "reachable",
      filePath: "src/handler.py",
      lineStart: 19,
      message: "Untrusted input reaches command execution",
      remediation: "Use an argv allowlist.",
      evidenceId: "static-fixture-1",
      callChain: JSON.stringify([
        { function: "api.run", filePath: "src/handler.py", line: 10 },
        { function: "service.execute", filePath: "src/handler.py", line: 19 },
      ]),
    }],
    endpoints: [{
      path: "/run",
      method: "POST",
      handlerFunction: "api.run",
      filePath: "src/handler.py",
      framework: "fastapi",
      authRequired: false,
      calledByFrontend: true,
      exposedViaGateway: true,
      runtimeObserved,
    }],
  };
}

test("agent blueprint exposes six Korean agents and approval-gated dynamic work", () => {
  const result = buildAgentBlueprint(scan(), "deep");
  assert.equal(result.status, "awaiting_approval");
  assert.deepEqual(result.stages.map((stage) => stage.agentName), [
    "해태", "매눈", "살쾡이", "거북선", "장승", "한울",
  ]);
  assert.equal(SECURITY_AGENTS.length, 6);
  const dynamic = result.stages.find((stage) => stage.role === "dynamic")!;
  assert.equal(dynamic.status, "waiting_approval");
  assert.equal(dynamic.dynamicPlans[0].targetOrigin, "http://127.0.0.1");
  assert.equal(dynamic.dynamicPlans[0].requiresApproval, true);
  assert.equal(dynamic.dynamicPlans[0].destructive, false);
  assert.match(result.artifactDigest, /^sha256:[0-9a-f]{64}$/);
});

test("runtime observation removes an unnecessary execution plan without proving impact", () => {
  const result = buildAgentBlueprint(scan(true), "lite");
  assert.equal(result.status, "completed");
  const staticStage = result.stages.find((stage) => stage.role === "static")!;
  assert.equal(staticStage.reachability[0].runtimeObserved, true);
  assert.equal(staticStage.reachability[0].impactProven, false);
  const dynamic = result.stages.find((stage) => stage.role === "dynamic")!;
  assert.equal(dynamic.dynamicPlans.length, 0);
});

test("CVE parsing and assessment retain evidence boundaries", () => {
  const cves = validateCveInputs([
    {
      cveId: "cve-2026-12345",
      dependencyPresent: true,
      versionAffected: true,
      componentReachable: false,
    },
  ]);
  const result = buildAgentBlueprint(scan(true), "deep", cves);
  const cve = result.stages.find((stage) => stage.role === "cve")!;
  assert.equal(cve.cveAssessments[0].applicability, "version_exposed");
  assert.throws(() => validateCveInputs([{ cveId: "not-a-cve" }]), /invalid CVE/);

  const runtimeScan = scan(true);
  runtimeScan.endpoints[0].runtimeEvidence = JSON.stringify([{ id: "runtime-fixture-1" }]);
  const proofClaims = validateCveInputs([
    {
      cveId: "CVE-2026-12346",
      dependencyPresent: true,
      versionAffected: true,
      componentReachable: true,
      runtimeVerified: true,
      evidenceIds: ["forged-runtime-id"],
    },
    {
      cveId: "CVE-2026-12347",
      dependencyPresent: true,
      versionAffected: true,
      componentReachable: true,
      runtimeVerified: true,
      evidenceIds: ["runtime-fixture-1"],
    },
  ]);
  const proofResult = buildAgentBlueprint(runtimeScan, "deep", proofClaims);
  const assessments = proofResult.stages.find((stage) => stage.role === "cve")!.cveAssessments;
  assert.equal(assessments[0].applicability, "reachable");
  assert.deepEqual(assessments[0].missingEvidence, [
    "approved runtime evidence bound to this scan",
  ]);
  assert.equal(assessments[1].applicability, "exploitable_in_fixture");
});

test("harness evidence requires execution, image pinning, and output digests", () => {
  const valid = {
    contract_version: 1,
    plan_name: "owned fixture",
    status: "passed",
    executed: true,
    image: `fixture@sha256:${"a".repeat(64)}`,
    approval_scope_sha256: "f".repeat(64),
    workspace_sha256: "b".repeat(64),
    policy_sha256: "c".repeat(64),
    steps: [{
      id: "verify",
      status: "passed",
      command: ["python3", "test.py"],
      stdout_sha256: "d".repeat(64),
      stderr_sha256: "e".repeat(64),
    }],
  };
  assert.equal(validateHarnessEvidence(valid).status, "passed");
  assert.throws(
    () => validateHarnessEvidence({ ...valid, executed: false }),
    /executed harness/,
  );
  assert.throws(
    () => validateHarnessEvidence({ ...valid, image: "fixture:latest" }),
    /pinned/,
  );
  assert.throws(
    () => validateHarnessEvidence({ ...valid, approval_scope_sha256: "missing" }),
    /approval_scope_sha256/,
  );
});
