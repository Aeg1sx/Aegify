import { createHash } from "node:crypto";
import { AccessDenied } from "./project-access.ts";
import { decrypt } from "./crypto.ts";
import { FIXTURE_INPUT_BYTES, FIXTURE_RULE_BYTES, FIXTURE_SUITE_BYTES, FIXTURE_TIMEOUT_SECONDS, type FixtureInput } from "./rule-fixture-contract.ts";

export const fixtureDigest = (text: string) => "sha256:" + createHash("sha256").update(text, "utf8").digest("hex");
export function fixtureInput(value: unknown): FixtureInput {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new AccessDenied(400, "Provide ruleYaml and suiteJson strings.");
  const input = value as Record<string, unknown>;
  if (Object.keys(input).length !== 2 || typeof input.ruleYaml !== "string" || typeof input.suiteJson !== "string" || !input.ruleYaml.trim() || !input.suiteJson.trim() || !input.ruleYaml.isWellFormed() || !input.suiteJson.isWellFormed() || Buffer.byteLength(input.ruleYaml) > FIXTURE_RULE_BYTES || Buffer.byteLength(input.suiteJson) > FIXTURE_SUITE_BYTES) throw new AccessDenied(400, "Provide one rule within 128 KiB and fixture JSON within 2 MiB.");
  const result = { ruleYaml: input.ruleYaml, suiteJson: input.suiteJson };
  if (Buffer.byteLength(encodeFixtureInput(result)) > FIXTURE_INPUT_BYTES || Buffer.byteLength(fixtureWorkerInput(result)) > FIXTURE_INPUT_BYTES) throw new AccessDenied(400, "Fixture request exceeds 3 MiB.");
  return result;
}
export function encodeFixtureInput(input: FixtureInput): string {
  return JSON.stringify({ version: 1, timeoutSeconds: FIXTURE_TIMEOUT_SECONDS, ruleYaml: input.ruleYaml, suiteJson: input.suiteJson });
}
export function fixtureWorkerInput(input: FixtureInput): string {
  // Preserve submitted JSON bytes inside the trusted worker envelope. Python's
  // strict parser rejects duplicate keys, non-finite values and malformed JSON.
  return `{"rule_yaml":${JSON.stringify(input.ruleYaml)},"suite":${input.suiteJson},"timeout_seconds":${FIXTURE_TIMEOUT_SECONDS}}`;
}
export function restoreFixtureInput(job: { inputCiphertext: string | null; inputDigest: string; expiresAt: Date }, secret?: string, now = new Date()): FixtureInput {
  if (job.expiresAt <= now) throw new AccessDenied(410, "Saved fixture input has expired. Submit a new suite.");
  if (!job.inputCiphertext) throw new AccessDenied(409, "Saved fixture input is unavailable before its retention deadline.");
  try {
    if (job.inputCiphertext.length > FIXTURE_INPUT_BYTES * 2 + 128) throw new Error();
    const raw = decrypt(job.inputCiphertext, secret);
    if (Buffer.byteLength(raw) > FIXTURE_INPUT_BYTES || fixtureDigest(raw) !== job.inputDigest) throw new Error();
    const value = JSON.parse(raw);
    if (value.version !== 1 || value.timeoutSeconds !== FIXTURE_TIMEOUT_SECONDS || Object.keys(value).length !== 4) throw new Error();
    return fixtureInput({ ruleYaml: value.ruleYaml, suiteJson: value.suiteJson });
  } catch { throw new AccessDenied(409, "Saved fixture input could not be verified. Check the encryption key and record integrity."); }
}
