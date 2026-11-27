import assert from "node:assert/strict";
import test from "node:test";
import { remediationDiff } from "./remediation-diff.ts";

test("fix comparison preserves both excerpts through repeated lines, whitespace and blank lines", () => {
  for (const [a, b] of [["a\nb\na\nd\n", "a\nc\na\nd"], ["", "x"], ["x", ""], [" a\r\nb", "a\nb"]]) {
    const rows = remediationDiff(a, b)!;
    assert.equal(rows.filter((r) => r.original !== null).map((r) => r.text).join("\n"), a.replaceAll("\r\n", "\n"));
    assert.equal(rows.filter((r) => r.proposed !== null).map((r) => r.text).join("\n"), b);
  }
  assert.deepEqual(remediationDiff("a\nb\nc", "a\nz\nc")?.map((r) => r.kind), ["context", "remove", "add", "context"]);
  assert.equal(remediationDiff("x\n".repeat(400), "y\n".repeat(400)), null);
  assert.equal(remediationDiff("x".repeat(40_001), "y"), null);
});
