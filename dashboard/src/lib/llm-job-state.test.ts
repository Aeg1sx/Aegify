import assert from "node:assert/strict";
import test from "node:test";

import {
  isLlmJobTerminal,
  llmJobTerminalStatus,
} from "./llm-job-state.ts";

test("classifies complete, partial, and failed AI review jobs", () => {
  assert.equal(llmJobTerminalStatus(10, 10, 0), "completed");
  assert.equal(llmJobTerminalStatus(10, 7, 1), "partial");
  assert.equal(llmJobTerminalStatus(10, 0, 1), "failed");
  assert.equal(llmJobTerminalStatus(0, 0, 0), "completed");
});

test("recognizes every terminal AI review state", () => {
  assert.equal(isLlmJobTerminal("completed"), true);
  assert.equal(isLlmJobTerminal("partial"), true);
  assert.equal(isLlmJobTerminal("failed"), true);
  assert.equal(isLlmJobTerminal("running"), false);
});
