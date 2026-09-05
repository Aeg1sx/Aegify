import assert from "node:assert/strict";
import test from "node:test";
import { ALLOWED_SETTINGS, SECRET_SETTINGS, publicSetting, settingsChanges, settingsDraft, settingTypeError } from "./settings-contract.ts";

test("settings responses redact every credential, including legacy custom headers", () => {
  for (const key of SECRET_SETTINGS) {
    const publicValue = publicSetting(key, "synthetic-private-value", false);
    assert.equal(publicValue.value, "configured");
    assert.equal(publicValue.masked, "••••••••");
    assert.ok(!JSON.stringify(publicValue).includes("synthetic-private-value"));
    assert.equal(settingsDraft({ [key]: publicValue })[key], "");
  }
  assert.equal(publicSetting("llm.custom_headers", "", true, true).unreadable, true);
  assert.equal(publicSetting("llm.model", "configured-model", false).value, "configured-model");
});

test("blank credential drafts preserve stored values; replacement and removal are explicit", () => {
  const saved = { "llm.anthropic_api_key": publicSetting("llm.anthropic_api_key", "sample", true), "llm.model": { value: "saved-model" } };
  const draft = settingsDraft(saved);
  assert.deepEqual(settingsChanges(draft, saved, new Set(), "llm"), {});
  assert.deepEqual(settingsChanges({ ...draft, "llm.anthropic_api_key": "replacement" }, saved, new Set(), "llm"), { "llm.anthropic_api_key": "replacement" });
  assert.deepEqual(settingsChanges(draft, saved, new Set(["llm.anthropic_api_key"]), "llm"), { "llm.anthropic_api_key": "" });
});

test("settings patches are section-scoped and retain zero and false values", () => {
  const saved = { "llm.verify_threshold": { value: "0.7" }, "slack.enabled": { value: "true" } };
  const draft = { ...settingsDraft(saved), "llm.verify_threshold": "0", "slack.enabled": "false", "jira.project_key": "SEC" };
  assert.deepEqual(settingsChanges(draft, saved, new Set(), "llm"), { "llm.verify_threshold": "0" });
  assert.deepEqual(settingsChanges(draft, saved, new Set(), "slack"), { "slack.enabled": "false" });
  assert.deepEqual(settingsChanges(draft, saved, new Set(), "jira"), { "jira.project_key": "SEC" });
});

test("setting values reject unsupported providers, malformed types, and invalid thresholds", () => {
  for (const value of ["", "NaN", "Infinity", "-0.1", "1.1", "text"]) assert.ok(settingTypeError("llm.verify_threshold", value));
  for (const value of ["0", "0.5", "1"]) assert.equal(settingTypeError("llm.verify_threshold", value), null);
  assert.ok(settingTypeError("llm.enabled", true));
  assert.ok(settingTypeError("llm.enabled", "yes"));
  assert.equal(settingTypeError("llm.provider", "google"), null);
  assert.equal(settingTypeError("llm.provider", "openai-responses"), null);
  assert.ok(settingTypeError("llm.provider", "unimplemented"));
  assert.ok(settingTypeError("llm.model", "invalid model name"));
  assert.ok(settingTypeError("llm.language", "unknown"));
  assert.ok(settingTypeError("jira.project_key", "lowercase"));
  assert.ok(settingTypeError("jira.issue_type", " "));
  assert.ok(settingTypeError("jira.email", "invalid"));
  assert.ok(settingTypeError("admin.injected", "true"));
  assert.ok(settingTypeError("llm.custom_headers", "x".repeat(32_769)));
  assert.equal(settingTypeError("llm.provider", "openai"), null);
  assert.equal(settingTypeError("llm.model", "provider/model:version"), null);
  assert.equal(settingTypeError("jira.project_key", "SEC_01"), null);
  assert.ok(ALLOWED_SETTINGS.has("llm.custom_headers"));
});
