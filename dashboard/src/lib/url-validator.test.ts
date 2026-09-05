import assert from "node:assert/strict";
import test from "node:test";

import {
  validateJiraBaseUrl,
  validateSlackWebhookUrl,
} from "./url-validator.ts";

test("Slack webhooks are restricted to the exact Slack HTTPS host and path", () => {
  assert.equal(
    validateSlackWebhookUrl("https://hooks.slack.com/services/T000/B000/secret").valid,
    true,
  );
  assert.equal(
    validateSlackWebhookUrl("https://hooks.slack.com.example.test/services/T/B/C").valid,
    false,
  );
  assert.equal(
    validateSlackWebhookUrl("https://127.0.0.1/services/T/B/C").valid,
    false,
  );
});

test("Jira defaults to Atlassian Cloud and rejects embedded API paths", () => {
  assert.equal(validateJiraBaseUrl("https://company.atlassian.net").valid, true);
  assert.equal(
    validateJiraBaseUrl("https://company.atlassian.net/rest/api/3/myself").valid,
    false,
  );
  assert.equal(validateJiraBaseUrl("https://169.254.169.254").valid, false);
  assert.equal(validateJiraBaseUrl("https://jira.attacker.example").valid, false);
});
