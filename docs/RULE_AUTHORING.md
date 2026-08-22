# Rule Authoring and Normalization

Aegify rules are executable security detectors, not documentation disguised as
configuration. The strict audit gate requires every enabled rule and every
declared pattern to map to implemented evaluator behavior.

## Minimal rule

```yaml
rules:
  - id: AEG-EXAMPLE-001
    name: Untrusted command execution
    description: User-controlled input reaches a process execution API.
    severity: critical
    confidence: 0.9
    languages: [java, kotlin]
    cwe_id: 78
    owasp_category: "A03:2021-Injection"
    patterns:
      - callee_match: "^(exec|start)$"
        receiver_match: "^(Runtime|ProcessBuilder)$"
        args_match: "request|param|input"
        disposition: advisory
    taint:
      source_types: [http_param, http_body]
      sink_types: [os_command]
    defense_patterns:
      - "allowlist"
      - "validateCommand"
    message: Avoid constructing operating-system commands from request data.
```

## Identity and metadata

- Use stable `AEG-<AREA>-<NUMBER>` IDs. Never reuse an ID for a different issue.
- Give rules a concise name, security impact, severity, confidence, CWE, and
  actionable message.
- List only languages supported by the current scanner. A mixed list may include
  deferred languages, but a rule containing only unsupported languages fails.

## Executable patterns

Patterns normalize into either call matching or source matching.

Common call fields:

- `callee` / `callee_match`
- `receiver` / `receiver_match`
- `args_match`, `args_exclude`, and `missing_args`
- language restrictions

Common source fields:

- `pattern_type: regex|negative_check|sequence|taint|entropy`
- `match` / `pattern` / `regex_match`
- `annotation_match`, `decorator_match`, `import_match`
- `assignment_match`, `config_match`, `content_match`
- `file_match`, `must_contain`, `missing_pattern`, and exclusion fields

Compatibility fields are accepted only when `PatternSpec` implements them. A
partially executable rule is still invalid: strict audit reports each
non-executable pattern even if another pattern in the same rule works.

Pattern results default to `candidate` evidence with an `advisory` disposition.
This preserves broad coverage in console, SARIF, GitHub review annotations, and
the dashboard without failing CI. Do not mark a lexical fallback `blocking`.

## Evidence and CI disposition

Findings carry two independent fields:

- `evidence_state`: `candidate`, `reachable`, `observed`, or `impact_proven`;
- `disposition`: `advisory` or `blocking`.

Native and YAML pattern matches are advisory by default. A source-to-sink taint
flow is emitted as `reachable` and `blocking`. A structured semantic detector
may also emit a blocking result when its required receiver, ordering, defense,
and scope evidence is satisfied. Severity does not override this contract: a
critical advisory remains visible but does not change the CLI exit code.

SARIF encodes advisory results as `level: note`, `kind: review`, and
`blocksCi: false`. Blocking high or critical results produce a non-zero CLI exit
code. Dashboard ingestion stores and filters both classification fields.

## Structured database-race evidence

The `database_race` semantic detector finds a bounded read-modify-write sequence
inside one parsed function. Broad patterns for the same rule remain advisory.

```yaml
patterns:
  - sequence_match: ["findById", "save"]
    disposition: advisory
semantic:
  kind: database_race
  read_callee: "(findById|findOne|get|load)"
  write_callee: "(save|update|delete)"
  receiver_match: "(?:^|[._])(repo|repository|dao|db)(?:$|[._])"
  required_between: "(?:\\+=|-=|\\+\\+|--)"
  defense_match: "(?:transaction|atomic|lock|compareAndSet)"
  same_receiver: true
  max_lines_between: 20
```

The blocking finding is created only when the read and write use the required
database receiver, occur in order and within the bound, contain the required
business-state operation, and have no matching transaction or concurrency
defense in that function.

## Negative checks

Negative rules require a positive scope anchor. A global “missing header” or
“missing validation” declaration without a file, endpoint, function, or framework
anchor would match everything and is rejected. Use a bounded form:

```yaml
- pattern_type: negative_check
  match: "@PostMapping|router.post"
  must_contain: "authorize|requireRole"
  scope: function
```

If a safe implementation does not exist, remove the pattern or mark the entire
reference rule `enabled: false` with a concrete `disabled_reason`.

## Taint rules

Taint rules declare compatible source and sink categories and may select library
model behavior. They must preserve the path, source, sink, sanitizer decision,
call context, and repository/module identity in evidence. Avoid broad categories
that cannot be tested with positive and negative fixtures.

## Defense patterns

Defense patterns reduce confidence or suppress a finding only when their scope
and meaning are clear. Do not use generic words such as `safe` or `secure`.
Prefer concrete validators, framework guards, parameterization APIs, or encoding
functions, and include bypass-oriented negative tests.

## Strict audit

Run:

```bash
cd scanner
uv run aegify audit-rules ../rules --strict
```

The audit rejects:

- invalid YAML and regular expressions;
- missing or duplicate IDs;
- invalid severity;
- unknown fields;
- unsupported-only language declarations;
- enabled rules with no executable detector;
- any individual non-executable pattern.

The release baseline is 311 definitions, 303 enabled/executable rules, 8
explicitly disabled reference rules, and 980/980 enabled patterns executable.

## Test requirements

Every new or materially changed rule should include:

1. a minimal positive fixture;
2. a safe negative fixture;
3. a cross-file or framework fixture when claimed;
4. stable rule ID, severity, location, and evidence assertions;
5. a test proving a nearby decoy is not selected.

Rules with a fallback and a semantic detector also require assertions that the
fallback is retained as advisory, the semantic path is blocking, and a defended
or unrelated path is not blocking.

Rules affecting reachability should test repository/module identity and ambiguous
targets. Rules affecting secrets or logs must use synthetic placeholders.
