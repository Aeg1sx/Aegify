# CodeGuard 룰 작성 및 정규화 계약

기준일: 2026-08-19

## 현재 판정

번들 룰은 호환 evaluator와 strict audit가 일치하도록 정규화했습니다. 2026-08-19 감사 결과는 다음과 같습니다.

| 항목 | 값 |
|---|---:|
| YAML 파일 | 58 |
| 룰 정의 | 311 |
| 현재 언어 집합에서 로드 가능 | 303 |
| enabled + detector 실행 가능 | 303 |
| 명시적 비활성 reference 룰 | 8 |
| active 패턴 | 987 |
| 실행 가능한 식별 패턴 | 980 |
| 오류 | 0 |
| 경고 | 0 |

현재 parser가 지원하지 않는 언어만 선언한 8개 룰은 `enabled: false`와 사유를 기록한 reference definition으로 보존했습니다. 혼합 언어 룰의 ruby/php/csharp 등 선언은 지원 언어 부분만 실행하며 감사 결과의 `deferred_languages`에 집계합니다.

따라서 “311개 룰 정의”와 “311개 룰이 실행됨”은 같은 말이 아닙니다. 현재 303개가 enabled/executable이고 8개는 의도적으로 비활성화되어 있습니다. strict audit는 CI 필수 게이트입니다.

## 감사 명령

```bash
cd scanner
codeguard audit-rules ../rules
codeguard audit-rules ../rules --strict
codeguard audit-rules ../rules --json
```

기본 감사는 error가 하나라도 있으면 실패하고, `--strict`는 warning도 실패로 처리합니다. 번들 룰은 두 기준 모두 통과해야 하며 CI에서 `--strict`를 실행합니다.

## 현재 실행되는 패턴 필드

| 필드 | 의미 |
|---|---|
| `pattern_type` | `call`, `regex`, `negative_check`, `sequence`, lexical `taint`, `entropy` |
| `match`, `pattern` | source regex. `pattern`은 shorthand |
| `callee`, `callee_match` | 호출 대상 regex |
| `receiver`, `receiver_match` | receiver regex |
| `callee_chain` | receiver + callee shorthand |
| `args_match` | argument text에 필요한 regex |
| `args_exclude` | argument text에 존재하면 제외 |
| `context`, `context_match`, `must_contain`, `multi_match` | 파일/함수 범위에서 함께 존재해야 하는 문맥 |
| `negative_match`, `exclude_*`, `missing_*`, `sanitizers` | 존재하면 결과를 제외하는 문맥 |
| `sequence_match`, `steps`, `max_lines_between` | 순서와 최대 줄 간격을 보존한 lexical sequence |
| `source`, `sink`, pattern-level `taint` | source 다음 sink와 sanitizer 부재를 검사하는 lexical taint compatibility mode |
| annotation/class/decorator/import/config/content/assignment 계열 | source-level 구조 힌트 regex |
| `file_match`, `languages`, `scope` | 파일, 언어, file/function 범위 제한 |
| `block_match`, `decorator_absent`, `argument_check`, `entropy_threshold` | block/decorator 부재, 수치 threshold, entropy 조건 |

필드가 실행된다는 사실과 compiler 의미를 이해한다는 사실은 구분해야 합니다. source-mode evaluator는 기존 룰을 조용히 무시하지 않기 위한 lexical compatibility 계층입니다. annotation/taint/guard의 타입·별칭·경로 민감 의미는 향후 symbol/dataflow engine으로 이전해야 합니다.

## 최소 실행 예시

```yaml
id: java-runtime-exec-user-input
name: Runtime exec with request-derived argument
severity: high
languages: [java, kotlin]
cwe: CWE-78
message: "Potential command injection in {callee}"
patterns:
  - pattern_type: call
    callee_match: "(^|\\.)exec$"
    receiver_match: "Runtime"
    args_match: "request|getParameter|input"
```

## 목표 schema

룰은 versioned discriminated union으로 분리합니다.

```yaml
schema_version: 2
id: java-command-injection
engine: dataflow
languages: [java, kotlin]
models:
  sources: [spring.mvc.request-parameter]
  sinks: [java.runtime.exec]
  sanitizers: [project.command-allowlist]
options:
  interprocedural: true
  field_sensitive: true
```

권장 engine 종류는 다음과 같습니다.

- `syntax`: CST/AST 구조 매칭
- `symbol`: 정의, 참조, 타입, annotation 매칭
- `dataflow`: source, propagator, sanitizer, sink
- `controlflow`: dominance, guard, exceptional path
- `framework`: Spring Security, MVC, WebFlux, ORM 등 의미 모델
- `graph`: CPG/Security Graph query
- `configuration`: YAML, properties, Terraform, container 설정
- `correlation`: frontend, gateway, backend, contract 간 관계

각 engine은 서로 다른 schema를 사용하고 알 수 없는 필드를 거부해야 합니다. YAML을 `dict[str, Any]`로 받아 조용히 무시하는 방식은 종료합니다.

## 룰 품질 요구사항

모든 룰 PR은 다음 fixture를 포함해야 합니다.

- 최소 1개 true positive
- 최소 2개 가까운 true negative
- sanitizer 또는 guard가 있는 방어 사례
- 지원 언어별 parser/compiler fixture
- framework version 또는 model pack version
- CWE와 source/sink/impact 설명
- 예상 graph path 또는 AST capture
- 성능 상한과 최대 finding 수

룰 결과에는 사용된 룰 버전, engine 버전, model pack, match capture, graph path, 제외된 sanitizer 근거를 남깁니다.

## 마이그레이션 순서

1. 의미가 겹치는 alias를 canonical field로 변환하는 migration 도구 추가
2. schema v2 discriminated union과 engine별 Pydantic model 도입
3. lexical compatibility 룰을 syntax/symbol/dataflow engine fixture와 함께 점진 이전
4. schema v2에서 unknown field를 load error로 변경
5. deferred language 룰은 parser/model pack이 생길 때만 다시 활성화
