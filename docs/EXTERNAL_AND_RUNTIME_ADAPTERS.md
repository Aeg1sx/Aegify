# 외부 분석기와 런타임 증거 계약

CodeGuard는 도구별 결과를 그대로 섞지 않고 finding, typed graph edge,
runtime observation으로 정규화한다. 모든 artifact에는 repository 소유권, producer,
version, fidelity, artifact SHA-256에서 만든 evidence ID가 붙는다.

## Workspace 예시

```yaml
version: 1
name: commerce
repositories:
  - id: orders
    path: ./orders
    analysis_artifacts:
      - format: sarif
        path: ./evidence/codeql.sarif
      - format: semgrep-json
        path: ./evidence/semgrep.json
      - format: joern-jsonl
        path: ./evidence/joern.jsonl
    runtime_artifacts:
      - format: browser-har
        path: ./evidence/browser.har
      - format: proxy-har
        path: ./evidence/proxy.har
      - format: otel-json
        path: ./evidence/otel.json
      - format: http-evidence-json
        path: ./evidence/http-evidence.json
```

모든 result path는 해당 repository 아래로 resolve되어야 한다. 절대 경로 탈출,
`..`, 비-file URI는 무시하고 warning을 남긴다. 결과와 path location은 manifest의
상한으로 제한한다.

## 정적 분석 어댑터

| 형식 | 보존하는 근거 | fidelity |
|---|---|---|
| SARIF 2.1.0 | rule, severity/security score, precision, location, partial fingerprint, thread flow | `sarif-result`, `sarif-thread-flow` |
| Semgrep JSON | check ID, location, severity, confidence, CWE/OWASP metadata | `pattern-analysis` |
| Joern JSONL/GraphSON | query finding, CPG node/edge, outgoing GraphSON edge | `cpg-query`, `cpg-export`, `joern-graphson` |

SARIF는 CodeQL뿐 아니라 2.1.0을 출력하는 도구에 공통으로 적용한다. Joern finding
JSONL은 `record: finding`, graph edge는 `record: edge`와 `source`, `target`, `kind`를
사용한다. native CPG 전체 그래프는 `joern-export --repr=all --format=graphson`의
outgoing edge 형태도 읽는다.

## 런타임 어댑터

| 형식 | 저장하는 값 | 저장하지 않는 값 |
|---|---|---|
| browser/proxy HAR | method, URL path, status, duration | query, header, cookie, request/response body |
| OpenTelemetry JSON | trace/span/parent ID, HTTP route/method/status, duration | arbitrary payload와 baggage |
| HTTP evidence v1 | case ID, method/path, status, duration, pass/fail | header, cookie, raw body |
| Proxy evidence v1 | original/mutated method/path, mutation kind/name, query/body/response hash, status | query/header value, cookie, raw request/response body |

관측된 method/path는 정적 endpoint와 직접 또는 Spring Gateway filter 변환을 거쳐
연결한다. 연결된 endpoint는 `runtime_observed`와 observation count를 가지며 edge의
`analysis_kind`는 `dynamic-correlation`이다. 이는 도달 관측이지 취약점 영향 증명은
아니다.

`codeguard verify-browser`는 digest-pinned Playwright image 안에서 owned loopback
서비스를 시작하고 navigate/click/wait action을 실행한다. 모든 외부 origin 요청은
browser routing 단계에서 중단하며, 출력은 `browser-evidence-json`의 redacted request
metadata뿐이다.

`codeguard verify-proxy`는 같은 격리 컨테이너 안의 loopback forward proxy를 통해
원본 요청을 전달하고, 선언형 method/path/query/header/body/JSON mutation을 적용한다.
외부 origin 및 sensitive header는 거부하며 `proxy-evidence-json`은 값 대신 hash와
mutation kind/name만 보존한다.

## HTTP evidence v1

```json
{
  "contract_version": 1,
  "producer": "codeguard-http-harness",
  "cases": [
    {
      "id": "orders-read",
      "method": "GET",
      "path": "/api/orders/42",
      "status_code": 200,
      "duration_ms": 8.1,
      "passed": true,
      "response_sha256": "..."
    }
  ]
}
```

## 정확한 한계

- CodeQL, Semgrep, Joern의 실행 환경 설치와 rule/query 선택은 별도 CI job이 담당하고
  CodeGuard는 현재 결과를 import한다.
- active loopback browser와 proxy mutation은 제공한다. 인증 비밀 주입, TLS MITM,
  multi-origin egress allowlist는 아직 제공하지 않으며 외부 proxy HAR import는 지원한다.
- OpenTelemetry parent-child edge는 실제 실행 증거지만 source symbol 역매핑은 route
  correlation 범위다.
- runtime observation은 exploit proof나 authorization bypass를 자동으로 의미하지 않는다.
