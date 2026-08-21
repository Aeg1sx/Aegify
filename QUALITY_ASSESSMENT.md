# CodeGuard 오픈소스 준비도 평가

기준일: 2026-08-22

## 결론

CodeGuard의 **오픈소스 alpha scanner 범위는 공개 가능한 상태**입니다. 멀티 레포/모노레포 identity와 cross reachability, Spring/Kotlin 및 frontend/gateway/runtime 공격 표면, strict-zero 룰 감사, SCIP 생성·수입, JVM module/CHA/RTA, CFG/SSA/DFG Program Graph, k=2 context-bounded JVM source points-to/alias와 bounded global taint v2, 외부 분석기 adapter, 정책 제한 Docker/HTTP 검증 하네스가 한 evidence contract로 연결됐습니다.

Strix/Shannon급 자율 exploit platform과 동일하다고 표기해서는 안 됩니다. source와 bytecode heap을 통합한 exhaustive points-to, IFDS/IDE tabulation, exception-complete interprocedural CFG, 인증/TLS/multi-origin proxying, 자동 exploit impact proof는 alpha 범위 밖입니다. README와 릴리스 노트는 정적 후보, 동적 도달 관측, exploit impact proof를 서로 다른 상태로 표시해야 합니다.

## 검증된 현재 상태

| 영역 | 상태 | 근거/한계 |
|---|---|---|
| Scanner regression | 통과 | pytest 297개, 1 skip, coverage 77.20%, loopback 통합 포함 2026-08-22 전체 실행 확인 |
| Python lint/type | 통과 | ruff 전체, mypy strict 74 source files |
| Wheel packaging | 통과 | 0.1.0 wheel에서 classpath planner/exporter/materializer와 JVM model pack `2026.08.1` 9개 모델 로드 확인 |
| Multi-repo parsing | 구현 | 병렬 parsing과 repo-qualified symbol ID |
| Cross-repo semantics | 구현 | SCIP exact symbol/package-version path, Maven/Gradle exact artifact→workspace provider-module path, module-scoped compiler-classpath source→bytecode→invoke path, version-conflict/unresolved/ambiguous evidence, content-addressed SCIP import shard cache와 fidelity-labeled repository fallback; compiler-index 생성 cache는 후속 |
| Monorepo semantics | 구현 | Gradle/Maven module membership/dependency, Maven property/dependency-management, Gradle literal/default version catalog/lockfile 좌표와 복수 SCIP index |
| JVM semantics | 구현 | build/module/artifact discovery, descriptor-safe Java/Kotlin overload, source CHA/RTA, k=2 source points-to fixed point, 승인 기반 Maven/Gradle classpath exporter, bounded classfile method·direct invoke·virtual/interface CHA·`NEW` 기반 allocation-aware RTA·LambdaMetafactory/altMetafactory lambda/method-reference target·Exceptions 분석; CHA는 보수적 coverage로 병렬 보존하며 generic substitution, source+bytecode unified heap points-to와 non-Lambda custom bootstrap 의미는 제한 |
| Spring DI semantics | 구현 | component/`@Bean` factory, `@Qualifier`/`@Primary`/injection-name/ambiguous 후보, `@Profile`/`@ConditionalOn*` 조건 evidence, exact Gradle/Maven module·artifact-provider scope, cross-repo auto-configuration, Java/Kotlin constructor/field 호출; 활성 profile/property 값 평가와 custom condition 실행은 하지 않음 |
| Spring MVC/Kotlin routes | 개선 | class + method mapping 조합, named `path`/`value`, suspend endpoint golden fixture |
| Spring Gateway | 초기 구현 | YAML 및 단순 Java/Kotlin DSL |
| Frontend API calls | 초기 구현 | fetch/axios 계열 정적 문자열·template |
| Attack-surface evidence | 구현 | frontend/gateway/runtime observation과 파일·라인·provenance |
| External tools | 구현 | CodeQL/SARIF, Semgrep JSON, Joern JSONL/GraphSON bounded import |
| Runtime adapters | 구현 | active loopback Playwright/proxy mutation, browser/proxy HAR, HTTP/proxy evidence v1, OpenTelemetry trace parent-child |
| Evidence interchange | 통과 | deterministic snapshot, finding/edge provenance, SARIF round-trip, Prisma insert/read test |
| Dashboard quality | 통과 | Node evidence/security tests 7개, production fail-closed config, ESLint, Next.js 16.3.1 webpack production build |
| Dashboard migrations | 통과 | fresh migration SQL + Prisma insert/read; 과거 schema drift 보정 migration 포함 |
| Dashboard supply chain | 통과 | npm audit 0, 2026-08-22 재검증 |
| Open-source CI hardening | 통과 | 7개 workflow의 third-party action full-SHA pin, least-privilege permission, Harden-Runner, CodeQL, dependency review, Gitleaks, Scorecard, zizmor, SBOM/attestation; zizmor 1.29.0 auditor 0 findings |
| Secret/public-tree gate | 통과 | 실제 `.env`/DB/cache/build artifact ignored, Gitleaks 8.30.1 공개 후보 전체 0 findings, Vault Agent read-only template와 fail-closed production env contract |
| Dashboard auth maturity | 주의 | fixed advisory 범위의 NextAuth beta.32이나 v5는 여전히 beta |
| Rule inventory | 감사됨 | 311 definitions, 303 enabled/executable, 8 explicit disabled |
| Rule strictness | 통과 | 0 errors, 0 warnings, CI required gate |
| Program Graph | 구현 | branch/loop/switch/when, conservative try/catch/finally CFG, call-site 보존 source-bounded call/return ICFG, compiler-classpath bytecode call/return 및 선언 예외→caller catch ICFG, callsite stack을 push/pop하는 bounded context-balanced path/reachability와 limit exhaustion 오류, reaching-def DFG, SSA phi, data-state transformation, context-bounded source points-to/alias 및 typed overlays; runtime/implicit exception-complete CFG와 full Joern CPG 동등성은 주장하지 않음 |
| Global taint v2 | 구현 | flow-sensitive local, field path, allocation-site object, argument/receiver/scalar return, callee object-return points-to와 caller field identity, singleton allocation strong update, k=2 call-string context, sink-category sanitizer 및 SCIP-disambiguated cross-repo path; object-return caller 격리와 안전값 overwrite 부정 회귀 통과, IFDS/IDE 및 source+bytecode unified heap은 후속 |
| JVM library model pack | 구현 | strict schema의 `2026.08.1` source/sink/propagator/sanitizer 9개 모델과 SARIF coverage counter; 대규모 framework/library 확장은 후속 |
| Isolated verification | 구현 | digest-pinned/no-network Docker, approval, ephemeral copy, bounded output/artifact hash, loopback HTTP runner, Maven/Gradle classpath exporter와 safe materializer; live smoke는 daemon 부재 |
| Active proxy mutation | 구현 | loopback 실제 interception 통합 test, method/path/query/header/body/JSON mutation, value-redacted evidence |
| Dynamic exploit proof | 제한 | HTTP/browser와 loopback proxy mutation 관측은 가능; 인증/TLS/multi-origin 및 자동 impact proof는 후속 |

## Alpha 공개와 production 승격 조건

Alpha 공개는 가능하다. production-ready 표기 전에는 다음이 필요하다.

1. 실제 benchmark에서 precision/recall과 unsupported/unresolved 비율 공개
2. Auth.js stable 경로와 dashboard dependency policy 재검증
3. Docker daemon이 준비된 CI에서 scanner/dashboard image, scip-java, HTTP harness container smoke 실행
4. IFDS/IDE·source+bytecode unified points-to·대규모 library model 확장과 authenticated proxy/impact proof는 별도 maturity로 공개

## 경쟁 제품과의 정확한 비교

- Strix는 격리된 Kali sandbox에서 코드 실행, 브라우저/프록시 및 보안 도구를 사용하고 PoC로 검증하는 동적 agentic 플랫폼입니다.
- 공개 Shannon은 LLM source pass와 proof-by-exploitation 흐름을 제공하지만 CPG/SAST 기능은 상용 플랫폼 설명과 구분해야 합니다.
- CodeGuard의 현재 강점은 자체 호스팅 가능한 scanner/dashboard, 멀티 레포/모듈 Program Graph, 코드·API·Gateway·frontend·runtime 상관 evidence, 확장 가능한 룰/adapter 기반입니다.
- 가장 큰 남은 약점은 IFDS/IDE·source+bytecode unified heap points-to·대규모 JVM library model coverage와 인증/TLS/multi-origin 동적 검증입니다. k=2 source points-to와 call-string taint, JVM model pack v1, active loopback browser/proxy 및 HAR/HTTP/OTel evidence는 이미 있으나 자율 exploit proof와 동일하지 않습니다.

요구사항별 실행 증거는 [alpha 완료 감사](docs/ALPHA_COMPLETION_AUDIT.md), 상세 설계는 [기술 아키텍처](docs/TECHNICAL_ARCHITECTURE.md), 룰 상태는 [룰 작성 및 정규화 계약](docs/RULE_AUTHORING.md)을 기준으로 합니다.
