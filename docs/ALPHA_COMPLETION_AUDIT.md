# CodeGuard alpha 완료 감사

기준일: 2026-08-22

## 판정

오픈소스 **alpha 공개 범위는 GO**다. strict rule debt는 0이고, 요청된 멀티
레포/모노레포 reachability, Java/Spring/Kotlin framework model, Program Graph,
SCIP 생성·수입, 외부 분석기 adapter, frontend/Gateway/runtime 공격 표면,
격리 HTTP/Browser 하네스가 실행 가능한 contract와 회귀 테스트로 연결됐다.

Docker daemon이 현재 꺼져 있어 scip-java/HTTP/Browser container의 live smoke만
이 머신에서 실행하지 못했다. dry-run은 digest pin, no-network, read-only root,
capability drop, resource/timeout, argv allowlist, artifact output/hash까지 resolve됐다.
이는 alpha 코드 완료와 별도의 CI 환경 검증 항목이다.

## 요구사항별 증거

| 요구사항 | 구현 | 검증/정확도 |
|---|---|---|
| 룰 정규화 | strict schema/audit, unknown field 거부, executable pattern audit | 311 definitions, 303 enabled/executable, 8 explicit disabled, issue 0 |
| AST/Call Graph | tree-sitter 8언어, repository-qualified symbols, cross-file call graph, caller/callee가 같아도 call-site별 MultiDiGraph edge 보존 | 전체 회귀, symbol collision 및 반복 호출 line 4/5 보존 test |
| CFG/SSA/DFG | branch/loop/break/continue, switch/when, conservative try/catch/finally CFG, call statement→callee entry와 callee exit→정상 continuation source-bounded ICFG, callsite stack 기반 bounded context-balanced path/reachability, reaching-def, SSA phi, def-use | Java/Python/Kotlin exception/case, 반복 호출, mismatched return 거부, nested/recursion depth, state-limit 명시 오류, source/bytecode normal·declared-exception return, exact/ambiguous overload 및 caller catch 비합류 golden test |
| data lineage | definition별 data-state와 `transforms` edge | DTG 관점의 bounded source overlay, 논문 전체 구현 주장은 아님 |
| points-to/alias/taint | k=2 context-bounded JVM source points-to와 flow/field/allocation-site-sensitive global taint v2, call-string별 parameter/scalar return/allocation, argument/receiver/object-return summary, singleton allocation field strong update | alias+factory-return receiver 축소, 호출 context 격리, explicit-import cross-repo decoy 배제, callee field-store→object return→caller field-load, 호출자 간 heap 격리, tainted→safe overwrite 부정 테스트 통과; IFDS/IDE와 source+bytecode unified heap은 production 정밀도 항목 |
| JVM library model | strict/versioned `2026.08.1` source/sink/propagator/sanitizer 9개 모델 | StringBuilder receiver, System source, ProcessBuilder sink, sink-category sanitizer 회귀 통과 |
| 멀티 레포 | SCIP external symbol precise path + manifest dependency fallback | precise compiler-index와 coarse fallback을 별도 fidelity로 표시 |
| SCIP package/cache | 공식 symbol grammar의 scheme/manager/name/version exact resolver, version conflict/unresolved counter, content SHA import shard cache | exact-version cross-repo 1건·version conflict·cache miss→hit·content invalidation 회귀 통과 |
| 모노레포 | Gradle/Maven module membership/dependency와 복수 SCIP index | 동일 repo membership shortcut을 질의에서 제거하고 실제 module path 검증 |
| JVM dependency | Maven property/dependency-management, Gradle literal/default `libs.versions.toml` alias·bundle, `gradle.lockfile` exact version, artifact→workspace provider-module resolver | declared/lock fidelity 분리, exact·dynamic·unresolved·ambiguous·version-conflict SARIF counter; 중복 provider는 추측하지 않음 |
| JVM classpath/bytecode | strict JSON + SHA-256 classpath snapshot, module-scoped artifact loading, bounded JAR/classfile method·opcode invoke·`NEW`·BootstrapMethods·Exceptions import, source owner/arity/type→unique bytecode overload, direct 및 hierarchy virtual/interface CHA, allocation-aware RTA, LambdaMetafactory/altMetafactory dynamic target | source→Client→Library와 복수 interface override sink 경로, 무할당 CHA 보존, 단일/복수 할당 RTA 부분집합, subclass→inherited method, default implementation dedup, lambda·virtual method reference, Kotlin-indy형 altMetafactory, StringConcat unresolved 및 malformed bootstrap 거부, 선언 IOException→caller catch ICFG 회귀 통과; hash/path escape 거부, ambiguous는 추측하지 않음 |
| JVM classpath 생성 | 독립 build root별 승인 기반 Maven/Gradle offline exporter, deterministic ZIP, host-side safe materializer | 멀티 모듈 identity, Maven/Gradle argv, mutable image/미승인 실행 거부, ZIP path/hash/duplicate/size/compression/repository 검증 및 materialize→workspace scan E2E 통과; Docker live smoke 대기 |
| Java/Kotlin | JVM hierarchy, CHA/RTA, Gradle/Maven discovery | compiler index 우선, source fallback 병행 |
| JVM overload | source callable descriptor, exact caller range, arity/literal/local type, Kotlin default/vararg 선택 | symbol collision·잘못된 overload taint·CHA/RTA·Spring DI 회귀 통과, ambiguous는 추측하지 않고 counter로 보존 |
| Spring | component/`@Bean` factory, Java/Kotlin constructor·field binding, qualifier/primary/name/ambiguous dispatch, profile/`ConditionalOn*` evidence, exact module/artifact-provider scope와 cross-repo auto-configuration, Security guard, transaction proxy, suspend, Reactor | Maven exact provider만 선택하고 미의존 decoy 배제, Gradle api→domain DI 2개, Java qualifier/primary/ambiguous, Kotlin qualifier, conditional factory graph/SARIF 회귀 통과; 실제 활성 condition 값은 평가하지 않음 |
| Spring Gateway | YAML/DSL path/method/filter, RewritePath/StripPrefix 등 | public path에서 backend endpoint 변환 검증 |
| 프론트 공격 표면 | fetch/axios 계열 호출과 backend/Gateway 상관 분석 | source file/line, match kind, confidence 보존 |
| 런타임 공격 표면 | HTTP/browser/proxy HAR, HTTP/proxy evidence, OTel trace | trace parent→child→observation→endpoint와 mutated request→endpoint 경로 검증 |
| CodeQL/Semgrep/Joern | SARIF 2.1.0, Semgrep JSON, Joern JSONL/GraphSON import | path escape 거부, result/path cap, artifact SHA/provenance |
| SCIP 생성 | 독립 JVM build root별 `scip-java index` | digest-pinned isolated plan, retained index SHA; live Docker smoke 대기 |
| HTTP 하네스 | loopback-only service/request runner | redirect 차단, body/header/cookie 미보존, response hash |
| Browser 하네스 | loopback-only Playwright navigate/click/wait | 외부 origin abort, arbitrary JS/fill 금지, redacted request evidence |
| Proxy 하네스 | loopback interception과 method/path/query/header/body/JSON mutation | sensitive header/외부 target 거부, query/body 값 대신 SHA-256 보존 |
| Dashboard | Runtime DB migration, SARIF ingestion, endpoint list/detail UI | Prisma fresh migration test, ESLint, TypeScript/Next production build |

## 최종 실행 게이트

```text
scanner pytest:       297 passed, 1 skipped (loopback proxy integration included)
scanner coverage:     77.20%
scanner ruff:         passed
scanner mypy strict:  74 source files passed
rule strict audit:    311 rules, 303 executable, 8 disabled, 0 issues
wheel packaging:      codeguard_sast-0.1.0-py3-none-any.whl built,
                      JVM model pack 2026.08.1 / 9 models loaded from wheel
dashboard tests:      7 passed, fresh migration and production security included
dashboard lint:       passed
dashboard build:      passed (Next.js 16.3.1 production build)
dashboard npm audit:  0 vulnerabilities
public-tree gitleaks: 0 findings (8.30.1)
workflow zizmor:      0 findings (1.29.0 auditor/offline)
golden workspace:     2 endpoints, 6 attack-surface links,
                      2 runtime observations/links, 1 module dependency,
                      2 Spring DI call edges, ICFG callsite/call/return 1/1/1
```

현재 wheel SHA-256은
`56b8d6ef5e508c512f8cfb2048c7402d5c118bbbb0502336b83e1c02a42142b8`다.
wheel을 직접 해제한 환경에서 CLI, static-only `scan-pr`, JVM model pack
`2026.08.1` 9개, k=2 points-to analyzer를 재검증했다. 전체 297개 회귀는 같은
wheel 소스를 사용하는 locked 개발 환경에서 통과했다.
Docker live smoke는 Colima socket이 존재하지 않아 계속 미검증 상태다.

## Alpha 이후 정밀도 마일스톤

다음은 alpha 공개 blocker가 아니라 production/enterprise 정밀도 트랙이다.

1. scip-java 생성 cache와 Maven BOM 및 Gradle custom catalog/convention plugin resolution
2. generic substitution, Kotlin extension, non-Lambda custom bootstrap 의미, source+bytecode unified points-to receiver narrowing 및 활성 Spring profile/property/custom condition 평가
3. runtime/implicit library exception-complete interprocedural CFG와 bytecode heap/object propagation
4. IFDS/IDE 계열 tabulation과 JVM library model pack 대규모 확장
5. 인증 비밀/TLS MITM/multi-origin proxy 정책과 승인 기반 exploit impact proof
6. 대규모 corpus precision/recall, unresolved ratio, memory/latency benchmark 공개
