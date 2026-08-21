# SCIP/JVM 의미 분석 계약

CodeGuard의 의미 계층은 compiler-backed evidence와 source-derived fallback을
같은 정확도로 취급하지 않는다. `scan-workspace` 결과의 `semantic_analysis`와
`semantic_relationships`는 각 edge에 `provider`, `fidelity`, `confidence`를
보존한다.

## Workspace 설정

SCIP 인덱스는 repository 단위로 연결하며, 독립 빌드가 여러 개인 모노레포는
`scip_indexes`로 여러 인덱스를 붙인다.

```yaml
version: 1
name: commerce
scip_cache_dir: ./.codeguard/cache/scip
repositories:
  - id: orders
    path: ./orders
    depends_on: [shared-contracts]
    scip_indexes:
      - ./indexes/orders-api.scip
      - ./indexes/orders-batch.scip
    jvm_classpath_snapshots:
      - path: ./evidence/orders/classpath.json
```

- `.json`은 `scip print --json index.scip`의 protobuf JSON을 직접 읽는다.
- native `.scip`은 upstream `scip` CLI가 있을 때 argv 방식으로 JSON 변환한다.
- `scip_cache_dir`을 지정하면 repository ID, importer schema, index content
  SHA-256으로 normalized import shard를 저장한다. 동일 content는 native CLI/JSON
  parsing을 건너뛰고, content 변경은 새 shard로 자동 invalidation된다.
- global symbol의 scheme/manager/package/version을 공식 double-space escape 문법으로
  파싱해 exact-version ownership·dependency와 version-conflict evidence를 만든다.
- SCIP document path는 절대 경로와 `..`를 거부한다.
- occurrence definition/reference와 symbol implementation/reference/type-definition
  관계를 repository-scoped graph로 정규화한다.
- 변환 실패는 전체 scan을 정밀 분석으로 오인시키지 않도록 summary warning으로
  남기고 JVM source fallback을 계속한다.
- `codeguard index-scip-java`는 Gradle/Maven 빌드 루트를 발견해 digest-pinned,
  no-network 격리 계획을 만들고, 승인 실행 시 `index.scip`을 SHA-256과 함께
  보존한다. 의존성은 이미지에 미리 포함되어야 한다.

## Compiler classpath/bytecode 계약

`jvm_classpath_snapshots`는 신뢰된 Gradle/Maven 수집 단계가 보존한 classpath
manifest를 읽는다. `codeguard export-jvm-classpath`는 build root별 digest-pinned,
no-network, 승인 기반 수집 계획과 실행을 제공한다. 스캐너 자체는 build나 JAR 코드를
실행하지 않는다.
manifest와 같은 디렉터리의 상대 JAR만 허용하고, 각 파일의 SHA-256과 크기,
전체 크기, class 수/크기, 압축 비율을 검사한 뒤 bounded classfile parser로
method descriptor, invoke instruction, `NEW` allocation site, `Exceptions` attribute를
그래프로 만든다. class-level `BootstrapMethods`와 method handle도 검증해
LambdaMetafactory/altMetafactory 구현 메서드를 `invokedynamic` target으로 연결한다.

```json
{
  "contract_version": 1,
  "repository_id": "orders",
  "producer": {"name": "gradle", "version": "8.14"},
  "target_java": 17,
  "entries": [{
    "path": "jars/contracts-1.2.3.jar",
    "sha256": "<64 lowercase hex>",
    "scope": "compile",
    "build_root": "root",
    "module": "orders-api",
    "coordinate": {
      "manager": "maven",
      "group": "com.example",
      "artifact": "contracts",
      "version": "1.2.3"
    }
  }]
}
```

source call은 해당 파일의 build-derived module이 실제로 load한 artifact 안에서만
owner/import, arity, 알려진 argument type으로 unique best bytecode method에 연결한다.
동률은 추측하지 않고 ambiguous counter로 남긴다. 연결된 method의 bytecode invoke는
source-to-sink 경로에 포함되며, 선언 예외는 caller의 기존 보수적 catch/uncaught CFG로
연결한다. 이는 `Exceptions` attribute 기반 declared-only 증거이며 implicit/runtime
exception 완전성을 뜻하지 않는다.

자동 수집 흐름은 다음과 같다.

```bash
# dry-run: source/policy hash와 Docker argv만 출력
codeguard export-jvm-classpath codeguard-workspace.yml \
  --image registry.example/codeguard-jvm-classpath@sha256:<digest>

# 승인 실행: bundle과 재검증된 classpath.json/JAR들을 별도 evidence 경로에 보존
codeguard export-jvm-classpath codeguard-workspace.yml \
  --image registry.example/codeguard-jvm-classpath@sha256:<digest> \
  --execute --approve-build \
  --artifact-directory ./classpath-evidence \
  --output-file classpath-export-evidence.json
```

Maven은 offline `dependency:build-classpath`, Gradle은 무작위 이름의 init task로
module별 `compileClasspath`를 수집한다. shell 문자열을 사용하지 않으며, source는
ephemeral copy에서만 변경된다. classpath와 JAR는 deterministic ZIP 하나로 반출되고,
호스트에서 path/symlink/duplicate/size/compression/SHA/repository ID를 재검증한 뒤
`jvm_classpath_snapshots[].path`에 넣을 수 있는 manifest로 materialize된다.

## JVM 계층

현재 구현된 범위:

- Maven/Gradle descriptor와 module/source-root 비실행 discovery
- Gradle/Maven module membership과 module dependency edge
- Maven property와 동일 POM dependency-management의 exact dependency coordinate
- Gradle literal dependency, 기본 `gradle/libs.versions.toml` alias/bundle 및
  `gradle.lockfile`/dependency-locks의 selected version
- artifact coordinate가 동일한 다른 repository의 유일한 provider module을 exact
  연결하며, provider가 둘 이상이면 임의 선택 없이 ambiguous counter로 보존
- Java class/interface `extends`/`implements`, Kotlin delegation 기반 type hierarchy
- 동일 method name 기반 override relation
- Java/Kotlin의 명시적 receiver binding에서 CHA candidate 생성
- 실제 생성된 runtime type으로 RTA candidate를 축소하고 call graph에 우선 overlay
- allocation site, local alias, parameter, receiver, return을 k=2 call string별로
  고정점 전파하고 points-to receiver가 증명된 호출을 `rta-call`로 축소
- Java explicit import와 workspace provider/module 경계를 사용해 같은 simple name의
  cross-repository decoy type을 배제하며, alias·argument·return·direct/receiver call
  사실을 별도 relationship과 summary counter로 보존
- classfile invoke opcode를 보존하고 static/special direct dispatch와
  virtual/interface concrete subtype별 최종 override/default method CHA 후보를 분리
- 검증된 classfile의 `NEW` 타입만으로 virtual/interface 후보를 줄인
  `bytecode-rta-invoke`를 병렬 증거로 추가하되, 무할당·reflection·DI 누락에 대비해
  기존 CHA edge는 삭제하지 않음
- LambdaMetafactory/altMetafactory의 implementation method handle을 lambda·method
  reference target으로 연결하고 bootstrap method, opcode offset, dynamic dispatch를
  edge evidence에 보존; StringConcatFactory와 custom bootstrap은 누락시키지 않고
  `bytecode-invokedynamic-bootstrap-unresolved`로 구분
- 여러 runtime class가 같은 상속/default 구현으로 수렴하면 단일 target으로 dedup하고,
  서로 다른 override면 candidate edge를 모두 보존하며 임의 선택하지 않음
- Spring constructor/field DI call, method security, transaction proxy,
  Kotlin suspend, Reactor continuation overlay
- Spring component/`@Bean` factory를 bean candidate로 만들고
  `@Qualifier`→unconditional `@Primary`→injection name→ambiguous 순으로 선택하며,
  `@Profile`/`@ConditionalOn*` 원문을 edge condition으로 보존
- Gradle/Maven module dependency와 exact artifact-provider path가 허용하고,
  cross-repo에서는 `@AutoConfiguration`, explicit `@Import`, 또는
  `@ComponentScan` evidence가 있을 때만 DI target 후보로 사용

현재 source fallback은 Java/Kotlin parameter descriptor와 exact caller range,
arity/literal/local-variable type, Kotlin default parameter/vararg로 overload를
구분한다. 다만 generic substitution, reflection, Kotlin extension, non-Lambda custom
bootstrap의 언어별 의미, source와 bytecode heap을 합친 exhaustive points-to receiver
narrowing, 실제 활성 profile/property와 custom condition 결과를 compiler/runtime
수준으로 평가하지 않는다.
source points-to edge의 fidelity는 `source-context-bounded-points-to`, provider는
`codeguard-jvm-points-to`이다. 나머지 source fallback은 `source-heuristic`이다. classpath 연결은
`compiler-classpath-bytecode-signature`, bytecode 내부 사실은
`sha256-verified-bytecode`, allocation RTA는 `bytecode-rta-allocation`으로 구분한다.
SCIP 인덱스가 함께 있으면 전체 summary만
`hybrid`이고, 개별 edge의 원래 fidelity는 유지된다.

## 크로스 도달성 정확도

도달성은 증거 수준을 섞지 않는다.

1. module-scoped source→classpath bytecode method→invoke 경로:
   `compiler-classpath-bytecode-signature` + `sha256-verified-bytecode`; virtual dispatch는
   보수적 CHA와 `bytecode-rta-allocation` 부분집합을 병렬 보존
2. SCIP definition/reference/external symbol 경로: `compiler-index`
3. Maven/Gradle module→artifact→provider-module: `dependency-lock-workspace-exact`,
   `declared-coordinate-workspace-exact` 또는 `version-catalog-workspace-exact`
4. Spring/JVM source model: `framework-model` 또는 CHA/RTA fidelity
5. Gradle/Maven module dependency: `declared-module-dependency-coarse`
6. manifest의 repository `depends_on`: `declared-dependency-coarse`

빌드 coordinate는 의도되거나 lock된 dependency 증거이지, 해당 artifact가 실제
compiler classpath에 로드됐다는 실행 증거는 아니다. 실제 classpath 사실은 compiler
index 또는 검증된 classpath snapshot이 있어야 승격한다.

동일 repository 안에서는 repository membership을 통한 지름길을 질의에서 제외해
실제 call/data/module 경로가 숨지 않게 한다.

global taint v2는 이 도달성 위에서 k=2 call string별 parameter, scalar return,
allocation identity를 분리한다. callee가 field를 가진 객체를 반환하면 allocation
identity를 caller local로 전달하고, 이후 `returned.field` load가 callee field-store와
return 경계를 모두 증거 경로에 남긴다. 단일 allocation으로 증명된 field overwrite는
strong update로 이전 taint를 제거하고, 복수·unknown alias는 weak update로 합친다.
SARIF summary의 `object_return_propagations`, `heap_strong_updates`,
`jvm_points_to_contexts`, `jvm_points_to_allocations`, alias/argument/return 및
receiver/direct-call counter로 해당 동작 횟수를 확인할 수 있다. 이는 bounded source
분석이며 source+bytecode unified heap이나 IFDS/IDE를
대체한다고 주장하지 않는다.

CFG/ICFG 정밀 질의는 `ProgramGraphQuery.context_balanced_path()`와
`context_balanced_reachable()`을 사용한다. source/bytecode call edge의
`callsite_id`를 push하고 normal/declared-exception return에서 같은 ID만 pop한다.
기본 한계는 call depth 32, state 100,000이며, 한계가 소진되면 빈 경로로 오인하지
않고 `ContextQueryLimitError`를 발생시킨다. 일반 `shortest_path()`는 구조 탐색용이며
context-balanced 증거를 뜻하지 않는다.

## 다음 정밀도 단계

1. scip-java 생성 cache와 Maven BOM 및 Gradle custom catalog/convention plugin resolution
2. generic substitution, Kotlin extension, non-Lambda custom bootstrap 및 source+bytecode
   unified heap points-to receiver narrowing
3. Spring 활성 profile/property/custom condition 평가, reflection, generated-source 모델
4. 현재 k=2 source points-to/call-string taint를 source+bytecode heap 및 IFDS/IDE tabulation으로 승격
5. unresolved/ambiguous ratio와 증분 성능 benchmark
