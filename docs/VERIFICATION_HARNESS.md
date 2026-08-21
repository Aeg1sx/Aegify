# 격리 검증 하네스

`codeguard verify-plan`은 동적 검증을 명시적 계획과 승인 아래 실행하는 alpha
하네스다. 기본 동작은 dry-run이며 `--execute --approve-dynamic`을 함께 주어야
실행한다.

```bash
codeguard verify-plan examples/verification-jvm.yml /path/to/repository

codeguard verify-plan examples/verification-jvm.yml /path/to/repository \
  --execute --approve-dynamic \
  --artifact-directory ./verification-artifacts \
  --output-file verification-evidence.json

codeguard verify-http examples/verification-http.yml /path/to/repository

codeguard verify-browser examples/verification-browser.yml /path/to/repository

codeguard verify-proxy examples/verification-proxy.yml /path/to/repository

codeguard index-scip-java codeguard-workspace.yml \
  --image ghcr.io/scip-code/scip-java@sha256:<digest>

codeguard export-jvm-classpath codeguard-workspace.yml \
  --image registry.example/codeguard-jvm-classpath@sha256:<digest>

codeguard export-jvm-classpath codeguard-workspace.yml \
  --image registry.example/codeguard-jvm-classpath@sha256:<digest> \
  --execute --approve-build \
  --artifact-directory ./classpath-evidence \
  --output-file classpath-export-evidence.json
```

계약으로 강제되는 통제:

- container image는 `@sha256` digest 고정
- network는 `none`만 허용
- read-only root filesystem, all Linux capabilities drop, no-new-privileges
- 임의 UID에서도 build cache가 read-only root를 쓰지 않도록 `HOME`/XDG cache를
  `/tmp` tmpfs로 고정
- CPU, memory, PID, file-descriptor, timeout, output 크기 제한
- shell string 대신 argv만 허용하고 실행 파일 allowlist 적용
- password/token/secret/API key 형태의 command argument 거부
- 원본 repository가 아니라 임시 복제본을 mount
- source snapshot, plan/policy, stdout/stderr 전체 내용의 SHA-256과 truncation 상태 보존
- 선언한 regular-file output만 크기 제한 후 별도 디렉터리에 복사하고 SHA-256 보존
- timeout/error 시 해당 CodeGuard container ID만 cleanup

HTTP 하네스 추가 통제:

- 서비스와 요청 runner를 같은 no-network 컨테이너에 두고 loopback HTTP만 허용
- 외부 URL, credential/query가 포함된 base URL, parent traversal 거부
- redirect 자동 추적 금지
- 요청/응답 header, cookie, body는 evidence에 저장하지 않고 response hash만 보존
- HTTP status expectation과 실행 시간, truncation, error만 contract v1 JSON으로 출력

Browser 하네스 추가 통제:

- Playwright와 대상 서비스를 같은 no-network 컨테이너에서 실행
- base URL과 navigation을 loopback-relative path로 제한
- browser routing에서 loopback origin 이외 요청을 `blockedbyclient`로 중단
- 임의 JavaScript와 credential fill action을 허용하지 않고 navigate/click/wait만 지원
- header, cookie, request/response body 없이 method/path/status/duration만 evidence v1로 출력

Proxy 하네스 추가 통제:

- 대상 origin과 proxy/client/service를 같은 no-network 컨테이너의 loopback에 한정
- method, path literal, query set/delete, safe header set/delete, body replace,
  JSON field set/delete를 순서가 있는 선언형 mutation으로만 허용
- Authorization, Cookie, token/secret/API-key 계열 header와 외부 target을 거부
- 원본/변조 query와 body 값은 저장하지 않고 SHA-256, byte 수, mutation kind/name만 보존
- response도 bounded hash/status/duration만 보존하며 plan당 case/mutation/body 크기를 제한
- 각 실행은 `--approve-dynamic`과 artifact directory를 요구하고 종료 시 proxy/service를 cleanup

SCIP 인덱싱 추가 통제:

- repository의 독립 Gradle/Maven build root별 argv-only `scip-java index`
- 생성된 `index.scip`을 ephemeral copy 밖으로 명시적으로 보존
- Gradle cross-repo metadata(`maven-publish`/publication) 부재와 Maven Kotlin
  자동 인덱싱 한계를 warning으로 표시

JVM classpath export 추가 통제:

- repository의 독립 Maven/Gradle build root마다 shell 없는 Python exporter argv 생성
- `--execute --approve-build` 없이는 build를 실행하지 않고 dry-run evidence만 출력
- Maven/Gradle은 offline/no-network로 실행하고 pinned image의 `/opt/codeguard-cache`를
  writable tmpfs에 복제해 사용
- module별 compile classpath JAR를 SHA-256 content address로 중복 제거하고
  `classpath.json`과 함께 deterministic ZIP 하나로 반출
- 호스트 materializer가 ZIP member path, duplicate, symlink, member/total size,
  compression ratio, manifest exact membership, repository ID와 각 JAR SHA-256을
  다시 검증한 뒤에만 workspace snapshot으로 승격
- [Dockerfile.jvm-classpath](../scanner/Dockerfile.jvm-classpath)는 Python/Gradle/Maven
  base image를 모두 digest-pinned build arg로 요구한다. 프로젝트 plugin/dependency
  cache가 더 필요하면 이 이미지를 확장한 뒤 결과 RepoDigest를 CLI에 전달한다.

현재 한계:

- active loopback intercepting proxy와 선언형 요청 변조는 구현됐다. 인증 비밀 주입,
  multi-origin egress allowlist, TLS MITM, 브라우저 전체 세션 proxying은 아직 허용하지 않는다.
- network allowlist/proxy egress는 구현하지 않아 alpha에서는 완전 차단만 허용한다.
- dependency download가 필요한 build는 사전에 채운 digest-pinned image나 offline cache가
  필요하다. generic exporter image는 네트워크를 열어 자동 다운로드하지 않는다.
- 로컬 Docker daemon이 실행 중이어야 한다. Docker 없는 운영 배포를 위한 Cloudflare
  Sandbox provider는 별도 adapter로 추가할 수 있지만, 동일한 plan/evidence 계약과
  egress 정책을 먼저 유지해야 한다.
