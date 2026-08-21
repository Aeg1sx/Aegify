# CodeGuard Data and Privacy Policy

기준일: 2026-08-19

이 문서는 self-hosted CodeGuard가 어떤 데이터를 읽고 저장하며 외부로 보낼 수 있는지 설명합니다. 운영 조직은 실제 배포의 controller로서 별도 개인정보·retention 정책을 정해야 합니다.

## 기본 동작

CodeGuard 자체의 first-party analytics 또는 사용량 telemetry 전송 코드는 현재 없습니다. 로컬 scanner는 기본적으로 지정한 source를 읽고 결과를 로컬 출력/저장소에 기록합니다. 외부 전송은 사용자가 기능을 설정하거나 명시적으로 요청한 경우에만 발생합니다.

## 처리하는 데이터

| 데이터 | 사용 목적 | 기본 저장 위치 |
|---|---|---|
| Source path/content | AST, rule, endpoint, graph 분석 | scanner memory; 선택한 storage/output |
| Code snippet, finding, call chain, endpoint | triage와 evidence 표시 | SARIF, dashboard DB, 선택한 backend |
| Workspace snapshot/rule digest/evidence ID | 재현성과 중복 식별 | SARIF와 dashboard DB |
| Repository/branch/commit metadata | project/scan 식별 | dashboard DB/SARIF |
| OAuth account/token | GitHub/GitLab repository 접근 | Auth.js account tables |
| LLM/Slack secret | 외부 연동 | dashboard Setting table, AES-256-GCM 암호화 |
| Session/account data | dashboard 인증 | Auth.js tables |

Workspace snapshot은 파일 내용 자체가 아니라 repository-qualified path와 content digest를 다시 해시한 값입니다. 그러나 작은 입력 집합의 존재 여부를 검증하는 용도로 악용될 수 있으므로 공개 식별자로 간주하지 않습니다.

## 선택적 외부 전송

- Scanner LLM review: finding snippet, call chain, defense context 등 prompt에 포함된 정적 근거를 설정된 Anthropic 또는 custom endpoint로 보냅니다.
- Dashboard repository LLM scan: GitHub/GitLab에서 읽은 허용 파일 내용을 batch로 설정된 LLM provider에 보냅니다.
- Dashboard upload: SARIF 전체를 지정한 CodeGuard dashboard로 보냅니다.
- DefectDojo: SARIF와 repository/product metadata를 지정한 DefectDojo instance로 보냅니다.
- Slack: 설정한 severity 이상의 finding 요약과 repository/branch metadata를 webhook으로 보낼 수 있습니다.
- GitHub/GitLab: OAuth 기능 사용 시 provider API로 repository metadata와 file content를 요청합니다.

외부 provider의 logging, training, retention, region 정책은 CodeGuard가 통제하지 않습니다. proprietary source 또는 개인정보가 포함된 repository에는 조직 승인 provider와 data-processing agreement를 사용해야 합니다.

## Secret 처리

- `llm.*_api_key`와 `slack.webhook_url`은 `ENCRYPTION_SECRET`에서 유도한 key로 AES-256-GCM 암호화해 저장합니다.
- API 응답과 설정 화면에는 secret 원문 대신 masked 상태를 반환합니다.
- OAuth token은 Auth.js adapter storage에 저장되므로 database와 backup 접근을 credential 접근으로 취급해야 합니다.
- SARIF, log, issue, PR comment에는 credential, proprietary path, 전체 source를 넣지 않습니다.

암호화는 host 또는 `ENCRYPTION_SECRET`이 함께 침해되는 상황을 막지 못합니다. Secret rotation 시 기존 설정을 다시 저장하거나 migration하는 운영 절차가 필요합니다.

## Retention과 삭제

현재 제품에는 자동 retention scheduler가 없습니다. Project에 새 SARIF를 업로드하면 기존 project scan을 삭제하는 경로가 있지만, 이를 일반 retention 또는 안전한 삭제 보장으로 해석하면 안 됩니다.

운영자는 다음을 별도로 정해야 합니다.

- scan/finding/snippet 보존 기간과 삭제 주기
- database snapshot, volume, object storage, log, CI artifact의 backup retention
- 사용자 계정/OAuth token 폐기 절차
- incident와 legal hold 예외
- source와 개인정보를 LLM/provider로 전송할 수 있는 승인 기준

## 로그와 지원 자료

오류 로그에는 URL, file path, rule ID, provider error 일부가 포함될 수 있습니다. 공개 issue나 지원 요청 전에 secret, 내부 hostname, proprietary path, source snippet, SARIF를 redaction합니다. 최소 재현은 synthetic 또는 owned fixture를 사용합니다.

## 운영자 체크리스트

1. `AUTH_SECRET`, `CODEGUARD_UPLOAD_TOKEN`, `ENCRYPTION_SECRET`을 배포 secret으로 설정합니다.
2. 필요한 외부 provider만 활성화하고 egress allowlist를 적용합니다.
3. LLM 전송 전 source classification과 조직 승인을 확인합니다.
4. DB/volume/backup을 암호화하고 최소 권한 접근을 적용합니다.
5. retention과 사용자/OAuth token 삭제 runbook을 문서화합니다.
6. 사고 또는 취약점 제보는 [Security Policy](../SECURITY.md)를 따릅니다.
