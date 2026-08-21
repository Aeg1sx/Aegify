# CodeGuard SAST - Product Requirements Document

> 이 문서는 제품 방향을 기록한 historical PRD입니다. 현재 구현 보장과
> production 경계는 [QUALITY_ASSESSMENT.md](QUALITY_ASSESSMENT.md) 및
> [docs/ALPHA_COMPLETION_AUDIT.md](docs/ALPHA_COMPLETION_AUDIT.md)를 기준으로 합니다.
> 아래의 미래 기능이나 버전 표는 구현 완료를 의미하지 않습니다.

## 1. Overview

**CodeGuard**는 차세대 정적 응용 프로그램 보안 테스트(SAST) 도구로, Call Graph 분석, AST 기반 패턴 매칭, Dataflow/Taint Analysis, LLM 기반 취약점 검증 및 교정을 결합하여 오탐을 최소화하고 실질적인 보안 인사이트를 제공한다.

### 1.1 핵심 차별점
- **Cross-file Context Analysis**: 단일 파일이 아닌 프로젝트 전체의 call graph를 구축하여 상위 방어 로직(auth middleware, input sanitization) 존재 여부를 확인
- **LLM-Augmented Verification**: Claude Opus 4.6을 활용하여 탐지된 취약점의 실제 악용 가능성 검증 및 교정안 제시
- **Token-Efficient Architecture**: AST/Call Graph로 1차 필터링 → LLM은 고확신 후보에만 사용하여 비용 최적화
- **SARIF 2.1.0 표준 출력**: GitHub Code Scanning, SonarQube 등과 즉시 통합 가능

### 1.2 실행 환경
| 환경 | 방식 |
|------|------|
| **로컬** | CLI (`codeguard scan .`) / Docker |
| **CI/CD** | GitHub Actions (공식 Action) |
| **CD** | ArgoCD 연동 (이미지 스캔 게이트) |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CodeGuard Scanner                     │
│                                                         │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────────┐ │
│  │ AST      │  │ Call Graph │  │ Dataflow / Taint     │ │
│  │ Parser   │──│ Builder   │──│ Analyzer             │ │
│  │(tree-sit)│  │(networkx) │  │                      │ │
│  └──────────┘  └───────────┘  └──────────────────────┘ │
│       │              │                    │              │
│       ▼              ▼                    ▼              │
│  ┌─────────────────────────────────────────────────┐    │
│  │            Context Analyzer                      │    │
│  │  - Auth middleware detection                     │    │
│  │  - Input sanitization tracking                   │    │
│  │  - Permission check verification                 │    │
│  └─────────────────────────────────────────────────┘    │
│       │                                                  │
│       ▼                                                  │
│  ┌─────────────────────────────────────────────────┐    │
│  │            Rule Engine                           │    │
│  │  - Pattern matching rules                        │    │
│  │  - Semantic rules (call graph aware)             │    │
│  │  - Configurable severity/confidence              │    │
│  └─────────────────────────────────────────────────┘    │
│       │                                                  │
│       ▼  (high-confidence candidates only)               │
│  ┌─────────────────────────────────────────────────┐    │
│  │            LLM Verification Layer                │    │
│  │  - False positive filtering                      │    │
│  │  - Remediation generation                        │    │
│  │  - Additional vulnerability search               │    │
│  │  - Token budget management                       │    │
│  └─────────────────────────────────────────────────┘    │
│       │                                                  │
│       ▼                                                  │
│  ┌─────────────────────────────────────────────────┐    │
│  │            Reporter                              │    │
│  │  - SARIF 2.1.0                                   │    │
│  │  - GitHub PR Comment                             │    │
│  │  - Dashboard API                                 │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                  CodeGuard Web Dashboard                  │
│                                                         │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────────┐ │
│  │ Dashboard │  │ Findings  │  │ Triage & Coverage    │ │
│  │ Overview  │  │ Explorer  │  │ Management           │ │
│  └──────────┘  └───────────┘  └──────────────────────┘ │
│                                                         │
│  Auth: Okta SAML/OIDC  |  DB: PostgreSQL + Prisma      │
│  Framework: Next.js 15  |  UI: Tailwind + shadcn/ui    │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Technical Specifications

### 3.1 Scanner Engine (Python)

| Component | Technology | Version |
|-----------|------------|---------|
| Language Parser | tree-sitter + language grammars | 0.24+ |
| Call Graph | networkx + custom resolver | 3.4+ |
| Dataflow | Custom taint propagation engine | - |
| LLM | Anthropic Claude API (Opus 4.6) | anthropic SDK 0.42+ |
| CLI | typer | 0.15+ |
| Config | pydantic-settings | 2.7+ |
| Async | asyncio + aiofiles | - |

### 3.2 Web Dashboard (TypeScript)

| Component | Technology | Version |
|-----------|------------|---------|
| Framework | Next.js | 15.x |
| UI | shadcn/ui + Tailwind CSS | 4.x |
| Auth | NextAuth.js + Okta Provider | 5.x |
| ORM | Prisma | 6.x |
| DB | PostgreSQL | 16+ |
| Charts | Recharts | 2.x |
| State | Zustand | 5.x |

### 3.3 지원 언어 (Phase 1)
- Python
- JavaScript / TypeScript
- Java
- Go

---

## 4. Core Features

### 4.1 Cross-File Call Graph Analysis
```
목표: 함수 호출 체인을 추적하여 취약점의 실제 도달 가능성 판단

예시:
  routes.py: get_user(request.args["id"])  ← user input
    → db.py: query_user(user_id)           ← SQL query

  BUT: middleware.py에 auth_required 데코레이터 존재
  AND: db.py에서 parameterized query 사용

  결과: FALSE POSITIVE → 억제
```

**구현 방식:**
1. tree-sitter로 각 파일의 AST 구축
2. 함수 정의/호출 관계를 추출하여 directed graph 생성
3. Entry point(route handler, API endpoint)에서 sink(DB query, OS command, file operation)까지의 경로 탐색
4. 경로 상의 방어 로직(sanitizer, validator, auth check) 존재 여부 확인

### 4.2 Dataflow / Taint Analysis
```
Source(사용자 입력) → Propagation(변수 할당, 함수 전달) → Sink(위험 함수)

Taint Sources:
  - request.args, request.form, request.json
  - sys.argv, os.environ
  - file read operations

Taint Sinks:
  - SQL queries (execute, raw SQL)
  - OS commands (subprocess, os.system)
  - File operations (open, write)
  - HTML rendering (render_template_string)

Sanitizers:
  - parameterized queries
  - html.escape, bleach.clean
  - shlex.quote
  - input validation functions
```

### 4.3 LLM Integration (Token-Efficient)

**3단계 토큰 최적화 전략:**

1. **Pre-filter (0 tokens)**: AST + Call Graph로 1차 필터링, 방어 로직이 확인된 경우 즉시 제외
2. **Batch Verification (최소 tokens)**: 남은 후보를 배치로 묶어 한 번의 API 호출로 검증
   - 코드 컨텍스트를 최소화하여 전달 (관련 함수 시그니처 + 호출 체인만)
3. **Deep Analysis (필요시)**: Critical/High severity만 상세 분석 및 교정안 생성

**Token Budget 관리:**
```
기본 예산: 100K tokens/scan
분배:
  - Verification: 60% (60K)
  - Remediation: 30% (30K)
  - Additional Search: 10% (10K)
```

### 4.4 Rule Engine

**Rule 구조:**
```python
class Rule:
    id: str           # e.g., "CG-SQL-001"
    name: str         # e.g., "SQL Injection via string concatenation"
    severity: Severity # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0.0 - 1.0
    languages: list    # ["python", "javascript"]

    # AST pattern to match
    ast_pattern: dict

    # Call graph context requirements
    requires_taint_path: bool    # source → sink 경로 필요
    defense_patterns: list       # 이 패턴이 경로에 있으면 억제

    # LLM verification threshold
    llm_verify_threshold: float  # confidence 이하일 때 LLM 검증
```

### 4.5 Reporting

#### SARIF 2.1.0 Output
- GitHub Code Scanning API 호환
- 취약점 위치, severity, 교정 제안 포함
- Call graph 경로 정보를 `codeFlows`에 기록

#### GitHub PR Comment
- 신규 취약점만 코멘트 (baseline diff)
- Inline annotation으로 코드 라인에 직접 표시
- 교정 제안 코드 블록 포함

#### Dashboard API
- RESTful API로 스캔 결과 전송
- 실시간 WebSocket 업데이트

---

## 5. Web Dashboard

### 5.1 Pages

| Page | Description |
|------|-------------|
| `/dashboard` | 전체 현황: severity 분포, 트렌드, 커버리지, 최근 스캔 |
| `/scans` | 스캔 이력 목록, 필터/검색, 상태별 분류 |
| `/scans/[id]` | 개별 스캔 상세: findings, call graph 시각화, SARIF 다운로드 |
| `/findings` | 전체 findings 목록, triage 상태 필터, 담당자 할당 |
| `/findings/[id]` | Finding 상세: 코드 뷰, call graph 경로, LLM 교정안, triage |
| `/coverage` | 언어별/레포별 커버리지 현황, 미스캔 레포 알림 |
| `/settings` | Okta 연동, 알림 설정, rule 커스터마이징 |

### 5.2 Triage Workflow
```
NEW → CONFIRMED → IN_PROGRESS → FIXED → VERIFIED
  └→ FALSE_POSITIVE (자동 baseline에 추가)
  └→ ACCEPTED_RISK (사유 기록 필수)
```

### 5.3 Authentication
- Okta SAML 2.0 / OIDC 연동
- Role-Based Access: ADMIN, SECURITY_TEAM, DEVELOPER, VIEWER
- Team/Repository 기반 접근 제어

---

## 6. CI/CD Integration

### 6.1 GitHub Actions
```yaml
# .github/workflows/codeguard.yml
name: CodeGuard SAST
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codeguard/sast-action@v1
        with:
          severity-threshold: high
          fail-on-findings: true
          sarif-upload: true
```

### 6.2 ArgoCD Integration
- Pre-sync hook으로 이미지 빌드 시 스캔
- 스캔 실패 시 배포 차단 가능 (configurable)

### 6.3 Local Execution
```bash
# Install
pip install codeguard-sast

# Scan
codeguard scan ./src --output sarif --severity high

# With LLM remediation
codeguard scan ./src --llm --model claude-opus-4-6

# Config file
codeguard scan --config .codeguard.yml
```

---

## 7. Configuration

```yaml
# .codeguard.yml
scan:
  languages: [python, javascript, typescript, java, go]
  exclude:
    - "tests/**"
    - "vendor/**"
    - "node_modules/**"

rules:
  severity_threshold: medium
  custom_rules: ./rules/
  disabled_rules: []

llm:
  enabled: true
  model: claude-opus-4-6
  token_budget: 100000
  verify_threshold: 0.7

reporting:
  sarif: true
  github_comment: true
  dashboard_url: https://codeguard.internal.com

context:
  auth_patterns:
    - "@auth_required"
    - "@login_required"
    - "requireAuth"
  sanitizer_patterns:
    - "parameterized"
    - "escape"
    - "sanitize"
```

---

## 8. Data Model

### Finding
```
id: UUID
scan_id: FK → Scan
rule_id: string
severity: CRITICAL | HIGH | MEDIUM | LOW
confidence: float
status: NEW | CONFIRMED | IN_PROGRESS | FIXED | VERIFIED | FALSE_POSITIVE | ACCEPTED_RISK
file_path: string
line_start: int
line_end: int
code_snippet: text
call_chain: json[]  # [{file, function, line}]
defense_context: json  # {auth_present, sanitizer_present, ...}
llm_analysis: text
remediation: text
assignee: FK → User
created_at: datetime
updated_at: datetime
```

### Scan
```
id: UUID
repository: string
branch: string
commit_sha: string
status: PENDING | RUNNING | COMPLETED | FAILED
findings_count: json  # {critical: 0, high: 2, ...}
duration_seconds: int
token_usage: json  # {input: N, output: N, cost: $X}
sarif_url: string
created_at: datetime
```
