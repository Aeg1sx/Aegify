# Aegify - Quick Start Guide

The maintained Mintlify quickstart is available at
[docs/quickstart.mdx](docs/quickstart.mdx). This repository page retains the
extended DefectDojo workflow.

## 1. Install Scanner

```bash
cd scanner
pip install -e .
```

## 2. Run a Scan

```bash
# Console output
aegify scan /path/to/your/code --severity low --no-llm

# SARIF output
aegify scan /path/to/your/code --output sarif --output-file results.sarif --no-llm

# List all rules
aegify rules
```

## 3. View Results in GitHub Code Scanning

Push SARIF to GitHub (automatic via `.github/workflows/aegify-scan.yml`):
- Go to your repo → Security → Code scanning → View alerts
- PR annotations appear automatically on pull requests

## 4. View Results in DefectDojo (Local Dashboard)

### Start DefectDojo

```bash
docker compose -f docker-compose.defectdojo.yml up -d
```

First-time startup takes ~3-5 minutes (DB migration). Check status:

```bash
docker compose -f docker-compose.defectdojo.yml logs -f defectdojo-initializer
```

Wait until you see "Initializing done" in logs.

### Access DefectDojo

- URL: **http://localhost:8080**
- Username: `admin`
- Password: check initializer logs:
  ```bash
  docker compose -f docker-compose.defectdojo.yml logs defectdojo-initializer 2>&1 | grep "Admin password"
  ```

### Upload Scan Results

**Option A: CLI**
```bash
# Set env vars
export AEGIFY_REPORTING__DEFECTDOJO_URL=http://localhost:8080
export AEGIFY_REPORTING__DEFECTDOJO_TOKEN=<your-api-token>

# Scan + upload
aegify scan /path/to/code --output sarif --output-file results.sarif --upload-defectdojo --no-llm
```

**Option B: curl**
```bash
# Get API token from DefectDojo UI → API v2 key (under your user profile)
# Inject DEFECTDOJO_TOKEN through your shell or secret manager first.
: "${DEFECTDOJO_TOKEN:?DEFECTDOJO_TOKEN is required}"
curl -X POST "http://localhost:8080/api/v2/import-scan/" \
  -H "Authorization: Token ${DEFECTDOJO_TOKEN}" \
  -F "scan_type=SARIF" \
  -F "file=@results.sarif" \
  -F "engagement=1" \
  -F "active=true"
```

**Option C: Python**
```python
from aegify.reporter.defectdojo import DefectDojoReporter

reporter = DefectDojoReporter("http://localhost:8080", "YOUR_TOKEN")
test_id = reporter.upload(scan_result, engagement_id=1)
```

### First-Time Setup in DefectDojo UI

1. Login at http://localhost:8080
2. Go to **Products** → Add Product (e.g., "My App")
3. Go to **Engagements** → Add Engagement for the product
4. Note the engagement ID (visible in URL)
5. Upload SARIF using any method above

### What You'll See

- **Findings list**: All vulnerabilities grouped by severity, CWE, rule
- **Deduplication**: Repeated scans auto-deduplicate findings
- **Triage workflow**: Mark findings as Verified, False Positive, Risk Accepted
- **Metrics dashboard**: Severity distribution, finding trends over time
- **JIRA integration**: Push findings to JIRA tickets (configure in Settings)

## 5. View Results in VS Code

1. Install the "SARIF Viewer" extension
2. Open `results.sarif` in VS Code
3. Click findings to navigate to exact code locations

## 6. Configuration

Create `.aegify.yml` in your project root:

```yaml
scan:
  languages: [python, javascript, typescript, java, kotlin, go, rust, swift]
  exclude: [tests/**, vendor/**, node_modules/**]
  max_workers: 0  # 0=auto, 1=sequential

rules:
  severity_threshold: medium
  disabled_rules: []

reporting:
  defectdojo_url: http://localhost:8080
  defectdojo_token: your-api-token
  defectdojo_engagement_id: 1

storage:
  backend: sqlite  # memory, sqlite, postgresql, s3
  db_path: .aegify.db
```

## Stop DefectDojo

```bash
docker compose -f docker-compose.defectdojo.yml down
# To also delete data:
docker compose -f docker-compose.defectdojo.yml down -v
```
