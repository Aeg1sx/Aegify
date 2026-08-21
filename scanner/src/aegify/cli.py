"""Aegify CLI powered by Typer."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from aegify import __version__
from aegify.config import AegifyConfig
from aegify.models import ScanProgress, ScanResult, Severity

app = typer.Typer(
    name="aegify",
    help="Aegify - Next-gen static application security testing",
    no_args_is_help=True,
)
console = Console()

SEVERITY_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "blue",
}


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Directory or file to scan",
            exists=True,
        ),
    ],
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output format: sarif, json, github"),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Output file path"),
    ] = None,
    severity: Annotated[
        str,
        typer.Option("--severity", "-s", help="Minimum severity: critical, high, medium, low"),
    ] = "medium",
    config_path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Config file path"),
    ] = None,
    llm: Annotated[
        bool,
        typer.Option("--llm/--no-llm", help="Enable LLM verification"),
    ] = False,
    model: Annotated[
        str,
        typer.Option("--model", "-m", help="LLM model to use"),
    ] = "claude-opus-4-6",
    upload_defectdojo: Annotated[
        bool,
        typer.Option("--upload-defectdojo", help="Upload SARIF results to DefectDojo"),
    ] = False,
    upload_dashboard: Annotated[
        bool,
        typer.Option("--upload-dashboard", help="Upload SARIF results to Aegify dashboard"),
    ] = False,
    dashboard_url: Annotated[
        str | None,
        typer.Option("--dashboard-url", help="Dashboard URL (default: http://localhost:3000)"),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose output"),
    ] = False,
) -> None:
    """Scan a directory or file for security vulnerabilities."""
    # Setup logging
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Load config
    if config_path:
        cfg = AegifyConfig.from_yaml(config_path)
    else:
        cfg = AegifyConfig.load(target if target.is_dir() else target.parent)

    cfg.rules.severity_threshold = severity
    cfg.llm.enabled = llm
    cfg.llm.model = model

    console.print(
        Panel(
            f"[bold]Aegify v{__version__}[/bold]\n"
            f"Target: {target}\n"
            f"Severity: >= {severity}\n"
            f"LLM: {'enabled' if llm else 'disabled'}",
            title="Scan Configuration",
        )
    )

    # Run scan with progress display
    from aegify.scanner.engine import ScanEngine

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("{task.fields[eta]}"),
        console=console,
    )
    task_id = progress.add_task("Initializing...", total=100, eta="")

    def on_progress(prog: ScanProgress) -> None:
        eta_str = ""
        if prog.eta_seconds is not None and prog.eta_seconds > 0:
            mins, secs = divmod(int(prog.eta_seconds), 60)
            eta_str = f"ETA {mins}m{secs:02d}s" if mins else f"ETA {secs}s"
        desc = f"[{prog.phase}/{prog.phase_total}] {prog.message}"
        progress.update(
            task_id, completed=prog.overall_progress * 100, description=desc, eta=eta_str
        )

    engine = ScanEngine(config=cfg, on_progress=on_progress)

    with progress:
        result = engine.scan(target)
        progress.update(task_id, completed=100, description="Scan complete", eta="")

    # LLM verification (if enabled)
    if llm and cfg.anthropic_api_key and result.findings:
        console.print("\n[bold]Running LLM verification...[/bold]")
        from aegify.llm.verifier import LLMVerifier

        verifier = LLMVerifier(
            api_key=cfg.anthropic_api_key,
            model=cfg.llm.model,
            token_budget=cfg.llm.token_budget,
            verify_threshold=cfg.llm.verify_threshold,
            batch_size=cfg.llm.batch_size,
            base_url=cfg.llm.base_url,
        )
        result.findings = verifier.verify_and_remediate(result.findings)
        result.token_usage = verifier.get_token_usage()

    # Output
    if output == "sarif":
        _output_sarif(result, output_file, call_graph=engine._last_call_graph)
    elif output == "json":
        _output_json(result, output_file)
    elif output == "github":
        _output_github(result, output_file)
    else:
        _output_console(result)

    # Upload to DefectDojo
    if upload_defectdojo:
        dojo_url = cfg.reporting.defectdojo_url
        dojo_token = cfg.reporting.defectdojo_token
        if not dojo_url or not dojo_token:
            console.print(
                "[red]DefectDojo upload requires "
                "AEGIFY_REPORTING__DEFECTDOJO_URL and "
                "AEGIFY_REPORTING__DEFECTDOJO_TOKEN env vars "
                "(or .aegify.yml config)[/red]"
            )
        else:
            from aegify.reporter.defectdojo import DefectDojoReporter

            dojo = DefectDojoReporter(dojo_url, dojo_token)
            test_id = dojo.upload(
                result,
                engagement_id=cfg.reporting.defectdojo_engagement_id,
            )
            if test_id:
                console.print(f"[green]Uploaded to DefectDojo: test={test_id}[/green]")
            else:
                console.print("[red]DefectDojo upload failed[/red]")

    # Upload to Aegify Dashboard
    if upload_dashboard:
        from aegify.reporter.sarif import SARIFReporter

        url = dashboard_url or "http://localhost:3000"
        sarif_reporter = SARIFReporter()
        sarif_data = sarif_reporter.generate(result, call_graph=engine._last_call_graph)
        sarif_json = json.dumps(sarif_data).encode("utf-8")

        import urllib.request

        req = urllib.request.Request(
            f"{url.rstrip('/')}/api/upload",
            data=sarif_json,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                resp_data = json.loads(resp.read().decode())
                console.print(
                    f"[green]Uploaded to dashboard: scan={resp_data.get('scanId')}, "
                    f"{resp_data.get('findingsCount', 0)} findings[/green]"
                )
        except Exception as e:
            console.print(f"[red]Dashboard upload failed: {e}[/red]")

    # Exit code
    critical_high = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if critical_high > 0:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"Aegify v{__version__}")


@app.command()
def rules() -> None:
    """List all available security rules."""
    from aegify.rules.registry import load_builtin_rules

    registry = load_builtin_rules()
    all_rules = registry.get_all()

    table = Table(title="Security Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Languages")
    table.add_column("CWE")

    for rule in sorted(all_rules, key=lambda r: r.definition.id):
        d = rule.definition
        sev_color = SEVERITY_COLORS.get(d.severity.value, "white")
        table.add_row(
            d.id,
            d.name,
            Text(d.severity.value.upper(), style=sev_color),
            ", ".join(lang.value for lang in d.languages),
            f"CWE-{d.cwe_id}" if d.cwe_id else "-",
        )

    console.print(table)


@app.command("scan-workspace")
def scan_workspace(
    manifest: Annotated[
        Path,
        typer.Argument(
            help="Path to a versioned Aegify workspace YAML manifest",
            exists=True,
            dir_okay=False,
        ),
    ],
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format: sarif or json"),
    ] = "sarif",
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Output file path"),
    ] = None,
    severity: Annotated[
        str,
        typer.Option("--severity", "-s", help="Minimum finding severity"),
    ] = "medium",
    semantic_graph_file: Annotated[
        Path | None,
        typer.Option(
            "--semantic-graph-file",
            help="Write the complete semantic graph as JSONL",
        ),
    ] = None,
    program_graph_file: Annotated[
        Path | None,
        typer.Option(
            "--program-graph-file",
            help="Write the complete CFG/DFG/SSA/security graph as JSONL",
        ),
    ] = None,
) -> None:
    """Scan a multi-repository workspace with stable cross-repo identities."""
    from aegify.scanner.engine import ScanEngine

    cfg = AegifyConfig.load(manifest.parent)
    cfg.rules.severity_threshold = severity
    cfg.llm.enabled = False
    engine = ScanEngine(config=cfg)
    result = engine.scan_workspace(manifest)

    if semantic_graph_file is not None and result.status == "completed":
        engine.export_semantic_graph(semantic_graph_file)
    if program_graph_file is not None and result.status == "completed":
        engine.export_program_graph(program_graph_file)

    if output == "json":
        _output_json(result, output_file)
    elif output == "sarif":
        _output_sarif(result, output_file, call_graph=engine._last_call_graph)
    else:
        console.print(f"[red]Unsupported output format: {output}[/red]")
        raise typer.Exit(code=2)

    if result.status != "completed":
        raise typer.Exit(code=2)


@app.command("index-scip-java")
def index_scip_java(
    manifest: Annotated[
        Path,
        typer.Argument(
            help="Path to a versioned Aegify workspace YAML manifest",
            exists=True,
            dir_okay=False,
        ),
    ],
    image: Annotated[
        str,
        typer.Option(
            "--image",
            help="scip-java container pinned as name@sha256:<digest>",
        ),
    ],
    execute: Annotated[
        bool,
        typer.Option(
            "--execute/--dry-run",
            help="Execute isolated index builds; default emits plans only",
        ),
    ] = False,
    approve_build: Annotated[
        bool,
        typer.Option(
            "--approve-build",
            help="Required acknowledgement for build-system execution",
        ),
    ] = False,
    artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--artifact-directory",
            help="Directory that retains generated index.scip files",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write plan/evidence JSON"),
    ] = None,
) -> None:
    """Plan or run compiler-backed Java/Kotlin SCIP indexing per repository."""
    from aegify.harness import DockerVerificationExecutor
    from aegify.harness.docker import HarnessUnavailableError
    from aegify.semantic import ScipJavaPlanner

    if execute and not approve_build:
        console.print("[red]Index execution requires --approve-build.[/red]")
        raise typer.Exit(code=2)
    if execute and artifact_directory is None:
        console.print(
            "[red]Index execution requires --artifact-directory so outputs are retained.[/red]"
        )
        raise typer.Exit(code=2)

    try:
        workspace_plan = ScipJavaPlanner().plan(manifest, image)
        executor = DockerVerificationExecutor()
        reports: list[dict[str, Any]] = []
        failed_execution = False
        for repository in workspace_plan.repositories:
            if execute:
                assert artifact_directory is not None
                destination = artifact_directory / repository.repository_id
                report = executor.execute(
                    repository.verification_plan,
                    repository.workspace,
                    artifact_directory=destination,
                )
            else:
                report = executor.plan(
                    repository.verification_plan,
                    repository.workspace,
                )
            failed_execution = failed_execution or report.status != "passed"
            reports.append(
                {
                    "repository_id": repository.repository_id,
                    "targets": [target.model_dump(mode="json") for target in repository.targets],
                    "warnings": repository.warnings,
                    "verification": report.model_dump(mode="json"),
                }
            )
    except (ValueError, HarnessUnavailableError) as error:
        console.print(f"[red]scip-java indexing failed: {error}[/red]")
        raise typer.Exit(code=2) from error

    payload = {
        "contract_version": 1,
        "manifest": str(workspace_plan.manifest),
        "executed": execute,
        "warnings": workspace_plan.warnings,
        "repositories": reports,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output_file is not None:
        output_file.write_text(rendered + "\n", encoding="utf-8")
        console.print(f"scip-java evidence written to {output_file}")
    else:
        console.print_json(rendered)

    if execute and failed_execution:
        raise typer.Exit(code=1)


@app.command("export-jvm-classpath")
def export_jvm_classpath(
    manifest: Annotated[
        Path,
        typer.Argument(
            help="Path to a versioned Aegify workspace YAML manifest",
            exists=True,
            dir_okay=False,
        ),
    ],
    image: Annotated[
        str,
        typer.Option(
            "--image",
            help="Exporter/build container pinned as name@sha256:<digest>",
        ),
    ],
    target_java: Annotated[
        int,
        typer.Option("--target-java", help="Highest Java release selected from JARs"),
    ] = 17,
    execute: Annotated[
        bool,
        typer.Option(
            "--execute/--dry-run",
            help="Execute isolated Maven/Gradle builds; default emits plans only",
        ),
    ] = False,
    approve_build: Annotated[
        bool,
        typer.Option(
            "--approve-build",
            help="Required acknowledgement for build-system execution",
        ),
    ] = False,
    artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--artifact-directory",
            help="Directory retaining bundles and materialized classpath snapshots",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write plan/evidence JSON"),
    ] = None,
) -> None:
    """Plan or export SHA-verified JVM classpaths in isolated containers."""
    from aegify.harness import DockerVerificationExecutor
    from aegify.harness.docker import HarnessUnavailableError
    from aegify.semantic import (
        JvmClasspathBundleMaterializer,
        JvmClasspathPlanner,
    )

    if execute and not approve_build:
        console.print("[red]Classpath export requires --approve-build.[/red]")
        raise typer.Exit(code=2)
    if execute and artifact_directory is None:
        console.print(
            "[red]Classpath export requires --artifact-directory so outputs are retained.[/red]"
        )
        raise typer.Exit(code=2)

    try:
        workspace_plan = JvmClasspathPlanner().plan(
            manifest,
            image,
            target_java=target_java,
        )
        executor = DockerVerificationExecutor()
        materializer = JvmClasspathBundleMaterializer()
        reports: list[dict[str, Any]] = []
        failed_execution = False
        for repository in workspace_plan.repositories:
            if execute:
                assert artifact_directory is not None
                destination = artifact_directory / repository.repository_id
                report = executor.execute(
                    repository.verification_plan,
                    repository.workspace,
                    artifact_directory=destination,
                )
            else:
                report = executor.plan(
                    repository.verification_plan,
                    repository.workspace,
                )
            failed_execution = failed_execution or report.status != "passed"
            materialized: list[dict[str, Any]] = []
            materialization_errors: list[str] = []
            if execute:
                assert artifact_directory is not None
                results = {step.id: step for step in report.steps}
                for target in repository.targets:
                    step = results.get(target.step_id)
                    if step is None or step.status != "passed":
                        continue
                    artifact = next(
                        (
                            item
                            for item in step.artifacts
                            if item.relative_path == target.expected_output
                        ),
                        None,
                    )
                    if artifact is None or not artifact.retained_path:
                        materialization_errors.append(
                            f"{target.step_id}: retained classpath bundle is missing"
                        )
                        failed_execution = True
                        continue
                    snapshot_directory = (
                        artifact_directory
                        / repository.repository_id
                        / "snapshots"
                        / f"{target.step_id}-{report.id}"
                    )
                    try:
                        snapshot = materializer.materialize(
                            Path(artifact.retained_path),
                            snapshot_directory,
                            expected_repository_id=repository.repository_id,
                        )
                    except (OSError, ValueError) as error:
                        materialization_errors.append(f"{target.step_id}: {error}")
                        failed_execution = True
                        continue
                    materialized.append(snapshot.model_dump(mode="json"))
            reports.append(
                {
                    "repository_id": repository.repository_id,
                    "targets": [target.model_dump(mode="json") for target in repository.targets],
                    "warnings": repository.warnings,
                    "verification": report.model_dump(mode="json"),
                    "materialized_snapshots": materialized,
                    "materialization_errors": materialization_errors,
                }
            )
    except (ValueError, HarnessUnavailableError) as error:
        console.print(f"[red]JVM classpath export failed: {error}[/red]")
        raise typer.Exit(code=2) from error

    payload = {
        "contract_version": 1,
        "manifest": str(workspace_plan.manifest),
        "target_java": workspace_plan.target_java,
        "executed": execute,
        "warnings": workspace_plan.warnings,
        "repositories": reports,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output_file is not None:
        output_file.write_text(rendered + "\n", encoding="utf-8")
        console.print(f"JVM classpath evidence written to {output_file}")
    else:
        console.print_json(rendered)

    if execute and failed_execution:
        raise typer.Exit(code=1)


@app.command("audit-rules")
def audit_rule_files(
    path: Annotated[
        Path,
        typer.Argument(help="Rule YAML file or directory", exists=True),
    ],
    strict: Annotated[
        bool,
        typer.Option(
            "--strict/--no-strict",
            help="Fail on unsupported fields as well as hard errors",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the full machine-readable audit report"),
    ] = False,
) -> None:
    """Validate that YAML rules map to executable scanner semantics."""
    from aegify.rules.audit import audit_rules

    report = audit_rules(path)
    if json_output:
        console.print_json(report.model_dump_json())
    else:
        table = Table(title="Aegify Rule Audit")
        table.add_column("Metric")
        table.add_column("Count", justify="right")
        table.add_row("Files", str(report.files))
        table.add_row("Rules", str(report.rules))
        table.add_row("Loadable rules", str(report.loadable_rules))
        table.add_row("Executable rules", str(report.executable_rules))
        table.add_row("Disabled rules", str(report.disabled_rules))
        table.add_row("Patterns", str(report.patterns))
        table.add_row("Executable patterns", str(report.executable_patterns))
        table.add_row("Errors", str(report.errors))
        table.add_row("Warnings", str(report.warnings))
        console.print(table)
        if report.unsupported_fields:
            fields = ", ".join(
                f"{name}={count}" for name, count in list(report.unsupported_fields.items())[:12]
            )
            console.print(f"Unsupported fields: {fields}")
        if report.deferred_languages:
            languages = ", ".join(
                f"{name}={count}" for name, count in report.deferred_languages.items()
            )
            console.print(f"Deferred language declarations: {languages}")

    if report.errors or (strict and report.warnings):
        raise typer.Exit(code=2)


@app.command("verify-plan")
def verify_plan(
    plan_file: Annotated[
        Path,
        typer.Argument(
            help="Versioned verification-plan YAML",
            exists=True,
            dir_okay=False,
        ),
    ],
    workspace: Annotated[
        Path,
        typer.Argument(
            help="Source workspace copied into the isolated run",
            exists=True,
            file_okay=False,
        ),
    ],
    execute: Annotated[
        bool,
        typer.Option(
            "--execute/--dry-run",
            help="Execute containers; the default only emits the resolved plan",
        ),
    ] = False,
    approve_dynamic: Annotated[
        bool,
        typer.Option(
            "--approve-dynamic",
            help="Required acknowledgement for dynamic execution",
        ),
    ] = False,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write evidence JSON to this path"),
    ] = None,
    artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--artifact-directory",
            help="Retain declared regular-file outputs beneath this directory",
        ),
    ] = None,
) -> None:
    """Plan or run policy-bounded verification in an isolated Docker container."""
    from aegify.harness import DockerVerificationExecutor, VerificationPlan
    from aegify.harness.docker import HarnessUnavailableError

    try:
        plan = VerificationPlan.load(plan_file)
        executor = DockerVerificationExecutor()
        if execute:
            if not approve_dynamic:
                console.print("[red]Dynamic execution requires --approve-dynamic.[/red]")
                raise typer.Exit(code=2)
            report = executor.execute(
                plan,
                workspace,
                artifact_directory=artifact_directory,
            )
        else:
            report = executor.plan(plan, workspace)
    except (ValueError, HarnessUnavailableError) as error:
        console.print(f"[red]Verification plan failed: {error}[/red]")
        raise typer.Exit(code=2) from error

    payload = report.model_dump_json(indent=2)
    if output_file is not None:
        output_file.write_text(payload + "\n", encoding="utf-8")
        console.print(f"Verification evidence written to {output_file}")
    else:
        console.print_json(payload)

    if execute and report.status != "passed":
        raise typer.Exit(code=1)


@app.command("verify-http")
def verify_http(
    plan_file: Annotated[
        Path,
        typer.Argument(
            help="Versioned loopback HTTP verification-plan YAML",
            exists=True,
            dir_okay=False,
        ),
    ],
    workspace: Annotated[
        Path,
        typer.Argument(
            help="Source workspace copied into the isolated run",
            exists=True,
            file_okay=False,
        ),
    ],
    execute: Annotated[
        bool,
        typer.Option(
            "--execute/--dry-run",
            help="Execute the service and HTTP cases; default emits the plan",
        ),
    ] = False,
    approve_dynamic: Annotated[
        bool,
        typer.Option(
            "--approve-dynamic",
            help="Required acknowledgement for service execution",
        ),
    ] = False,
    artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--artifact-directory",
            help="Retain the redacted HTTP evidence JSON beneath this directory",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write plan/run evidence JSON"),
    ] = None,
) -> None:
    """Plan or run loopback-only HTTP verification in an isolated container."""
    from aegify.harness import HttpVerificationExecutor, HttpVerificationPlan
    from aegify.harness.docker import HarnessUnavailableError

    if execute and not approve_dynamic:
        console.print("[red]HTTP execution requires --approve-dynamic.[/red]")
        raise typer.Exit(code=2)
    if execute and artifact_directory is None:
        console.print("[red]HTTP execution requires --artifact-directory to retain evidence.[/red]")
        raise typer.Exit(code=2)
    try:
        plan = HttpVerificationPlan.load(plan_file)
        executor = HttpVerificationExecutor()
        if execute:
            assert artifact_directory is not None
            report = executor.execute(plan, workspace, artifact_directory)
        else:
            report = executor.plan(plan, workspace)
    except (ValueError, HarnessUnavailableError) as error:
        console.print(f"[red]HTTP verification failed: {error}[/red]")
        raise typer.Exit(code=2) from error

    payload = report.model_dump_json(indent=2)
    if output_file is not None:
        output_file.write_text(payload + "\n", encoding="utf-8")
        console.print(f"HTTP verification evidence written to {output_file}")
    else:
        console.print_json(payload)
    if execute and report.status != "passed":
        raise typer.Exit(code=1)


@app.command("verify-browser")
def verify_browser(
    plan_file: Annotated[
        Path,
        typer.Argument(
            help="Versioned loopback Playwright verification-plan YAML",
            exists=True,
            dir_okay=False,
        ),
    ],
    workspace: Annotated[
        Path,
        typer.Argument(
            help="Source workspace copied into the isolated browser run",
            exists=True,
            file_okay=False,
        ),
    ],
    execute: Annotated[
        bool,
        typer.Option("--execute/--dry-run", help="Run Playwright; default emits a plan"),
    ] = False,
    approve_dynamic: Annotated[
        bool,
        typer.Option(
            "--approve-dynamic",
            help="Required acknowledgement for service/browser execution",
        ),
    ] = False,
    artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--artifact-directory",
            help="Retain redacted browser evidence beneath this directory",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write plan/run evidence JSON"),
    ] = None,
) -> None:
    """Plan or run a loopback-only Playwright journey with egress blocked."""
    from aegify.harness import BrowserVerificationExecutor, BrowserVerificationPlan
    from aegify.harness.docker import HarnessUnavailableError

    if execute and not approve_dynamic:
        console.print("[red]Browser execution requires --approve-dynamic.[/red]")
        raise typer.Exit(code=2)
    if execute and artifact_directory is None:
        console.print(
            "[red]Browser execution requires --artifact-directory to retain evidence.[/red]"
        )
        raise typer.Exit(code=2)
    try:
        plan = BrowserVerificationPlan.load(plan_file)
        executor = BrowserVerificationExecutor()
        if execute:
            assert artifact_directory is not None
            report = executor.execute(plan, workspace, artifact_directory)
        else:
            report = executor.plan(plan, workspace)
    except (ValueError, HarnessUnavailableError) as error:
        console.print(f"[red]Browser verification failed: {error}[/red]")
        raise typer.Exit(code=2) from error

    payload = report.model_dump_json(indent=2)
    if output_file is not None:
        output_file.write_text(payload + "\n", encoding="utf-8")
        console.print(f"Browser verification evidence written to {output_file}")
    else:
        console.print_json(payload)
    if execute and report.status != "passed":
        raise typer.Exit(code=1)


@app.command("verify-proxy")
def verify_proxy(
    plan_file: Annotated[
        Path,
        typer.Argument(
            help="Versioned loopback intercepting-proxy plan YAML",
            exists=True,
            dir_okay=False,
        ),
    ],
    workspace: Annotated[
        Path,
        typer.Argument(
            help="Source workspace copied into the isolated proxy run",
            exists=True,
            file_okay=False,
        ),
    ],
    execute: Annotated[
        bool,
        typer.Option(
            "--execute/--dry-run",
            help="Run proxy mutations; default emits a plan",
        ),
    ] = False,
    approve_dynamic: Annotated[
        bool,
        typer.Option(
            "--approve-dynamic",
            help="Required acknowledgement for service/proxy execution",
        ),
    ] = False,
    artifact_directory: Annotated[
        Path | None,
        typer.Option(
            "--artifact-directory",
            help="Retain redacted proxy evidence beneath this directory",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="Write plan/run evidence JSON"),
    ] = None,
) -> None:
    """Plan or run loopback interception and declarative request mutation."""
    from aegify.harness import ProxyVerificationExecutor, ProxyVerificationPlan
    from aegify.harness.docker import HarnessUnavailableError

    if execute and not approve_dynamic:
        console.print("[red]Proxy execution requires --approve-dynamic.[/red]")
        raise typer.Exit(code=2)
    if execute and artifact_directory is None:
        console.print(
            "[red]Proxy execution requires --artifact-directory to retain evidence.[/red]"
        )
        raise typer.Exit(code=2)
    try:
        plan = ProxyVerificationPlan.load(plan_file)
        executor = ProxyVerificationExecutor()
        if execute:
            assert artifact_directory is not None
            report = executor.execute(plan, workspace, artifact_directory)
        else:
            report = executor.plan(plan, workspace)
    except (ValueError, HarnessUnavailableError) as error:
        console.print(f"[red]Proxy verification failed: {error}[/red]")
        raise typer.Exit(code=2) from error

    payload = report.model_dump_json(indent=2)
    if output_file is not None:
        output_file.write_text(payload + "\n", encoding="utf-8")
        console.print(f"Proxy verification evidence written to {output_file}")
    else:
        console.print_json(payload)
    if execute and report.status != "passed":
        raise typer.Exit(code=1)


@app.command("scan-pr")
def scan_pr(
    target: Annotated[
        Path,
        typer.Argument(
            help="Repository root directory",
            exists=True,
        ),
    ],
    base_ref: Annotated[
        str | None,
        typer.Option("--base-ref", help="Base git ref for diff (auto-detected if omitted)"),
    ] = None,
    changed_files: Annotated[
        str | None,
        typer.Option(
            "--changed-files",
            help="Comma-separated list of changed files (overrides git diff)",
        ),
    ] = None,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", "-f", help="SARIF output file path"),
    ] = None,
    comment_file: Annotated[
        Path | None,
        typer.Option("--comment-file", help="PR comment markdown output path"),
    ] = None,
    severity: Annotated[
        str,
        typer.Option("--severity", "-s", help="Minimum severity: critical, high, medium, low"),
    ] = "low",
    model: Annotated[
        str,
        typer.Option("--model", "-m", help="LLM model to use"),
    ] = "claude-opus-4-6",
    max_related: Annotated[
        int,
        typer.Option("--max-related", help="Max related files to include in scan"),
    ] = 150,
    llm: Annotated[
        bool,
        typer.Option("--llm/--no-llm", help="Enable LLM verification"),
    ] = True,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose output"),
    ] = False,
) -> None:
    """Scan changed and related files in a pull request."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    target = target.resolve()

    # Load config
    cfg = AegifyConfig.load(target)
    cfg.rules.severity_threshold = severity
    cfg.llm.enabled = llm
    cfg.llm.model = model

    if llm and not cfg.anthropic_api_key:
        console.print("[red]AEGIFY_ANTHROPIC_API_KEY env var is required for scan-pr[/red]")
        raise typer.Exit(code=2)

    # Step 1: Resolve changed files
    from aegify.scanner.diff_resolver import DiffResolver

    resolver = DiffResolver(target)
    explicit = changed_files.split(",") if changed_files else None
    changed = resolver.get_changed_files(base_ref=base_ref, explicit_files=explicit)

    if not changed:
        console.print("[yellow]No changed files detected — nothing to scan.[/yellow]")
        raise typer.Exit(code=0)

    console.print(
        Panel(
            f"[bold]Aegify v{__version__} — PR Scan[/bold]\n"
            f"Changed files: {len(changed)}\n"
            f"Severity: >= {severity}\n"
            f"LLM: {'enabled' if llm else 'disabled'}" + (f"\nModel: {model}" if llm else ""),
            title="PR Scan Configuration",
        )
    )

    # Step 2: Parse changed files to get ASTs, then find related files
    from aegify.scanner.engine import ScanEngine

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("{task.fields[eta]}"),
        console=console,
    )
    task_id = progress.add_task("Initializing...", total=100, eta="")

    def on_progress(prog: ScanProgress) -> None:
        eta_str = ""
        if prog.eta_seconds is not None and prog.eta_seconds > 0:
            mins, secs = divmod(int(prog.eta_seconds), 60)
            eta_str = f"ETA {mins}m{secs:02d}s" if mins else f"ETA {secs}s"
        desc = f"[{prog.phase}/{prog.phase_total}] {prog.message}"
        progress.update(
            task_id, completed=prog.overall_progress * 100, description=desc, eta=eta_str
        )

    engine = ScanEngine(config=cfg, on_progress=on_progress)

    # Parse changed files first to get ASTs for import resolution
    from aegify.scanner.ast_parser import ASTParser

    parser = ASTParser()
    changed_asts = []
    for f in changed:
        ast = parser.parse_file(f)
        if ast:
            changed_asts.append(ast)

    # Find related files
    related = resolver.find_related_files(changed, changed_asts, max_related=max_related)
    all_files = list(dict.fromkeys(changed + related))  # Dedupe preserving order

    console.print(
        f"  Changed: {len(changed)} files | Related: {len(related)} files | "
        f"Total: {len(all_files)} files"
    )

    # Step 3: Run scan on all files
    with progress:
        result = engine.scan_files(target, all_files)
        progress.update(task_id, completed=100, description="Scan complete", eta="")

    console.print(f"  Found {len(result.findings)} findings before LLM verification")

    # Step 4: LLM verification (all findings)
    if llm and result.findings:
        console.print("\n[bold]Running LLM verification on all findings...[/bold]")
        from aegify.llm.pr_verifier import PRVerifier

        verifier = PRVerifier(
            api_key=cfg.anthropic_api_key,
            model=cfg.llm.model,
            token_budget=cfg.llm.token_budget,
            batch_size=cfg.llm.batch_size,
            base_url=cfg.llm.base_url,
        )

        # Get the file ASTs from the engine for context
        file_asts = []
        for f in all_files:
            ast = parser.parse_file(f)
            if ast:
                file_asts.append(ast)

        result.findings = verifier.verify_all(result.findings, file_asts)
        result.token_usage = verifier.get_token_usage()

        console.print(
            f"  After LLM: {len(result.findings)} confirmed findings | "
            f"Tokens: {result.token_usage.input_tokens + result.token_usage.output_tokens:,} | "
            f"Cost: ${result.token_usage.total_cost_usd:.4f}"
        )

    # Step 5: Output SARIF
    sarif_path = output_file or Path("aegify-results.sarif")
    _output_sarif(result, sarif_path, call_graph=engine._last_call_graph)

    # Step 6: Output PR comment markdown
    from aegify.reporter.github import generate_pr_comment

    comment = generate_pr_comment(
        result,
        changed_files=changed,
        related_files=related,
        token_usage=result.token_usage,
    )

    md_path = comment_file or Path("aegify-pr-comment.md")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(comment)
    console.print(f"  PR comment written to {md_path}")

    # Console summary
    _output_console(result)

    # Exit code
    critical_high = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if critical_high > 0:
        raise typer.Exit(code=1)


def _output_console(result: ScanResult) -> None:
    """Pretty-print scan results to console."""
    console.print()

    if not result.findings:
        console.print(
            Panel("[bold green]No security findings detected.[/bold green]", title="Results")
        )
    else:
        table = Table(title=f"Security Findings ({len(result.findings)})")
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=14)
        table.add_column("Location", width=40)
        table.add_column("Message")
        table.add_column("Confidence", width=10)

        for finding in result.findings:
            sev_color = SEVERITY_COLORS.get(finding.severity.value, "white")
            table.add_row(
                Text(finding.severity.value.upper(), style=f"bold {sev_color}"),
                finding.rule_id,
                f"{finding.file_path}:{finding.line_start}",
                finding.message[:80] + "..." if len(finding.message) > 80 else finding.message,
                f"{finding.confidence:.0%}",
            )

        console.print(table)

    # Summary
    counts = result.findings_count
    console.print(
        f"\n[bold]Summary[/bold]: "
        f"[red]{counts.get('critical', 0)} critical[/red], "
        f"[dark_orange]{counts.get('high', 0)} high[/dark_orange], "
        f"[yellow]{counts.get('medium', 0)} medium[/yellow], "
        f"[blue]{counts.get('low', 0)} low[/blue]"
    )
    console.print(
        f"Files scanned: {result.files_scanned} | Duration: {result.duration_seconds:.1f}s"
    )

    if result.token_usage.total_cost_usd > 0:
        console.print(
            f"LLM tokens: {result.token_usage.input_tokens + result.token_usage.output_tokens:,} | "
            f"Cost: ${result.token_usage.total_cost_usd:.4f}"
        )


def _output_sarif(
    result: ScanResult,
    output_file: Path | None,
    call_graph: object | None = None,
) -> None:
    """Output SARIF report."""
    from aegify.reporter.sarif import SARIFReporter

    reporter = SARIFReporter()

    if output_file:
        reporter.write(result, output_file, call_graph=call_graph)
        console.print(f"SARIF report written to {output_file}")
    else:
        sarif = reporter.generate(result, call_graph=call_graph)
        print(json.dumps(sarif, indent=2))


def _output_json(result: ScanResult, output_file: Path | None) -> None:
    """Output raw JSON."""
    data = result.model_dump(mode="json")

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"JSON report written to {output_file}")
    else:
        print(json.dumps(data, indent=2))


def _output_github(result: ScanResult, output_file: Path | None) -> None:
    """Output GitHub PR comment markdown."""
    from aegify.reporter.github import GitHubReporter

    reporter = GitHubReporter()
    comment = reporter.generate_comment(result)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(comment)
        console.print(f"GitHub comment written to {output_file}")
    else:
        print(comment)


if __name__ == "__main__":
    app()
