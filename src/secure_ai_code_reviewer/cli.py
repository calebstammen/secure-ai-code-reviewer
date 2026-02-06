from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from .config import Config, load_config
from .engine import scan_repository
from .reporting.json_report import write_json_report
from .reporting.md_report import write_md_report
from .reporting.sarif_report import write_sarif_report
from .rules.registry import load_rules

app = typer.Typer(help="Secure AI Code Reviewer")
rules_app = typer.Typer(help="Manage rules")
app.add_typer(rules_app, name="rules")
console = Console()


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose"), quiet: bool = typer.Option(False, "--quiet")) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level)
    if quiet:
        logging.getLogger().setLevel(logging.ERROR)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False),
    format: str = typer.Option("json", "--format"),
    out: Optional[Path] = typer.Option(None, "--out"),
    severity_threshold: str = typer.Option("medium", "--severity-threshold"),
    enable_external: bool = typer.Option(False, "--enable-external"),
    enable_llm: bool = typer.Option(False, "--enable-llm"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    loaded = load_config(config)
    merged = Config(
        include_globs=loaded.include_globs,
        exclude_globs=loaded.exclude_globs,
        severity_threshold=severity_threshold or loaded.severity_threshold,
        enable_external_scanners=enable_external or loaded.enable_external_scanners,
        enable_llm=enable_llm or loaded.enable_llm,
        llm_mode=loaded.llm_mode,
        remote_llm=loaded.remote_llm,
        redaction=loaded.redaction,
        sarif=loaded.sarif,
    )
    if merged.enable_llm and merged.llm_mode == "remote":
        console.print(
            "[bold yellow]Warning:[/bold yellow] Remote LLM mode enabled. "
            "Code snippets may be sent to a remote endpoint after redaction."
        )
    report = scan_repository(path, merged)
    output_path = out or Path(f"saicr_report.{format}")

    if format == "json":
        write_json_report(report, output_path)
    elif format == "md":
        write_md_report(report, output_path)
    elif format == "sarif":
        write_sarif_report(report.findings, output_path)
    else:
        raise typer.BadParameter("format must be json|md|sarif")

    console.print(f"Report written to {output_path}")

    exit_code = 1 if report.findings else 0
    raise typer.Exit(code=exit_code)


@rules_app.command("list")
def rules_list() -> None:
    registry = load_rules()
    for rule in registry.all():
        console.print(f"{rule.rule_id} - {rule.title} ({rule.severity})")


@rules_app.command("describe")
def rules_describe(rule_id: str) -> None:
    registry = load_rules()
    rule = registry.get(rule_id)
    console.print(json.dumps(rule.__dict__, indent=2))


@app.command()
def explain(report: Path, finding_id: str) -> None:
    data = json.loads(report.read_text())
    findings = data.get("findings", [])
    for finding in findings:
        if finding.get("id") == finding_id:
            console.print(json.dumps(finding, indent=2))
            return
    raise typer.Exit(code=1)
