from pathlib import Path

from typer.testing import CliRunner

from secure_ai_code_reviewer.cli import app


runner = CliRunner()


def test_cli_scan_exit_code(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "tests/fixtures/vulnerable_samples",
            "--format",
            "json",
            "--out",
            str(output),
        ],
    )
    assert result.exit_code == 1
    assert output.exists()
