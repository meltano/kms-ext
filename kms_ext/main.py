"""KMS cli entrypoint."""

import sys
from pathlib import Path
from typing import Optional

import structlog
import typer
from meltano.edk.extension import DescribeFormat
from meltano.edk.logging import default_logging_config, parse_log_level

from kms_ext.extension import KMS

APP_NAME = "KMS"

log = structlog.get_logger(APP_NAME)

ext = KMS()

typer.core.rich = None  # remove to enable stylized help output when `rich` is installed
app = typer.Typer(
    name=APP_NAME,
    pretty_exceptions_enable=False,
)


@app.command()
def describe(
    output_format: DescribeFormat = typer.Option(
        DescribeFormat.text, "--format", help="Output format"
    )
) -> None:
    """Describe the available commands of this extension."""
    try:
        typer.echo(ext.describe_formatted(output_format))
    except Exception:
        log.exception(
            "describe failed with uncaught exception, please report to maintainer"
        )
        sys.exit(1)


@app.command()
def encrypt(
    public_key_path: Path,
    dotenv_path: Optional[Path] = typer.Option(Path(".env")),
    output_path: Optional[Path] = typer.Option(Path("secrets.yml")),
) -> None:
    """Encrypt a given dotenv file with a give RSA Public Key (PEM file)."""
    ext.encrypt(
        public_key_path=public_key_path,
        dotenv_path=dotenv_path,
        output_path=output_path,
    )
    typer.echo(f"Successfully encrypted dotenv file '{dotenv_path}' to '{output_path}'")


@app.command()
def decrypt(
    kms_key_id: str,
    input_path: Optional[Path] = typer.Option(Path("secrets.yml")),
    output_path: Optional[Path] = typer.Option(Path(".env")),
) -> None:
    """Decrypt a given secrets file to a given dotenv file using AWS KMS."""
    ext.decrypt(kms_key_id=kms_key_id, input_path=input_path, output_path=output_path)
    typer.echo(f"Successfully decrypted secrets file '{input_path}' to '{output_path}'")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    log_level: str = typer.Option("INFO", envvar="LOG_LEVEL"),
    log_timestamps: bool = typer.Option(
        False, envvar="LOG_TIMESTAMPS", help="Show timestamp in logs"
    ),
    log_levels: bool = typer.Option(
        False, "--log-levels", envvar="LOG_LEVELS", help="Show log levels"
    ),
    meltano_log_json: bool = typer.Option(
        False,
        "--meltano-log-json",
        envvar="MELTANO_LOG_JSON",
        help="Log in the meltano JSON log format",
    ),
) -> None:
    """Simple Meltano extension that wraps the `cryptography` python package and AWS KMS API."""
    default_logging_config(
        level=parse_log_level(log_level),
        timestamps=log_timestamps,
        levels=log_levels,
        json_format=meltano_log_json,
    )
