"""Passthrough shim for KMS extension."""
import sys

import structlog
from meltano.edk.logging import pass_through_logging_config
from kms_ext.extension import KMS


def pass_through_cli() -> None:
    """Pass through CLI entry point."""
    pass_through_logging_config()
    ext = KMS()
    ext.pass_through_invoker(
        structlog.getLogger("kms_invoker"),
        *sys.argv[1:] if len(sys.argv) > 1 else []
    )
