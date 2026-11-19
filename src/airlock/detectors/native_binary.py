"""`native_binary` detector: report tracked native executable binaries as metadata (Issue #43)."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, overload

from ..fingerprint import PendingFinding
from ..model import FileEntry, Rule, ScanContext, Severity
from ..roles import NATIVE_ROLE
from ..rules import finding_for

RULE_ID = "native-binary-artifact"


def _require_rule(rules: dict[str, Rule]) -> Rule:
    rule = rules.get(RULE_ID)
    if rule is None:
        raise ValueError(f"native_binary cannot run without the {RULE_ID} rule loaded")
    return rule


def _format_message(path: str, sha256: str | None) -> str:
    digest = sha256 or "unknown"
    return f"Tracked executable binary artifact: {path} (SHA-256: {digest})"


def run(ctx: ScanContext) -> Iterable[PendingFinding]:
    """Emit one WARN finding for each tracked file with the native-binary role."""
    rules = {rule.id: rule for rule in ctx.rules}
    rule = _require_rule(rules)
    for entry in ctx.entries:
        if NATIVE_ROLE in entry.roles:
            yield finding_for(
                rule,
                entry,
                1,
                evidence=entry.sha256,
                message=_format_message(entry.path, entry.sha256),
            )


@overload
def native_binary(
    entry_or_ctx: ScanContext,
    options: None = None,
    emit: None = None,
) -> Iterable[PendingFinding]: ...


@overload
def native_binary(
    entry_or_ctx: FileEntry | Any,
    options: Any,
    emit: Callable[[PendingFinding], None],
) -> None: ...


def native_binary(
    entry_or_ctx: ScanContext | FileEntry | Any,
    options: Any = None,
    emit: Callable[[PendingFinding], None] | None = None,
) -> Iterable[PendingFinding] | None:
    """Detect tracked native executable binaries.

    Can be invoked either as a runner Detector: `native_binary(ctx) -> Iterable[PendingFinding]`,
    or per the entry-level detector contract: `native_binary(entry, options, emit) -> None`.
    """
    if isinstance(entry_or_ctx, ScanContext):
        return run(entry_or_ctx)
    if emit is not None:
        entry = entry_or_ctx
        if NATIVE_ROLE in getattr(entry, "roles", ()):
            path = getattr(entry, "path", "<unknown>")
            sha256 = getattr(entry, "sha256", None)
            roles = tuple(getattr(entry, "roles", ()))
            finding = PendingFinding(
                rule_id=RULE_ID,
                severity=Severity.WARN,
                path=path,
                line=1,
                roles=roles,
                message=_format_message(path, sha256),
                evidence=sha256,
                suppressible=True,
                file_sha256=sha256,
            )
            emit(finding)
    return ()


native_binary.run = run  # type: ignore[attr-defined]
