"""Tests for deterministic fingerprint occurrence numbering (Issue #49).

Verifies that permuting pending findings before occurrence numbering never changes
the assigned occurrence indices, line-to-fingerprint mappings, or final output order,
even when duplicates share rule, path, and evidence across different lines.
Also verifies that detector registration/dispatch order in the runner does not affect
the final scan findings.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable

import pytest

from airlock import runner
from airlock.fingerprint import PendingFinding, number_occurrences
from airlock.model import Manifest, Policy, ScanContext, Severity


def _make_pending(
    *,
    rule_id: str,
    severity: Severity = Severity.HIGH,
    path: str,
    line: int,
    roles: tuple[str, ...] = ("source",),
    message: str = "test finding message",
    evidence: str | None = None,
    suppressible: bool = False,
    file_sha256: str | None = None,
) -> PendingFinding:
    """Build a PendingFinding locally without importing test helpers from other files."""
    return PendingFinding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        roles=roles,
        message=message,
        evidence=evidence,
        suppressible=suppressible,
        file_sha256=file_sha256,
    )


def test_fingerprint_numbering_order_invariance() -> None:
    """Assert number_occurrences produces identical results across all 24 permutations."""
    # Build 4 PendingFinding instances locally.
    # Findings 1 and 2 form a duplicate group sharing rule, path, and evidence
    # across lines 10 and 42.
    f1 = _make_pending(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="src/index.js",
        line=10,
        evidence="eval(payload)",
    )
    f2 = _make_pending(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="src/index.js",
        line=42,
        evidence="eval(payload)",
    )
    f3 = _make_pending(
        rule_id="cfg-network",
        severity=Severity.HIGH,
        path="src/index.js",
        line=15,
        evidence="fetch(url)",
    )
    f4 = _make_pending(
        rule_id="cfg-dynamic-code",
        severity=Severity.WARN,
        path="src/utils.js",
        line=5,
        evidence="eval(other)",
    )

    findings = [f1, f2, f3, f4]

    # Compute baseline from canonical order
    baseline = number_occurrences(findings)
    assert len(baseline) == 4

    # Baseline mappings and sequences
    baseline_line_map = {f.line: f.fingerprint for f in baseline}
    baseline_occurrences = [f.occurrence for f in baseline]

    # Verify duplicate group occurrence assignment: earlier line gets 0, later line gets 1
    f1_result = next(f for f in baseline if f.line == 10)
    f2_result = next(f for f in baseline if f.line == 42)
    assert f1_result.occurrence == 0
    assert f2_result.occurrence == 1
    assert f1_result.fingerprint != f2_result.fingerprint

    # Permute all 4 findings across all 24 possible orders
    all_permutations = list(itertools.permutations(findings))
    assert len(all_permutations) == 24

    for perm in all_permutations:
        result = number_occurrences(list(perm))
        # Exact same line-to-fingerprint map
        line_map = {f.line: f.fingerprint for f in result}
        assert line_map == baseline_line_map
        # Identical occurrence sequence
        assert [f.occurrence for f in result] == baseline_occurrences
        # Identical findings in report order
        assert result == baseline


def test_runner_dispatch_order_invariance(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run two stub detectors in both orders through a scan and assert identical final findings."""
    ctx = ScanContext(
        entries=(),
        policy=Policy(),
        manifest=Manifest(),
        rules=(),
    )

    # Stub detectors that emit findings sharing rule, path, and evidence across lines.
    # Detector 1 emits the later line (line 42) and another finding.
    # Detector 2 emits the earlier line (line 10) and another finding.
    # Their dispatch order inverts the arrival order of findings in the duplicate group.
    finding_line_42 = _make_pending(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="src/index.js",
        line=42,
        evidence="eval(payload)",
    )
    finding_line_5 = _make_pending(
        rule_id="cfg-dynamic-code",
        severity=Severity.WARN,
        path="src/utils.js",
        line=5,
        evidence="eval(other)",
    )
    finding_line_10 = _make_pending(
        rule_id="cfg-dynamic-code",
        severity=Severity.HIGH,
        path="src/index.js",
        line=10,
        evidence="eval(payload)",
    )
    finding_line_15 = _make_pending(
        rule_id="cfg-network",
        severity=Severity.HIGH,
        path="src/index.js",
        line=15,
        evidence="fetch(url)",
    )

    def stub_detector_a(context: ScanContext) -> Iterable[PendingFinding]:
        yield finding_line_42
        yield finding_line_5

    def stub_detector_b(context: ScanContext) -> Iterable[PendingFinding]:
        yield finding_line_10
        yield finding_line_15

    # Run with detectors registered in order A then B
    monkeypatch.setattr(runner, "DETECTORS", (stub_detector_a, stub_detector_b))
    findings_ab = runner.scan(ctx)

    # Run with detectors registered in order B then A
    monkeypatch.setattr(runner, "DETECTORS", (stub_detector_b, stub_detector_a))
    findings_ba = runner.scan(ctx)

    # Assert identical final findings regardless of detector registration order
    assert findings_ab == findings_ba
    assert len(findings_ab) == 4
    assert [f.fingerprint for f in findings_ab] == [f.fingerprint for f in findings_ba]
    assert [f.occurrence for f in findings_ab] == [f.occurrence for f in findings_ba]
    assert {f.line: f.fingerprint for f in findings_ab} == {
        f.line: f.fingerprint for f in findings_ba
    }
