"""`pat-editor-command-path` false positive on terminal preferences (issue 41).

In `.vscode/settings.json`, `terminal.integrated.defaultProfile.*` and
`terminal.integrated.shellArgs.*` specify shell preferences, NOT an executable path to run.
Removing `defaultProfile` and `shellArgs` from the alternation pattern stops false positives,
while actual executable and compiler paths (`python.defaultInterpreterPath`, `typescript.tsdk`)
must continue to trigger WARN.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from tests.fixtures import Case, context, fired, scan
from tests.fixtures.editor_profile_fp import (
    executable_paths,
    python_interpreter_path,
    terminal_preferences,
    typescript_tsdk,
)

from airlock.model import Finding, Severity

RULE_ID = "pat-editor-command-path"


def findings_for(case: Case) -> list[Finding]:
    return [finding for finding in scan(context(case)) if finding.rule_id == RULE_ID]


class TestEditorProfileFalsePositive:
    def test_terminal_preferences_do_not_fire_editor_command_path(self) -> None:
        hits = fired(terminal_preferences())
        assert RULE_ID not in hits

    def test_terminal_preferences_produce_no_editor_command_findings(self) -> None:
        findings = findings_for(terminal_preferences())
        assert findings == []

    @pytest.mark.parametrize(
        ("case_fn", "expected_key"),
        [
            (python_interpreter_path, "python.defaultInterpreterPath"),
            (typescript_tsdk, "typescript.tsdk"),
        ],
        ids=["python-interpreter", "typescript-tsdk"],
    )
    def test_executable_paths_still_trigger_warn(
        self, case_fn: Callable[[], Case], expected_key: str
    ) -> None:
        case = case_fn()
        hits = fired(case)
        assert RULE_ID in hits

        findings = findings_for(case)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARN

    def test_combined_executable_paths_trigger_warn(self) -> None:
        case = executable_paths()
        hits = fired(case)
        assert RULE_ID in hits

        findings = findings_for(case)
        assert len(findings) == 2
        assert all(f.severity == Severity.WARN for f in findings)
