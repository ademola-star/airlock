"""Terminal profile and shell args false-positive fixtures (issue 41).

In `.vscode/settings.json`, `terminal.integrated.defaultProfile.*` and
`terminal.integrated.shellArgs.*` specify shell preferences, NOT an executable path
to run. They should not trigger `pat-editor-command-path`.
"""

from __future__ import annotations

from . import Case, File

SETTINGS_PATH = ".vscode/settings.json"


def _settings(*lines: str) -> Case:
    return Case(files=(File(SETTINGS_PATH, text="\n".join(lines) + "\n"),))


def terminal_preferences() -> Case:
    """A `.vscode/settings.json` containing terminal profile and shell argument preferences."""
    return _settings(
        "{",
        '  "terminal.integrated.defaultProfile": "bash",',
        '  "terminal.integrated.defaultProfile.linux": "bash",',
        '  "terminal.integrated.shellArgs": ["-l"],',
        '  "terminal.integrated.shellArgs.linux": ["-l"]',
        "}",
    )


def executable_paths() -> Case:
    """A `.vscode/settings.json` containing actual executable and compiler paths."""
    return _settings(
        "{",
        '  "python.defaultInterpreterPath": "./venv/bin/python",',
        '  "typescript.tsdk": "./node_modules/typescript/lib"',
        "}",
    )


def python_interpreter_path() -> Case:
    """A `.vscode/settings.json` setting an interpreter path."""
    return _settings(
        "{",
        '  "python.defaultInterpreterPath": "./venv/bin/python"',
        "}",
    )


def typescript_tsdk() -> Case:
    """A `.vscode/settings.json` setting a compiler directory path."""
    return _settings(
        "{",
        '  "typescript.tsdk": "./node_modules/typescript/lib"',
        "}",
    )
