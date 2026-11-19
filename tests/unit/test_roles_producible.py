"""Tests ensuring every declared role in rule data is producible (Issue #51).

If a glob in `rules/roles.toml` has a typo or impossible pattern (e.g., leading `./`
or unmatched segment structures), the role is known to the engine but no file will
ever match it, silently disabling rules that target it.

This test derives a representative sample path for each declared glob and verifies
that `resolve_roles` produces the declared role.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from airlock.roles import resolve_roles
from airlock.rules import load_role_globs

REPO_ROOT = Path(__file__).resolve().parents[2]
ROLES_FILE = REPO_ROOT / "rules" / "roles.toml"

#: Magic roles are assigned from file header bytes, not path globs (ARCHITECTURE.md 6.2).
MAGIC_ROLES = frozenset({"wasm", "native-binary", "archive"})


def derive_sample_path(glob: str) -> str:
    """Derive a sample path that should match the given glob pattern.

    Strips leading directory-spanning wildcards ('**/') or relative prefixes ('./')
    and substitutes wildcard characters ('*' and '?') with representative valid characters.
    """
    path = glob
    while path.startswith("**/") or path.startswith("./"):
        if path.startswith("**/"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
    return path.replace("*", "a").replace("?", "a")


def assert_role_producible(
    role: str,
    glob: str,
    role_globs: Mapping[str, tuple[str, ...]],
) -> None:
    """Assert that a declared role is produced by resolve_roles for a glob's sample path.

    Fails naming the role and the glob if the role is not produced.
    """
    sample_path = derive_sample_path(glob)
    resolved = resolve_roles(sample_path, b"", role_globs)
    assert role in resolved, (
        f"Role {role!r} is not produced by glob {glob!r} "
        f"(sample path: {sample_path!r}, resolved roles: {resolved})"
    )


def assert_roles_producible(role_globs: Mapping[str, tuple[str, ...]]) -> None:
    """Assert that every non-magic declared role is producible from each of its globs."""
    for role, globs in sorted(role_globs.items()):
        if role in MAGIC_ROLES:
            continue
        for glob in globs:
            assert_role_producible(role, glob, role_globs)


ROLE_GLOBS = load_role_globs(ROLES_FILE)
ROLE_GLOB_PAIRS = [
    (role, glob)
    for role, globs in sorted(ROLE_GLOBS.items())
    if role not in MAGIC_ROLES
    for glob in globs
]


class TestRolesProducible:
    def test_every_declared_role_in_rules_data_is_producible(self) -> None:
        assert ROLE_GLOBS, "No role globs loaded from rules/roles.toml"
        assert_roles_producible(ROLE_GLOBS)

    def test_no_magic_roles_declared_in_roles_file(self) -> None:
        """rules/roles.toml must not declare magic roles (which are content-based)."""
        overlap = set(ROLE_GLOBS.keys()) & MAGIC_ROLES
        assert not overlap, f"Magic roles declared in roles file: {overlap}"

    def test_synthetic_unreachable_glob_fails_producibility_check(self) -> None:
        """A synthetic glob that cannot match repo-relative paths must fail the checker."""
        synthetic_mapping = {
            "unreachable-role": ("./impossible/path.js",),
        }
        with pytest.raises(AssertionError) as exc_info:
            assert_roles_producible(synthetic_mapping)
        message = str(exc_info.value)
        assert "unreachable-role" in message
        assert "./impossible/path.js" in message

    def test_magic_roles_are_excluded_from_glob_check(self) -> None:
        """Magic roles are determined by content headers, so they are excluded from glob checks."""
        synthetic_magic = {
            "wasm": ("./impossible.wasm",),
            "native-binary": ("./impossible.bin",),
            "archive": ("./impossible.zip",),
        }
        assert_roles_producible(synthetic_magic)

    @pytest.mark.parametrize(
        "role,glob",
        ROLE_GLOB_PAIRS,
        ids=[f"{r}:{g}" for r, g in ROLE_GLOB_PAIRS],
    )
    def test_individual_shipped_glob_is_producible(self, role: str, glob: str) -> None:
        assert_role_producible(role, glob, ROLE_GLOBS)
