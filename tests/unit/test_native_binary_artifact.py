"""Tests for `native_binary` detector and `native-binary-artifact` rule (Issue #43)."""

from __future__ import annotations

from tests.fixtures import Case, File, context
from tests.fixtures.native_binary_artifact import ELF_MAGIC, MACHO_MAGIC, ZIP_MAGIC

from airlock.detectors.native_binary import RULE_ID, native_binary
from airlock.fingerprint import PendingFinding
from airlock.model import FileEntry, Severity
from airlock.roles import NATIVE_ROLE, SOURCE_ROLE
from airlock.runner import scan


def findings_for(files: tuple[File, ...]) -> list:
    ctx = context(Case(files=files))
    return [finding for finding in scan(ctx) if finding.rule_id == RULE_ID]


class TestNativeBinaryDetector:
    def test_elf_fires_warn(self) -> None:
        files = (File("bin/tool_elf", raw=ELF_MAGIC + b"\x01\x01\x01" + b"\x00" * 32),)
        findings = findings_for(files)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == RULE_ID
        assert finding.severity is Severity.WARN
        assert finding.line == 1
        assert finding.path == "bin/tool_elf"
        assert finding.suppressible is True
        assert finding.evidence is not None
        assert finding.evidence in finding.message
        assert "SHA-256:" in finding.message

    def test_macho_fires_warn(self) -> None:
        files = (File("bin/tool_macho", raw=MACHO_MAGIC + b"\x00" * 32),)
        findings = findings_for(files)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == RULE_ID
        assert finding.severity is Severity.WARN
        assert finding.line == 1
        assert finding.path == "bin/tool_macho"
        assert finding.suppressible is True

    def test_macho_reverse_endian_fires_warn(self) -> None:
        files = (File("bin/tool_macho_rev", raw=b"\xcf\xfa\xed\xfe" + b"\x00" * 32),)
        findings = findings_for(files)
        assert len(findings) == 1
        assert findings[0].rule_id == RULE_ID
        assert findings[0].severity is Severity.WARN

    def test_rust_source_does_not_fire(self) -> None:
        files = (File("src/main.rs", text='fn main() {\n    println!("hello");\n}\n'),)
        findings = findings_for(files)
        assert findings == []

    def test_archive_does_not_fire(self) -> None:
        files = (File("vendor/bundle.zip", raw=ZIP_MAGIC + b"\x00" * 32),)
        findings = findings_for(files)
        assert findings == []

    def test_plain_text_does_not_fire(self) -> None:
        files = (File("docs/readme.txt", text="Some documentation\n"),)
        findings = findings_for(files)
        assert findings == []

    def test_detector_contract_entry_options_emit(self) -> None:
        emitted: list[PendingFinding] = []

        binary_entry = FileEntry(
            path="bin/payload",
            sha256="0123456789abcdef" * 4,
            roles=(NATIVE_ROLE,),
            text=None,
        )
        native_binary(binary_entry, options=None, emit=emitted.append)
        assert len(emitted) == 1
        assert emitted[0].rule_id == RULE_ID
        assert emitted[0].line == 1
        assert emitted[0].severity is Severity.WARN
        assert "0123456789abcdef" in emitted[0].message

        source_entry = FileEntry(
            path="src/lib.rs",
            sha256="fedcba9876543210" * 4,
            roles=(SOURCE_ROLE,),
            text="pub fn run() {}\n",
        )
        native_binary(source_entry, options=None, emit=emitted.append)
        assert len(emitted) == 1  # Unchanged, did not emit for source
