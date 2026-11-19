"""Synthetic native binary fixtures for executable binary detection (issue 43)."""

from __future__ import annotations

from . import Case, File, Fixture

ELF_MAGIC = b"\x7fELF"
MACHO_MAGIC = b"\xfe\xed\xfa\xce"
ZIP_MAGIC = b"PK\x03\x04"


def native_binary_artifact() -> Fixture:
    """Fixture providing positive native binary artifacts and negative controls."""
    return Fixture(
        positive=Case(
            files=(
                File("bin/tool_elf", raw=ELF_MAGIC + b"\x01\x01\x01" + b"\x00" * 32),
                File("bin/tool_macho", raw=MACHO_MAGIC + b"\x00" * 32),
            )
        ),
        negative=Case(
            files=(
                File("src/main.rs", text='fn main() {\n    println!("hello");\n}\n'),
                File("docs/readme.txt", text="Plain text documentation\n"),
                File("vendor/bundle.zip", raw=ZIP_MAGIC + b"\x00" * 32),
            )
        ),
    )


BUILDERS = {"native_binary_artifact": native_binary_artifact}
