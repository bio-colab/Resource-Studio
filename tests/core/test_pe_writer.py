from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.pe_writer import LiefPEWriter
from core.string_table import StringTableBlock


MANIFEST = """<?xml version='1.0'?>\n<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'><assemblyIdentity name='ResourceStudioTest' version='1.0.0.0'/><trustInfo xmlns='urn:schemas-microsoft-com:asm.v3'><security><requestedPrivileges><requestedExecutionLevel level='asInvoker' uiAccess='false'/></requestedPrivileges></security></trustInfo></assembly>"""


def main() -> None:
    source = Path("tests/fixtures/sample.dll").resolve()
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    writer = LiefPEWriter()
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "modified.dll"
        try:
            writer.replace_manifest(source, source, MANIFEST)
        except Exception as exc:
            assert "in-place writes are disabled" in str(exc)
        else:
            raise AssertionError("in-place write was accepted")
        result = writer.replace_manifest(source, output, MANIFEST)
        assert result.verified is True
        assert result.input_path == str(source)
        assert output.is_file()
        assert result.before_sha256 == source_hash
        assert result.after_sha256 != source_hash
        output_report = writer.validate_output(output)
        assert output_report.is_pe is True
        assert output_report.resource_index
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash

        payload_output = Path(temporary) / "modified-again.dll"
        payload = MANIFEST.encode("utf-8")
        result2 = writer.replace_resource(source, payload_output, "MANIFEST", 1, 1033, payload)
        assert result2.verified is True
        assert payload_output.is_file()

        added_output = Path(temporary) / "added.dll"
        result3 = writer.add_resource(source, added_output, "RCDATA", 999, 1033, b"new-resource")
        assert result3.verified is True
        string_output = Path(temporary) / "string.dll"
        string_payload = StringTableBlock(3, tuple(["Hello"] + [""] * 15)).to_bytes()
        result_string = writer.add_typed_resource(source, string_output, "STRING", 3, 1033, string_payload)
        assert result_string.verified is True
        assert writer.validate_output(string_output).is_pe is True
        deleted_output = Path(temporary) / "deleted.dll"
        result4 = writer.delete_resource(added_output, deleted_output, "RCDATA", 999, 1033)
        assert result4.verified is True

        language_output = Path(temporary) / "language.dll"
        result5 = writer.change_language(source, language_output, "MANIFEST", 1, 1033, 1025)
        assert result5.verified is True

        writer.replace_manifest(source, payload_output, MANIFEST + "\n")
        backup = payload_output.with_suffix(payload_output.suffix + ".bak")
        assert backup.is_file()
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash

    print("pe-writer-tests: passed")


if __name__ == "__main__":
    main()
