from pathlib import Path
import tempfile

from core.evidence_ledger import EvidenceLedger, EvidenceLedgerError, generate_ed25519_keypair


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-ledger-") as directory:
        root = Path(directory)
        ledger_path = root / "evidence.jsonl"
        ledger = EvidenceLedger(ledger_path)
        ledger.append({"operationId": "one", "value": 1})
        ledger.append({"operationId": "two", "value": 2})
        valid = ledger.verify()
        assert valid.valid is True
        assert valid.entries == 2
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"value":1', '"value":9')
        ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tampered = ledger.verify()
        assert tampered.valid is False
        assert any("hash mismatch" in error for error in tampered.errors)

        private_key = root / "ledger.key"
        public_key = root / "ledger.pub"
        signed_path = root / "signed.jsonl"
        try:
            generate_ed25519_keypair(private_key, public_key)
        except EvidenceLedgerError:
            pass
        else:
            signed = EvidenceLedger(signed_path, private_key=private_key, public_key=public_key)
            signed.append({"operationId": "signed", "value": 3})
            signed_result = signed.verify()
            assert signed_result.valid is True
            assert signed_result.signed is True
    print("evidence-ledger-tests: passed")


if __name__ == "__main__":
    main()
