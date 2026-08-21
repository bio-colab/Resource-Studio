from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]


def main() -> None:
    probe = "import sys; import resource_studio_cli; print(sorted(name for name in sys.modules if name == 'core' or name.startswith('core.')))"
    result = subprocess.run([sys.executable, "-c", probe], cwd=ROOT, check=True, capture_output=True, text=True)
    assert result.stdout.strip() == "[]", result.stdout
    print("cli-startup-contract-tests: passed")


if __name__ == "__main__":
    main()
