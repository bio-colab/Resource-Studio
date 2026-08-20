from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from core.windows_isolation import WindowsJob, WindowsJobLimits

ROOT = Path(__file__).resolve().parents[2]
CHILD = ROOT / "tests" / "windows" / "job_child.py"
GRANDCHILD = ROOT / "tests" / "windows" / "job_grandchild.py"


def main() -> None:
    if os.name != "nt":
        print("job-tree-containment-tests: skipped (Windows only)")
        return
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        trigger = root / "go"
        pid_file = root / "grandchild.pid"
        child = subprocess.Popen([sys.executable, str(CHILD), str(trigger), str(pid_file), str(GRANDCHILD)])
        try:
            with WindowsJob(WindowsJobLimits(max_processes=4, max_memory_bytes=256 * 1024 * 1024)) as job:
                job.assign(child)
                trigger.write_text("go", encoding="ascii")
                deadline = time.time() + 10
                while not pid_file.exists() and time.time() < deadline:
                    time.sleep(0.05)
                assert pid_file.exists(), "grandchild was not created inside job"
                grandchild_pid = int(pid_file.read_text(encoding="ascii"))
            deadline = time.time() + 10
            while child.poll() is None and time.time() < deadline:
                time.sleep(0.05)
            assert child.poll() is not None, "child survived JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"
            probe = subprocess.run(["tasklist", "/FI", f"PID eq {grandchild_pid}"], capture_output=True, text=True, check=False)
            assert str(grandchild_pid) not in probe.stdout, "grandchild survived job close"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    print("job-tree-containment-tests: passed")


if __name__ == "__main__":
    main()
