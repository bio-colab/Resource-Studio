from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

trigger = Path(sys.argv[1])
pid_file = Path(sys.argv[2])
grandchild_script = Path(sys.argv[3])
while not trigger.exists():
    time.sleep(0.05)
child = subprocess.Popen([sys.executable, str(grandchild_script)])
pid_file.write_text(str(child.pid), encoding="ascii")
try:
    child.wait()
finally:
    if child.poll() is None:
        child.kill()
while True:
    time.sleep(1)
