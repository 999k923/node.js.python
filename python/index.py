#!/usr/bin/env python3
import subprocess
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

try:
    subprocess.run(
        ["bash", "start.sh"],
        check=True
    )
except subprocess.CalledProcessError as e:
    print("start.sh 执行失败", file=sys.stderr)
    sys.exit(e.returncode)
