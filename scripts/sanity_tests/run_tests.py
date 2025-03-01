#!/usr/bin/env bash

''':' ; exec "$(command -v python)" "$0" "$@"
'''

import os
import subprocess
import sys

from pathlib import Path

sample = Path(os.environ.get("SAMPLE_PATH"))
q_script = Path(os.environ.get("Q_SCRIPT"))

# Set Path env
kernel_path = Path(os.environ.get("KERNEL_PATH"))


def main():
    os.chdir(kernel_path)
    test_path = sample.joinpath("runtest.py")
    cmd = " ".join([str(q_script), "-t", str(test_path)])
    try:
        # print(cmd)
        subprocess.run(
            cmd, timeout=180, shell=True, capture_output=True, text=True
        )
        output = subprocess.run(
            "cat auto_grade.txt | grep success",
            capture_output=True,
            text=True,
            shell=True,
        )
        if output.stdout.strip() != "success":
            print("", end="\x1b[1K\r")
            print("   \033[91mFailed\033[0m  %s" % sample.name)
            exit(1)

    except Exception:
        print(f"{sample.name} test run failed", file=sys.stderr)
        subprocess.run("pkill qemu-system-x86", shell=True)
    finally:
        subprocess.run("rm auto_grade.txt", shell=True, check=True)


if __name__ == "__main__":
    main()
