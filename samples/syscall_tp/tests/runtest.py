#!/usr/bin/env python


import re
import subprocess
from time import sleep

process = 0


def count_bpf_programs():
    try:
        # Run bpftool to list all loaded BPF programs
        result = subprocess.run(
            "bpftool prog show",
            capture_output=True,
            shell=True,
            text=True,
        )

        # Process the output to count programs
        if result.stdout:
            # Each program details start on a new line
            output = result.stdout.strip().split("\n")
            programs = [line for line in output if "name" in line]
            return len(programs)
        else:
            return 0
    except FileNotFoundError:
        print("bpftool is not installed or not found in the PATH.")
        return 0
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0


def run_loader():
    global process
    process = subprocess.Popen(
        ["./syscall_tp"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def capture_output() -> bool:
    try:
        global process

        sleep(2)
        process.kill()
        std_out, std_err = process.communicate(timeout=7)
        prog_match = re.findall(r"prog #0: map ids \d \d", std_out, re.M)
        map_match = re.findall(r"verify map:\d val: \d", std_out, re.M)
        if len(prog_match) == 1 and len(map_match) == 2:
            print("Success")
            return True
        else:
            print("Failed")
            return False

    except subprocess.CalledProcessError:
        return False
    except subprocess.TimeoutExpired:
        process.kill()
        return False


def main():

    old_prog_num = count_bpf_programs()
    run_loader()
    count = 0
    while old_prog_num == count_bpf_programs():
        sleep(1)
        count += 1
        if count == 5:
            break
    grade_file = open("auto_grade.txt", "w")
    if capture_output():
        grade_file.write("success")
    else:
        grade_file.write("fail")


if __name__ == "__main__":
    main()
