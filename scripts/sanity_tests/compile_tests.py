#!/bin/python

import argparse
import os
import re
import subprocess
import sys
import time

from pathlib import Path
from tqdm import tqdm

exclusion_list = ["electrode", "memcached_benchmark"]

script_path = Path(__file__).resolve()
repo_path = script_path.parent.parent.parent
samples_path = repo_path.joinpath("samples")
librex_path = repo_path.joinpath("librex")

# Set Path env
kernel_path = repo_path.joinpath("./linux")
rust_path = repo_path.joinpath("./rust/dist/bin")

os.environ["PATH"] = str(rust_path) + os.pathsep + os.environ["PATH"]
os.environ["LINUX"] = str(kernel_path)
os.environ["RUST_BACKTRACE"] = "1"


def check_simd_inst(path):
    command = f"objdump -d {path}"
    result = subprocess.run(
        command, shell=True, capture_output=True, text=True, check=True
    )
    lines = result.stdout.splitlines()
    lines = [line.strip() for line in lines]
    for line in lines:
        # skip symbol name
        if line and re.match(r"\w+ <.+>:", line, re.I):
            continue
        if "mm" in line:
            print(line, file=sys.stderr)
            raise Exception(f"Found SIMD in program {path}")

# Run make
def run_make(directory):
    """Compile rex samples"""
    try:
        debug_target = ""
        release_target = ""

        args = parse_arguments()
        if not args.no_clean_build:
            command = "make clean; make LLVM=1"
        else:
            command = "make LLVM=1"

        if "librex" not in str(directory):
            # the naming rule for samples/trace_event is slightly different
            sample_name = (
                "trace_event_kern"
                if "trace_event" in str(directory)
                else directory.name
            )
            if args.debug:
                # also compile debug target
                debug_target = f"target/x86_64-unknown-linux-gnu/debug/{sample_name}"
                command += f" all {debug_target}"

            release_target = f"target/x86_64-unknown-linux-gnu/release/{sample_name}"

        os.chdir(directory)
        subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        if debug_target:
            check_simd_inst(debug_target)

        if release_target:
            check_simd_inst(release_target)

        # print(f"Build succeeded in {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Build failed in {directory}", file=sys.stderr)
        print(f"Error: {e.stderr}", file=sys.stderr)
    finally:
        os.chdir("..")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run make commands in specified directories."
    )
    parser.add_argument(
        "--no-clean-build", action="store_true", help="Perform rust clean build."
    )
    parser.add_argument("--debug", action="store_true", help="Perform debug build")

    return parser.parse_args()


def is_sample(path):
    return path.is_dir() and path.name not in exclusion_list


def main():
    original_dir = os.getcwd()
    os.chdir(repo_path)

    # get samples_list
    samples_list = list(samples_path.iterdir())
    # filter out directory
    samples_list = sorted(filter(is_sample, samples_list), key=lambda x: x.name)

    # append librex to compile list
    samples_list.insert(0, librex_path)
    with tqdm(total=len(samples_list), desc='   \033[34mBuilding\033[0m',
              leave=False, dynamic_ncols=True) as pbar:
        start_time = time.time()
        for dir in samples_list:
            print('', end='\x1b[1K\r')
            print('   \033[32mCompiling\033[0m %s' % dir.name)
            pbar.display()
            run_make(dir)
            pbar.update(1)
        end_time = time.time()

    elapsed = end_time - start_time
    print("All builds completed in %.3fs." % elapsed)
    os.chdir(original_dir)


if __name__ == "__main__":
    main()
