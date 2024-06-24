#!/bin/python

import argparse
import os
import subprocess
import time

from pathlib import Path
from tqdm import tqdm

exclusion_list = ["cpustat", "memcached_benchmark"]

script_path = Path(__file__).resolve()
repo_path = script_path.parent.parent
samples_path = repo_path.joinpath("samples")

# Set Path env
kernel_path = repo_path.joinpath("./linux")
rust_path = repo_path.joinpath("./rust/dist/bin")

os.environ["PATH"] = str(rust_path) + os.pathsep + os.environ["PATH"]
os.environ["LINUX"] = str(kernel_path)
os.environ["RUST_BACKTRACE"] = "1"

# Run make
def run_make(directory):
    try:
        args = parse_arguments()
        if not args.no_clean_build:
            command = "make clean; make"
        else:
            command = "make"

        os.chdir(directory)
        subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        # print(f"Build succeeded in {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Build failed in {directory}")
        print(f"Error: {e.stderr}")
    finally:
        os.chdir("..")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run make commands in specified directories."
    )
    parser.add_argument(
        "--no-clean-build", action="store_true", help="Perform rust clean build."
    )
    return parser.parse_args()

def is_sample(path):
    return path.is_dir() and path.name not in exclusion_list

def main():
    original_dir = os.getcwd()
    os.chdir(repo_path)

    # get samples_list
    samples_list = list(samples_path.iterdir())
    # filter out directory
    samples_list = sorted(filter(is_sample, samples_list),
                          key=lambda x: x.name)

    # import concurrent.futures
    # with concurrent.futures.ThreadPoolExecutor() as executor:
    #     list(
    #         tqdm(
    #             executor.map(run_make, samples_list),
    #             total=len(samples_list),
    #             desc="Building",
    #         )
    #     )
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
