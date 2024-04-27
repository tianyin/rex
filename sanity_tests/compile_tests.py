#!/bin/python

import os
import argparse
import subprocess
from tqdm import tqdm
from pathlib import Path


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
        if args.clean_build:
            command = "make clean; make"
        else:
            command = "make"

        os.chdir(directory)
        subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        print(f"Build succeeded in {directory}")
    except subprocess.CalledProcessError as e:
        print(f"Build failed in {directory}\nError: {e.stderr}")
    finally:
        os.chdir("..")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Run make commands in specified directories."
    )
    parser.add_argument(
        "--clean-build", action="store_true", help="Perform rust clean build."
    )
    return parser.parse_args()


def main():

    original_dir = os.getcwd()
    os.chdir(repo_path)

    # get samples_list
    samples_list = list(samples_path.iterdir())
    # filter out directory
    samples_list = [
        item
        for item in samples_list
        if item.is_dir() and item.name not in exclusion_list
    ]

    # import concurrent.futures
    # with concurrent.futures.ThreadPoolExecutor() as executor:
    #     list(
    #         tqdm(
    #             executor.map(run_make, samples_list),
    #             total=len(samples_list),
    #             desc="Building",
    #         )
    #     )
    for dir in tqdm(samples_list, desc="Building"):
        run_make(dir)
    print("All builds completed.")
    os.chdir(original_dir)


if __name__ == "__main__":
    main()
