import os
import time
import argparse
from pathlib import Path
from tqdm import tqdm
import subprocess


exclusion_list = ["cpustat", "memcached_benchmark"]

script_path = Path(__file__).resolve()
repo_path = script_path.parent.parent
samples_path = repo_path.joinpath("samples")
q_script = repo_path.joinpath("q-script/sanity-test-q")

# Set Path env
kernel_path = repo_path.joinpath("./linux")
rust_path = repo_path.joinpath("./rust/dist/bin")


def is_sample(path):
    return path.is_dir() and path.name not in exclusion_list


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=str, help="Single sample to run")

    args = parser.parse_args()

    # print(dirs)
    original_dir = os.getcwd()
    os.chdir(repo_path)

    # get samples_list
    samples_list = list(samples_path.iterdir())
    # filter out directory
    samples_list = sorted(filter(is_sample, samples_list), key=lambda x: x.name)

    # only run one repo
    if args.sample:
        samples_list = [args.sample]

    with tqdm(
        total=len(samples_list),
        desc="   \033[34mBuilding\033[0m",
        leave=False,
        dynamic_ncols=True,
    ) as pbar:
        start_time = time.time()
        for sample in samples_list:
            os.chdir(kernel_path)
            test_path = sample.joinpath("tests/runtest.py")

            # check if test exist
            if not test_path.is_file():
                continue

            cmd = " ".join([str(q_script), "-r", str(sample)])
            try:
                # print(cmd)
                qemu_proc = subprocess.run(
                    cmd, timeout=180, shell=True, capture_output=True, text=True
                )
                output = subprocess.run(
                    "cat auto_grade.txt | grep success",
                    capture_output=True,
                    text=True,
                    shell=True,
                )
                print(f"{sample.name}  {output.stdout}")

            except Exception:
                print(f"{sample.name} test run failed")
                subprocess.run("pkill qemu-system-x86", shell=True)
            finally:
                subprocess.run("rm auto_grade.txt", shell=True)
        end_time = time.time()

    elapsed = end_time - start_time
    print("All sanity tests completed successfully in %.3fs." % elapsed)
    os.chdir(original_dir)


if __name__ == "__main__":
    main()
