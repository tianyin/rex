import csv
import resource
import subprocess


CLIENT_IP = "192.168.50.253"

import numpy as np
from tqdm import tqdm

class MemcachedCtx:
    def __init__(self, start, stop):
        self.start = start
        self.stop = stop

    def __enter__(self):
        subprocess.run(self.start, check=True, capture_output=True)

    def __exit__(self, *args):
        subprocess.run(self.stop, check=True, capture_output=True)

def increase_fd_limit(new_limit):
    # Get the current soft and hard limits
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"Current Limits - Soft: {soft_limit}, Hard: {hard_limit}")

    # Check if the new limit is within the permissible range
    if new_limit <= hard_limit:
        # Set the new soft limit
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, hard_limit))
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f"File descriptor soft_limit increased to { soft_limit }")
    else:
        print("Requested limit exceeds the hard limit. Cannot increase beyond the hard limit.")

def run_bench():
    # cmd = 'cargo run -r -- bench -n 200000000 -t 40 -s 10.0.1.1 -p 11211'.split()
    cmd = 'cargo run -r -- bench -n 20000000 -t 40 -s 10.0.1.1 -p 11211'.split()
    p = subprocess.run(cmd, check=True, capture_output=True)
    output = p.stdout.decode('utf-8').split('\n')
    output = filter(lambda x: x.startswith('Throughput across all threads:'),
                    map(str.strip, output))
    output = list(output)
    assert len(output) == 1
    return float(output[0].split()[4])

def run_vanilla(nr_threads):
    start = [*f'ssh {CLIENT_IP} -t'.split(),
             'sudo /root/run-memcached.sh %d' % nr_threads]

    stop = [*f'ssh {CLIENT_IP} -t'.split(),
            'sudo /root/stop-memcached.sh %d' % nr_threads]

    with MemcachedCtx(start, stop):
        result = run_bench()

    return result

def run_bpf(nr_threads):
    start = [*f'ssh {CLIENT_IP} -t'.split(),
             'sudo /root/attach-bpf.sh %d' % nr_threads]

    stop = [*f'ssh {CLIENT_IP} -t'.split(),
            'sudo /root/detach-bpf.sh %d' % nr_threads]

    with MemcachedCtx(start, stop):
        result = run_bench()

    return result

def run_rust(nr_threads):
    start = [*f'ssh {CLIENT_IP} -t'.split(),
             'sudo /root/attach-rust.sh %d' % nr_threads]

    stop = [*f'ssh {CLIENT_IP} -t'.split(),
            'sudo /root/detach-rust.sh %d' % nr_threads]

    with MemcachedCtx(start, stop):
        result = run_bench()

    return result

def main():
    max_cpu = 8
    rounds = 10
    increase_fd_limit(102400)

    data = {
        'vanilla': [[0 for j in range(rounds)] for i in range(max_cpu)],
        'bpf': [[0 for j in range(rounds)] for i in range(max_cpu)],
        'rust': [[0 for j in range(rounds)] for i in range(max_cpu)],
    }

    for i in tqdm(range(max_cpu), desc=" outer loop", position=0):
        for j in tqdm(range(rounds), desc=" inner loop", position=1, leave=False):
            data['vanilla'][i][j] = run_vanilla(i + 1)
            data['bpf'][i][j] = run_bpf(i + 1)
            data['rust'][i][j] = run_rust(i + 1)

    result = [('nr_cpu', *data.keys(),
               *list(map(lambda x: x + '-stdev', data.keys())))]

    for i in range(max_cpu):
        row = [i]

        for v in data.values():
            row.append(np.mean(v[i]))

        for v in data.values():
            row.append(np.std(v[i]))

        result.append(tuple(row))

    with open('bmc-results.csv', 'w', newline='') as out_f:
        writer = csv.writer(out_f)
        writer.writerows(result)

    return 0

if __name__ == '__main__':
    exit(main())
