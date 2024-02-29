import csv
import subprocess

from tqdm import tqdm
import numpy as np

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
    start = [*'ssh 10.0.0.3 -t'.split(),
             'sudo /root/run-memcached.sh %d' % nr_threads]

    stop = [*'ssh 10.0.0.3 -t'.split(),
            'sudo /root/stop-memcached.sh %d' % nr_threads]

    subprocess.run(start, check=True, capture_output=True)
    result = run_bench()
    subprocess.run(stop, check=True, capture_output=True)

    return result

def run_bpf(nr_threads):
    start = [*'ssh 10.0.0.3 -t'.split(),
             'sudo /root/attach-bpf.sh %d' % nr_threads]

    stop = [*'ssh 10.0.0.3 -t'.split(),
            'sudo /root/detach-bpf.sh %d' % nr_threads]

    subprocess.run(start, check=True, capture_output=True)
    result = run_bench()
    subprocess.run(stop, check=True, capture_output=True)

    return result

def run_rust(nr_threads):
    start = [*'ssh 10.0.0.3 -t'.split(),
             'sudo /root/attach-rust.sh %d' % nr_threads]

    stop = [*'ssh 10.0.0.3 -t'.split(),
            'sudo /root/detach-rust.sh %d' % nr_threads]

    subprocess.run(start, check=True, capture_output=True)
    result = run_bench()
    subprocess.run(stop, check=True, capture_output=True)

    return result

def main():
    max_cpu = 8
    rounds = 1

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

    result = [('nr_cpu', *data.keys())]

    for i in range(max_cpu):
        row = [i]
        for v in data.values():
            row.append(np.mean(v[i]))

        result.append(tuple(row))

    with open('bmc-results.csv', 'w', newline='') as out_f:
        writer = csv.writer(out_f)
        writer.writerows(result)

    return 0

if __name__ == '__main__':
    exit(main())