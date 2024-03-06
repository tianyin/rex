import csv

import matplotlib.pyplot as plt
import numpy as np

with open('bmc-results.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)

    data = [row for row in reader][1:]
    nr_cpu = [float(row[0]) for row in data]
    vanilla = [float(row[1]) for row in data]
    bpf = [float(row[2]) for row in data]
    rust = [float(row[3]) for row in data]

penguin_means = {
    'Vanilla': np.array(vanilla) / 1000 / 1000,
    'eBPF': np.array(bpf) / 1000 / 1000,
    'REX': np.array(rust) / 1000 / 1000,
}

with plt.style.context('seaborn-v0_8-talk'):
    x = np.arange(len(data))  # the label locations
    width = 0.25  # the width of the bars
    multiplier = 0

    fig, ax = plt.subplots(layout='constrained')
    fig.set_size_inches(8, 4.8)

    for attribute, measurement in penguin_means.items():
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute)
        multiplier += 1

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_xlabel('# of cores')
    ax.set_ylabel('Throughput\n(MReq/s)')
    ax.set_xticks(x + width, x + 1)
    ax.legend(loc='upper left', ncols=3)

    plt.savefig("bmc.pdf")
