#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2023 Linutronix GmbH
#
# SPDX-License-Identifier: 0BSD

import argparse
import pandas as pd
import matplotlib.pyplot as plt

DATA_LABELS = {
        'txUser_txSched': 'Userspace to Queue',
        'txSched_txSw': 'Queuing',
        'txSw_txHw': 'Kernel to NIC',
        'txHw_rxHw': 'Transmission',
        'rxHw_rxSw': 'NIC to Kernel',
        'rxSw_rxUser': 'Kernel to Userspace'
        }

parser = argparse.ArgumentParser()
parser.add_argument('filename')
args = parser.parse_args()

df = pd.read_csv(args.filename)

time_cols = ['txUser','txSched','txSw','txHw','rxHw','rxSw','rxUser']

diff_df = pd.DataFrame(index=df.index)
for a,b in zip(time_cols[:-1], time_cols[1:]):
    diff_df[DATA_LABELS[f"{a}_{b}"]] = (df[b]-df[a])*1000*1000

diff_df.plot.barh(stacked=True, cmap='rainbow', xlabel="Latency [us]", ylabel="Packet")
plt.gca().invert_yaxis()
plt.show()

