#!/usr/bin/env python
# coding=utf-8

import pandas as pd
import numpy as np
import sys

from matplotlib import pyplot as plt

def get_pcap_name(pcap_path):
    while pcap_path.find('/') != -1:
        pcap_path = pcap_path[pcap_path.find('/') + 1 :]
    pcap_name = pcap_path[: pcap_path.find('.')]
    return pcap_name

pcap_path = sys.argv[1]
FMgrace = int(sys.argv[2]) #the number of instances taken to learn the feature mapping (the ensemble's architecture)
ADgrace = int(sys.argv[3]) #the number of instances used to train the anomaly detector (ensemble itself)
RMSEs_path = sys.argv[4]
logProbs_path = sys.argv[5]

RMSEs = np.array(pd.read_csv(RMSEs_path))
logProbs = np.array(pd.read_csv(logProbs_path))

plt.figure(figsize=(10,5))
fig = plt.scatter(range(FMgrace+ADgrace+1,len(RMSEs)),RMSEs[FMgrace+ADgrace+1:],s=0.1,c=logProbs[FMgrace+ADgrace+1:],cmap='RdYlGn')
plt.yscale("log")
plt.title("Anomaly Scores from Kitsune's Execution Phase")
plt.ylabel("RMSE (log scaled)")
plt.xlabel("Time elapsed [min]")
plt.annotate('Mirai C&C channel opened [Telnet]', xy=(121662,RMSEs[121662]), xytext=(151662,1),arrowprops=dict(facecolor='black', shrink=0.05),)
plt.annotate('Mirai Bot Activated\nMirai scans network\nfor vulnerable devices', xy=(122662,10), xytext=(122662,150),arrowprops=dict(facecolor='black', shrink=0.05),)
plt.annotate('Mirai Bot launches DoS attack', xy=(370000,100), xytext=(390000,1000),arrowprops=dict(facecolor='black', shrink=0.05),)
figbar=plt.colorbar()
figbar.ax.set_ylabel('Log Probability\n ', rotation=270)
plt.savefig("../Kitsune-py/results/" + get_pcap_name(pcap_path) + "_fig.pdf")
plt.show()
