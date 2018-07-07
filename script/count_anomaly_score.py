#!/usr/bin/env python
# coding=utf-8

import pandas as pd
import numpy as np
import sys
import os

RMSEs_folder_path = sys.argv[1]
threshold = float(sys.argv[2])

part_stats = {}
total_RMSEs = np.array(())

for file in os.listdir(RMSEs_folder_path):
    if "RMSEs" in file:
        part_num = file[file.find("part_") + 5 :]
        part_num = int(part_num[: part_num.find('_')])
        RMSEs_path = RMSEs_folder_path + '/' + file
        RMSEs = np.array(pd.read_csv(RMSEs_path))
        stats = {}
        stats["total_number"] = RMSEs.shape[0]
        stats["number_beyond_threshold"] = RMSEs[RMSEs > threshold].shape[0]
        stats["average_value"] = np.mean(RMSEs)
        stats["standard_deviation"] = np.std(RMSEs)
        stats["RMSEs"] = RMSEs
        part_stats[part_num] = stats

print('-' * 60)

for part_num in sorted(part_stats.keys()):
    stats = part_stats[part_num]
    total_RMSEs = np.append(total_RMSEs, stats["RMSEs"])
    print("Part %d:" % part_num)
    print("\tPackets total number: %d" % stats["total_number"])
    print("\tNumber beyond threshold: %d" % stats["number_beyond_threshold"])
    print("\tAverage RMSE value: %f" % stats["average_value"])
    print("\tRMSE standard deviation: %f" % stats["standard_deviation"])

print('-' * 60)

print("Total Results")
print("\tPackets total number: %d" % total_RMSEs.shape[0])
print("\tNumber beyond threshold: %d" % 
      total_RMSEs[total_RMSEs > threshold].shape[0])
print("\tAverage RMSE value: %f" % np.mean(total_RMSEs))
print("\tRMSE standard deviation: %f" % np.std(total_RMSEs))

print('-' * 60)
