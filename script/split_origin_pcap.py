#!/usr/bin/env python
# coding=utf-8

# Usage:
# python split_origin_pcap.py split_type split_num origin_pcap target_path(folder) train_num
# split_type: one in ["mod", "mod_execution", "random", "random_execution", "ecmp", "ecmp_execution", "host", "host_execution"]
# split_num: the number of parts to split origin pcap
# origin_pcap: origin_pcap to be split
# target_path: target folder to save split result pcap
# train_num: the number of packets used for training model

from scapy.utils import PcapWriter
from scapy.all import PcapReader, IP, TCP, UDP
import zlib
import struct
import socket
import random
import sys

split_type_list = [
    "mod", "mod_execution",
    "random", "random_execution",
    "ecmp", "ecmp_execution",
    "host", "host_execution"
]
writer_array = []

def get_pcap_name(pcap_path):
    while pcap_path.find('/') != -1:
        pcap_path = pcap_path[pcap_path.find('/') + 1 :]
    pcap_name = pcap_path[: pcap_path.find('.')]
    return pcap_name

def split_by_mod(reader):
    seq_num = 0
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        part_num = seq_num % split_num
        writer = writer_array[part_num]
        writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_mod_without_for_train(reader, train_num, split_num):
    '''
    Don't split packets used for training
    '''
    seq_num = 0
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        if seq_num <= train_num:
            for i in range(split_num):
                writer = writer_array[i]
                writer.write(pkt)
        else:
            part_num = seq_num % split_num
            writer = writer_array[part_num]
            writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_random(reader, split_num):
    seq_num = 0
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        part_num = random.randint(0, split_num - 1)
        writer = writer_array[part_num]
        writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_random_without_for_train(reader, train_num, split_num):
    '''
    Don't split packets used for training
    '''
    seq_num = 0
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        if seq_num <= train_num:
            for i in range(split_num):
                writer = writer_array[i]
                writer.write(pkt)
        else:
            part_num = random.randint(0, split_num - 1)
            writer = writer_array[part_num]
            writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_ecmp(reader, split_num):
    ''' 
    Return an ECMP-style 5-tuple hash for TCP/IP packets, otherwise 0.
    RFC2992
    '''
    seq_num = 0
    hash_input = [0] * 5
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        if "<IP " in repr(pkt) and "<TCP " in repr(pkt):
            ipsrc = socket.inet_aton(pkt[IP].src)
            hash_input[0] = struct.unpack("!I", ipsrc)[0]
            ipdst = socket.inet_aton(pkt[IP].dst)
            hash_input[1] = struct.unpack("!I", ipdst)[0]
            hash_input[2] = pkt[IP].proto
            hash_input[3] = pkt[TCP].sport
            hash_input[4] = pkt[TCP].dport
            hash_output = zlib.crc32(struct.pack('LLIII', *hash_input))
            part_num = hash_output % split_num
            writer = writer_array[part_num]
            writer.write(pkt)
        elif "<IP " in repr(pkt) and "<UDP " in repr(pkt):
            ipsrc = socket.inet_aton(pkt[IP].src)
            hash_input[0] = struct.unpack("!I", ipsrc)[0]
            ipdst = socket.inet_aton(pkt[IP].dst)
            hash_input[1] = struct.unpack("!I", ipdst)[0]
            hash_input[2] = pkt[IP].proto
            hash_input[3] = pkt[UDP].sport
            hash_input[4] = pkt[UDP].dport
            hash_output = zlib.crc32(struct.pack('LLIII', *hash_input))
            part_num = hash_output % split_num
            writer = writer_array[part_num]
            writer.write(pkt)
        else:
            part_num = random.randint(0, split_num - 1)
            writer = writer_array[part_num]
            writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_ecmp_without_for_train(reader, train_num, split_num):
    ''' 
    Return an ECMP-style 5-tuple hash for TCP/IP packets, otherwise 0.
    RFC2992
    '''
    seq_num = 0
    hash_input = [0] * 5
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        if seq_num <= train_num:
            for i in range(split_num):
                writer = writer_array[i]
                writer.write(pkt)
        else:
            if "<IP " in repr(pkt) and "<TCP " in repr(pkt):
                ipsrc = socket.inet_aton(pkt[IP].src)
                hash_input[0] = struct.unpack("!I", ipsrc)[0]
                ipdst = socket.inet_aton(pkt[IP].dst)
                hash_input[1] = struct.unpack("!I", ipdst)[0]
                hash_input[2] = pkt[IP].proto
                hash_input[3] = pkt[TCP].sport
                hash_input[4] = pkt[TCP].dport
                hash_output = zlib.crc32(struct.pack('LLIII', *hash_input))
                part_num = hash_output % split_num
                writer = writer_array[part_num]
                writer.write(pkt)
            elif "<IP " in repr(pkt) and "<UDP " in repr(pkt):
                ipsrc = socket.inet_aton(pkt[IP].src)
                hash_input[0] = struct.unpack("!I", ipsrc)[0]
                ipdst = socket.inet_aton(pkt[IP].dst)
                hash_input[1] = struct.unpack("!I", ipdst)[0]
                hash_input[2] = pkt[IP].proto
                hash_input[3] = pkt[UDP].sport
                hash_input[4] = pkt[UDP].dport
                hash_output = zlib.crc32(struct.pack('LLIII', *hash_input))
                part_num = hash_output % split_num
                writer = writer_array[part_num]
                writer.write(pkt)
            else:
                part_num = random.randint(0, split_num - 1)
                writer = writer_array[part_num]
                writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_host(reader, split_num):
    seq_num = 0
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        if "<IP " in repr(pkt):
            ipsrc = struct.unpack("!I", socket.inet_aton(pkt[IP].src))[0]
            part_num = ipsrc % split_num
            writer = writer_array[part_num]
            writer.write(pkt)
        else:
            part_num = random.randint(0, split_num - 1)
            writer = writer_array[part_num]
            writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

def split_by_host_without_for_train(reader, train_num, split_num):
    seq_num = 0
    while True:
        pkt = reader.read_packet()
        if pkt is None:
            break
        if seq_num <= train_num:
            for i in range(split_num):
                writer = writer_array[i]
                writer.write(pkt)
        else:
            if "<IP " in repr(pkt):
                ipsrc = struct.unpack("!I", socket.inet_aton(pkt[IP].src))[0]
                part_num = ipsrc % split_num
                writer = writer_array[part_num]
                writer.write(pkt)
            else:
                part_num = random.randint(0, split_num - 1)
                writer = writer_array[part_num]
                writer.write(pkt)
        if (seq_num + 1) % 1000 == 0:
            print("%d pkts have been split" % (seq_num + 1))
        seq_num += 1

if __name__ == '__main__':
    # Set and check options
    split_type = sys.argv[1]
    split_num = int(sys.argv[2])
    if split_type not in split_type_list:
        print("Error: not supported split type!")
        exit(-1)
    elif split_num < 1:
        print("Error: invalid split number !")
        exit(-2)
    reader = PcapReader(sys.argv[3])
    target_path = sys.argv[4]
    train_num = int(sys.argv[5])

    # Initial all parts' pcap writers
    for i in range(split_num):
        pcap_name = get_pcap_name(sys.argv[3])
        target_pcap = target_path + '/'
        target_pcap += "%s_by_%s_part_%d.pcap" % (pcap_name, split_type, i + 1)
        writer = PcapWriter(target_pcap)
        writer_array.append(writer)

    # Start to split according to split type
    if split_type == "mod":
        split_by_mod(reader)
    elif split_type == "mod_execution":
        split_by_mod_without_for_train(reader, train_num, split_num)
    elif split_type == "random":
        split_by_random(reader, split_num)
    elif split_type == "random_execution":
        split_by_random_without_for_train(reader, train_num, split_num)
    elif split_type == "ecmp":
        split_by_ecmp(reader, split_num)
    elif split_type == "ecmp_execution":
        split_by_ecmp_without_for_train(reader, train_num, split_num)
    elif split_type == "host":
        split_by_host(reader, split_num)
    elif split_type == "host_execution":
        split_by_host_without_for_train(reader, train_num, split_num)

    # Flush and close all parts' writers
    for i in range(split_num):
        writer = writer_array[i]
        writer.flush()
        writer.close()

