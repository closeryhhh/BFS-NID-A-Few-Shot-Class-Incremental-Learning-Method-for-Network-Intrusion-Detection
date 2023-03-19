# -*- coding:utf-8 -*-
import os
from statistics import mean
import numpy as np
from tqdm import tqdm
import random
import json
import dpkt

from pcap2vetorsOrimage import pcapToVetors


dataset_root_path = '/Volumes/CSE-CIC-IDS2018/FSCIL-CSEIDS18/attacksFlows'
h_dim = 4
w_dim = 64
c_dim = 1
d_dim = 16
mode = 'CHDW'
model_name = 'FSCIL-CSE18DataSet'
save_data_path = f'./../datasets/{mode}_{model_name}.json'
save_model_data_path = f'./../datasets/{mode}_{model_name}_{d_dim}_{c_dim}_{h_dim}_{w_dim}.npz'
PER_NUM_CLASS = 2000


data = {}
save_dict_path = {}
noval_classes = ['BruteForce-Web', 'BruteForce-XSS', 'Infiltration', 'DDoS-LOIC-UDP', 'DoS-GoldenEye',  'SSH-Bruteforce']

flow_dict = None
with open(save_data_path, 'r') as jsn:
    flow_dict = json.load(jsn)
for class_name, selected_files in flow_dict.items():
    # selected_files = flow_dict[class_name]
    files_len = len(selected_files)
    save_dict_path[class_name] = selected_files

    file_path = selected_files[0]
    get_sample = pcapToVetors(file_path, pkts_d=d_dim, pkt_h=h_dim, pkt_w=w_dim, pkt_c=c_dim, mask = 0,  mode=mode)
    # sample_c, sample_h, sample_w = get_sample.shape
    # filesClassData = np.empty((files_len, sample_c, sample_h, sample_w), dtype=np.float32)
    filesClassData = np.empty((files_len,) + get_sample.shape, dtype=np.float32)

    with tqdm(total=files_len) as pbar:
        pbar.set_description(f'Processing {class_name}')
        for idx, file_path in tqdm(enumerate(selected_files)):
            instance = pcapToVetors(file_path, pkts_d=d_dim, pkt_h=h_dim, pkt_w=w_dim, pkt_c=c_dim, mask = 0,  mode=mode)
            # instance = instance[:, :, np.newaxis]
            # instance = instance / 255 # Normalise to 0-1
            # instance = (instance - instance.min()) / (instance.max() - instance.min())
            filesClassData[idx] = instance
            pbar.update(1)
    data[class_name] = filesClassData
np.savez(save_model_data_path, **data)
data.clear()

# step 2: 
data = np.load(save_model_data_path)
for file in data.files:
    print(file, data[file].shape)