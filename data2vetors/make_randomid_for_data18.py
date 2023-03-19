import numpy as np
import random


random.seed(1)

DATA_BASE = '../datasets/CSE18/CHDW_FSCIL-CSE18DataSet_16_1_4_64.npz'
data = np.load(DATA_BASE)
train_test_split = open('../datasets/CSE18/train_test_split.txt', 'w')
flowID_class_idx_labels = open('../datasets/CSE18/flowID_class_idx_labels.txt', 'w')
base_samples = open('../datasets/CSE18/base_samples.txt', 'w')
noval_samples = open('../datasets/CSE18/noval_samples.txt', 'w')

noval_classes = ['BruteForce-Web', 'BruteForce-XSS', 'Infiltration', 'DDoS-LOIC-UDP', 'DoS-GoldenEye',  'SSH-Bruteforce']
test_samples_num = 100

idx = 0
for attack_name in data.files:
    print(attack_name, data[attack_name].shape)
    random_num = data[attack_name].shape[0]
    random_list = np.arange(random_num)
    random.shuffle(random_list)
    temp = random_list[:test_samples_num]
    assert len(random_list) == data[attack_name].shape[0]

    for i in range(data[attack_name].shape[0]):
        idx += 1

        flowID_class_idx_labels.write(f'{idx} {attack_name}_{i}\n')

        train_test_split.write(f'{idx} 0'+'\n' if i in temp else f'{idx} 1'+'\n')

        if i not in temp:
            if attack_name not in noval_classes:
                base_samples.write(f'{attack_name}_{i}\n')
            if attack_name in noval_classes:
                noval_samples.write(f'{attack_name}_{i}\n')