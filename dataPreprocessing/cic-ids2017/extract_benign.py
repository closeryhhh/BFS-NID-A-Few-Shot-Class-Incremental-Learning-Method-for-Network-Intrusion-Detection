import os
import time
import datetime
import subprocess
import gc
import json

import dpkt
import socket


# step 1. 数据包处理为pcap格式
pcapng = "0000000 0a 0d 0d 0a 48 00 00 00 4d 3c 2b 1a 01 00 00 00"
pcap = "0000000 d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00"

root_base = "/Volumes/CIC-IDS-2017/ToPCAPs"

for pcap_day in os.listdir(root_base):
    pcap_file = os.path.join(root_base, pcap_day)
    a = subprocess.getoutput('hexdump "{}" | head -n 1'.format(pcap_file))
    if a == pcapng:
        # res = subprocess.getoutput('editcap "/Volumes/My Passport/CIC-IDS-2017/PCAPs/{}" "/Volumes/My Passport/CIC-IDS-2017/NewPCAPs/{}" -F pcap'.format(file, file))
        # a = subprocess.getoutput('hexdump "/Volumes/My Passport/CIC-IDS-2017/NewPCAPs/{}" | head -n 1'.format(file))
        print(pcap_file)


# step 2. 时间戳数据的书写和对应; 攻击和防御者处理
def str2localTimeStamp(start_str_timeStamp, end_str_timeStamp):
    # 14-02-2018 12:09
    start_timestamp = time.strptime(start_str_timeStamp, "%d/%m/%Y %H:%M")
    start_timestamp = datetime.datetime.fromtimestamp(time.mktime(start_timestamp))
    start_timestamp = start_timestamp + datetime.timedelta(hours=11) - datetime.timedelta(minutes=1)

    end_timestamp = time.strptime(end_str_timeStamp, "%d/%m/%Y %H:%M")
    end_timestamp = datetime.datetime.fromtimestamp(time.mktime(end_timestamp))
    end_timestamp = end_timestamp + datetime.timedelta(hours=11) + datetime.timedelta(minutes=1)
    return start_timestamp.timestamp(), end_timestamp.timestamp()

filename_label_map = {
    "Monday-WorkingHours.pcap" : [
        ["03/07/2017 01:00", "03/07/2017 13:00", "BENIGN"]
    ],
    "Tuesday-WorkingHours.pcap" : [
        ["4/7/2017 1:00", "4/7/2017 12:59", "BENIGN"]
    ],
    'Wednesday-WorkingHours.pcap' : [
        ["5/7/2017 1:00", "5/7/2017 12:59", "BENIGN"]
    ],
    'Thursday-WorkingHours.pcap':[
        ["6/7/2017 1:00", "6/7/2017 5:04", "BENIGN"],
        ["6/7/2017 8:59", "6/7/2017 12:59", "BENIGN"]
    ],
    'Friday-WorkingHours.pcap':[
        ["7/7/2017 1:00", "7/7/2017 5:02", "BENIGN"],
        ["7/7/2017 8:59", "7/7/2017 12:59", "BENIGN"]
    ]
}

# step 3. 开始遍历攻击流量包/每天
def get_biflow_id(pkt, ip_src, ip_dst):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    protocol = ip.p
    try:
        if protocol == 1:
            assert isinstance(ip.data, dpkt.icmp.ICMP)
        if protocol == 6:
            assert isinstance(ip.data, dpkt.tcp.TCP)
            tcp = ip.data
            sport = tcp.sport
            dport = tcp.dport
        elif protocol == 17:
            assert isinstance(ip.data, dpkt.udp.UDP)
            udp = ip.data
            sport = udp.sport
            dport = udp.sport

        if protocol == 1:
            if ip_src < ip_dst:
                pre = f'{ip_src}-{ip_dst}'
            else:
                pre = f'{ip_dst}-{ip_src}'
            return f'{pre}-{protocol}', protocol
        elif protocol in [6, 17]:
            if ip_src < ip_dst:
                pre = f'{ip_src}-{sport}-{ip_dst}-{dport}'
            else:
                pre = f'{ip_dst}-{dport}-{ip_src}-{sport}'
            return f'{pre}-{protocol}', protocol
        else:
            return None

    except Exception as e:
        return e


flows_maps = {}
timeout, timeout2 = 64, 120
save_to_disk = True
save_root_base = "/Volumes/CIC-IDS-2017/benignFlows"
label_number_map = {'WebAttackBruteForce':0, 'WebAttackXSS':0, 'WebAttackSqlInjection':0, 'Infiltration':0, \
    'Bot':0, 'PortScan':0, 'DDoS':0, 'FTP-Patator':0, 'SSH-Patator':0, 'Heartbleed':0, \
    'DoS-slowloris':0, 'DoS-GoldenEye':0, 'DoS-Hulk':0, 'DoS-Slowhttptest':0, 'BENIGN':0}

with open('flowids_benign.json', 'r') as jsn:
    flow_dict = json.load(jsn)

for pcap_day in os.listdir(root_base):
    # print(pcap_day)
    # if pcap_day in ['Monday-WorkingHours.pcap']:
    #     continue
    if pcap_day.startswith('._'):
        continue
    # if pcap_day not in ['Thursday-WorkingHours.pcap']:
    #     continue

    time_label_attacks = filename_label_map.get(pcap_day, None)
    if time_label_attacks:
        for attack in time_label_attacks:
            range_start_time, range_end_time, attack_type = attack
            curr_attack_path = os.path.join(save_root_base, pcap_day.split('.')[0], attack_type)
            if not os.path.exists(curr_attack_path):
                os.makedirs(curr_attack_path)
            range_start_time, range_end_time = str2localTimeStamp(range_start_time, range_end_time)

            pcap_file = os.path.join(root_base, pcap_day)
            flow_id = set()
            total_num = 0
            with open(pcap_file, 'rb') as pcap_reader_f:
                pkts_reader = dpkt.pcap.Reader(pcap_reader_f)

                for (ts, pkt) in pkts_reader:
                    if ts < range_start_time:
                        continue
                    if ts > range_end_time:
                        continue

                    eth = dpkt.ethernet.Ethernet(pkt)
                    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                        ip = eth.data
                        ip_src, ip_dst = socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)
                        
                        bid = get_biflow_id(pkt, ip_src, ip_dst)
                        if bid is None: #不考虑其它协议
                            continue
                        if isinstance(bid, Exception):
                            continue

                        biflow_id, protocol = bid
                        if biflow_id not in flow_dict[pcap_day.split('.')[0]][attack_type]:
                            continue

                        flow_id.add(biflow_id)

                        if biflow_id in flows_maps.keys():
                            cur_biflow = flows_maps[biflow_id]
                            last_seen_time = cur_biflow['last_seen_time']
                            
                            if (ts - cur_biflow['begin_time']) >= timeout2 or (ts - last_seen_time) >= timeout:
                            # if (ts - cur_biflow['begin_time']) >= timeout2 or (protocol == 6 and get_flags(ip.data.flags) == {'FIN', 'ACK'}):
                                save_biflow = flows_maps.pop(biflow_id)
                                total_num += 1

                                if save_to_disk:
                                    label_number_map[attack_type] += 1
                                    attack_num = label_number_map.get(attack_type)
                                    save_biflow_file_name = f'{attack_type}-{biflow_id}-{attack_num}.pcap'           
                                    pcap_save_path = os.path.join(curr_attack_path, save_biflow_file_name)
                                    with open(pcap_save_path, 'wb') as writer_file:
                                        writer_packets = dpkt.pcap.Writer(writer_file)
                                        writer_packets.writepkts(save_biflow['ts_pkts'])
                                        writer_file.flush()

                                flows_maps[biflow_id] = {
                                    'begin_time': ts,
                                    'last_seen_time': ts,
                                    'ts_pkts' : [(ts, pkt)]
                                    }
                            else:
                                cur_biflow['last_seen_time'] = ts
                                cur_biflow['ts_pkts'].append((ts, pkt))
                        else:
                            flows_maps[biflow_id] = {
                                'begin_time': ts,
                                'last_seen_time': ts,
                                'ts_pkts' : [(ts, pkt)]
                            }

                total_num += len(flows_maps.keys())
                
                if save_to_disk:
                    for biflow_id in flows_maps.keys():
                        label_number_map[attack_type] += 1
                        attack_num = label_number_map.get(attack_type)
                        save_biflow = flows_maps.get(biflow_id)
                        save_biflow_file_name = f'{attack_type}-{biflow_id}-{attack_num}.pcap'

                        pcap_save_path = os.path.join(curr_attack_path, save_biflow_file_name)
                        with open(pcap_save_path, 'wb') as writer_file:
                                writer_packets = dpkt.pcap.Writer(writer_file)
                                writer_packets.writepkts(save_biflow['ts_pkts'])
                                writer_file.flush()

                flows_maps.clear()
            print(attack_type, total_num, len(flow_id), len(flow_dict[pcap_day.split('.')[0]][attack_type])//2)
            print('save:', label_number_map)
    gc.collect()
