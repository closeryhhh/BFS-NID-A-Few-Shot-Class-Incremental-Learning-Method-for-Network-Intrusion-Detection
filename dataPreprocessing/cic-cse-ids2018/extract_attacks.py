import os
import time
import datetime

from tqdm import tqdm
import dpkt
import socket
import json
import gc


error_files = '''
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-23-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.66.115
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-23-02-2018/pcap/pcap/UCAP172.31.69.22
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-23-02-2018/pcap/pcap/UCAP172.31.69.25
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-01-03-2018/pcap/pcap/UCAP172.31.69.22
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-15-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.67.119
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-15-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.67.82
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-15-02-2018/pcap/pcap/UCAP172.31.69.21
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-15-02-2018/pcap/pcap/UCAP172.31.69.22
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-22-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.64.65
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-22-02-2018/pcap/pcap/UCAP172.31.69.15
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-22-02-2018/pcap/pcap/UCAP172.31.69.21
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-22-02-2018/pcap/pcap/UCAP172.31.69.28
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-22-02-2018/pcap/pcap/UCAP172.31.69.7
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Tuesday-20-02-2018/pcap/pcap/UCAP172.31.69.22
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.64.122
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.64.17
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.65.76
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.66.100
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.66.120
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/UCAP172.31.69.21
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/UCAP172.31.69.22
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-21-02-2018/pcap/pcap/UCAP172.31.69.15
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-21-02-2018/pcap/pcap/UCAP172.31.69.21
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-28-02-2018/pcap/pcap/UCAP172.31.69.15
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-28-02-2018/pcap/pcap/UCAP172.31.69.27
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.24 - Shortcut.lnk
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/UCAP172.31.69.18
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/UCAP172.31.69.27
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-16-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.65.86
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-16-02-2018/pcap/pcap/capDESKTOP-AN3U28N-172.31.66.72
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-16-02-2018/pcap/pcap/UCAP172.31.69.21
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-16-02-2018/pcap/pcap/UCAP172.31.69.22
/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-16-02-2018/pcap/pcap/UCAP172.31.69.27
'''.strip().split('\n')

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


def str2localTimeStamp(start_str_timeStamp, end_str_timeStamp):
    # 14-02-2018 12:09
    start_timestamp = time.strptime(start_str_timeStamp, "%d-%m-%Y %H:%M")
    start_timestamp = datetime.datetime.fromtimestamp(time.mktime(start_timestamp))
    start_timestamp = start_timestamp + datetime.timedelta(hours=12) - datetime.timedelta(minutes=1)

    end_timestamp = time.strptime(end_str_timeStamp, "%d-%m-%Y %H:%M")
    end_timestamp = datetime.datetime.fromtimestamp(time.mktime(end_timestamp))
    end_timestamp = end_timestamp + datetime.timedelta(hours=12) + datetime.timedelta(minutes=1)
    return start_timestamp.timestamp(), end_timestamp.timestamp()

filename_day_map = {
    'Friday-02-03-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.10',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.12',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.14',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.17',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.23',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.26',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.29',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.30',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.6',
            '/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-02-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.8'],
    'Friday-23-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-23-02-2018/pcap/pcap/UCAP172.31.69.28'],
    'Thursday-01-03-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-01-03-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.13'],
    'Thursday-15-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-15-02-2018/pcap/pcap/UCAP172.31.69.25'],
    'Tuesday-20-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Tuesday-20-02-2018/pcap/pcap/UCAP172.31.69.25'],
    'Wednesday-14-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-14-02-2018/pcap/pcap/UCAP172.31.69.25'],
    'Wednesday-21-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-21-02-2018/pcap/pcap/UCAP172.31.69.28'],
    'Wednesday-28-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Wednesday-28-02-2018/pcap/pcap/capEC2AMAZ-O4EL3NG-172.31.69.24'],
    'Friday-16-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Friday-16-02-2018/pcap/pcap/UCAP172.31.69.25'],
    'Thursday-22-02-2018' : ['/Volumes/CSE-CIC-IDS2018/Original Network Traffic and Log data/Thursday-22-02-2018/pcap/pcap/UCAP172.31.69.28']
    }

filename_label_map = {
    'Friday-02-03-2018':[
        ['02-03-2018 10:11', '02-03-2018 11:34', 'Bot', {'18.219.211.138'}],
        ['02-03-2018 14:24', '02-03-2018 15:55', 'Bot', {'18.219.211.138'}]
    ],
    'Friday-23-02-2018':[
        ['23-02-2018 10:03', '23-02-2018 11:03', 'BruteForce-Web', {'18.218.115.60'}],
        ['23-02-2018 13:00', '23-02-2018 14:10', 'BruteForce-XSS', {'18.218.115.60'}],
        ['23-02-2018 15:05', '23-02-2018 15:18', 'SQL-Injection', {'18.218.115.60'}]
    ],
    'Thursday-22-02-2018':[
        ['22-02-2018 10:17', '22-02-2018 11:24', 'BruteForce-Web', {'18.218.115.60'}],
        ['22-02-2018 13:50', '22-02-2018 14:29', 'BruteForce-XSS', {'18.218.115.60'}],
        ['22-02-2018 16:15', '22-02-2018 16:29', 'SQL-Injection', {'18.218.115.60'}]
    ],
    'Thursday-01-03-2018':[
        ['01-03-2018 9:57', '01-03-2018 10:55', 'Infiltration', {'13.58.225.34'}],
        ['01-03-2018 14:00', '01-03-2018 15:37', 'Infiltration', {'13.58.225.34'}]
    ],
    'Thursday-15-02-2018':[
        ['15-02-2018 9:26', '15-02-2018 10:09', 'DoS-GoldenEye', {'172.31.70.46', '18.219.211.138'}],
        ['15-02-2018 10:59', '15-02-2018 11:40', 'DoS-Slowloris', {'172.31.70.8', '18.217.165.70'}]
    ],
    'Tuesday-20-02-2018':[
        ['20-02-2018 10:12', '20-02-2018 11:17', 'DDoS-LOIC-HTTP', {'18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135',
            '18.219.5.43', '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'}],
        ['20-02-2018 13:13', '20-02-2018 13:32', 'DDoS-LOIC-UDP', {'18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135',
            '18.219.5.43', '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'}]
    ],
    'Wednesday-14-02-2018':[
        ['14-02-2018 10:32', '14-02-2018 12:09', 'FTP-BruteForce', {'172.31.70.4', '18.221.219.4'}],
        ['14-02-2018 14:01', '14-02-2018 15:31', 'SSH-Bruteforce', {'172.31.70.6', '13.58.98.64'}]
    ],
    'Wednesday-21-02-2018':[
        ['21-02-2018 14:05', '21-02-2018 15:05', 'DDoS-HOIC', {'18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135',
            '18.219.5.43', '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'}],
        ['21-02-2018 10:09', '21-02-2018 10:43', 'DDoS-LOIC-UDP', {'18.218.115.60', '18.219.9.1', '18.219.32.43', '18.218.55.126', '52.14.136.135',
            '18.219.5.43', '18.216.200.189', '18.218.229.235', '18.218.11.51', '18.216.24.42'}]
    ],
    'Wednesday-28-02-2018':[
        ['28-02-2018 10:50', '28-02-2018 12:05', 'Infiltration', {'13.58.225.34'}],
        ['28-02-2018 13:42', '28-02-2018 14:40', 'Infiltration', {'13.58.225.34'}]
    ],
    'Friday-16-02-2018':[
        ['16-02-2018 10:12', '16-02-2018 11:08', 'DoS-SlowHTTPTest', {'172.31.70.23', '13.59.126.31'}],
        ['16-02-2018 13:45', '16-02-2018 14:19', 'DoS-Hulk', {'172.31.70.16', '18.219.193.20'}]
    ]
}

attack_id_map = {
    'Bot':0, 'BruteForce-Web':0, 'BruteForce-XSS':0, 'SQL-Injection':0, 'Infiltration':0, 'DoS-GoldenEye':0, 'DoS-Slowloris':0, 'DDoS-LOIC-HTTP':0, 'DDoS-LOIC-UDP':0, 'DDoS-HOIC':0, 'FTP-BruteForce':0, 'SSH-Bruteforce':0, 'DoS-Hulk':0, 'DoS-SlowHTTPTest':0
}

root_save_path = '/Volumes/CSE-CIC-IDS2018/FSCIL-CSEIDS18/attacksFlows'
timeout, timeout2 = 64, 120
attack_num = {}

with open('flow_indx.json', 'r') as jsn:
    flow_dict = json.load(jsn)

for day_pcaps in filename_day_map.keys():

    day_pcaps_path = filename_day_map[day_pcaps]

    time_label_attacks = filename_label_map.get(day_pcaps, None)

    if time_label_attacks:
            for attack in time_label_attacks:
                print(f'start process {day_pcaps}')
                range_start_time, range_end_time, attack_type, attacker_IPs = attack

                if attack_type not in flow_dict.keys():
                    continue


                range_start_time, range_end_time = str2localTimeStamp(range_start_time, range_end_time)

                for ip_pcap_file in tqdm(day_pcaps_path):
                    if len(flow_dict[attack_type]) == 0:
                        break

                    sub_root_save_path = os.path.join(root_save_path, attack_type)
                    if not os.path.exists(sub_root_save_path): os.makedirs(sub_root_save_path)

                    flows_maps = {}

                    try:
                        with open(ip_pcap_file, 'rb') as pcap_reader_f:
                                pkts_reader = dpkt.pcap.Reader(pcap_reader_f)
                                for (ts, pkt) in pkts_reader:
                                    if ts < range_start_time:
                                        continue
                                    if ts > range_end_time:
                                        continue
                                    
                                    eth = dpkt.ethernet.Ethernet(pkt)

                                    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                                        ip = eth.data
                                        try:
                                            ip_src, ip_dst = socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)
                                        except:
                                            continue
                                        if ip_src not in attacker_IPs and ip_dst not in attacker_IPs:
                                            continue
                                        
                                        bid = get_biflow_id(pkt, ip_src, ip_dst)
                                        if bid is None:
                                            continue
                                        if isinstance(bid, Exception):
                                            continue
                                        
                                        biflow_id, protocol = bid

                                        if biflow_id in flows_maps.keys():
                                            cur_biflow = flows_maps[biflow_id]
                                            last_seen_time = cur_biflow['last_seen_time']

                                            if (ts - cur_biflow['begin_time']) >= timeout2 or (ts - last_seen_time) >= timeout:
                                                save_biflow = flows_maps.pop(biflow_id)
                                                get_id = attack_id_map[attack_type]
                                                save_biflow_file_name = f'{attack_type}-{biflow_id}-{get_id}.pcap'
                                                attack_id_map[attack_type] += 1

                                                if get_id in flow_dict[attack_type]:
                                                    flow_dict[attack_type].remove(get_id)
                                                    pcap_save_path = os.path.join(sub_root_save_path, save_biflow_file_name)
                                                    with open(pcap_save_path, 'wb') as writer_file:
                                                        writer_packets = dpkt.pcap.Writer(writer_file)
                                                        writer_packets.writepkts(save_biflow['ts_pkts'])
                                                        writer_file.flush()

                                                    if len(flow_dict[attack_type]) == 0:
                                                        break

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

                    except dpkt.dpkt.NeedData:
                        continue
                    except dpkt.dpkt.UnpackError:
                        continue
                    except ValueError:
                        continue

                    for biflow_id in flows_maps.keys():
                        save_biflow = flows_maps.get(biflow_id)
                        get_id = attack_id_map[attack_type]
                        save_biflow_file_name = f'{attack_type}-{biflow_id}-{get_id}.pcap'
                        attack_id_map[attack_type] += 1

                        if get_id in flow_dict[attack_type]:
                            flow_dict[attack_type].remove(get_id)
                            pcap_save_path = os.path.join(sub_root_save_path, save_biflow_file_name)
                            with open(pcap_save_path, 'wb') as writer_file:
                                writer_packets = dpkt.pcap.Writer(writer_file)
                                writer_packets.writepkts(save_biflow['ts_pkts'])
                                writer_file.flush()

                            if len(flow_dict[attack_type]) == 0:
                                break
                    gc.collect()