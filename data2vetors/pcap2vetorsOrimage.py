# -*- coding:utf-8 -*-


from abc import abstractmethod
import os
import numpy as np
from scapy.all import PcapReader, bytes_encode


def pkt_to_pixel(pkt):
    return [int(b) for b in bytes_encode(pkt)]

def reset_addr(pkt):
    if pkt.haslayer('Ether') and pkt.haslayer('IP'):
        pkt.getlayer('Ether').dst = "00:00:00:00:00:00"
        pkt.getlayer('Ether').src = "00:00:00:00:00:00"
        pkt.getlayer('IP').src = "0.0.0.0"
        pkt.getlayer('IP').dst = "0.0.0.0"
    return pkt


class ConvertFlow(object):
    def __init__(self, pkts_d, pkt_h, pkt_w, pkt_c, mask) -> None:
        super().__init__()
        self.pkts_d = pkts_d
        self.pkt_h = pkt_h
        self.pkt_w = pkt_w
        self.pkt_c = pkt_c
        self.mask = mask
        self.flow_instance = None

    @abstractmethod
    def init_flow_numpy(self):
        pass

    @abstractmethod
    def add_pkt(self, pkt):
        pass

    def get_flow(self):
        return self.flow_instance


class CDHW(ConvertFlow):
    def __init__(self, pkts_d, pkt_h, pkt_w, pkt_c, mask) -> None:
        super().__init__(pkts_d, pkt_h, pkt_w, pkt_c, mask)
        if pkt_w != pkt_h:
            raise EOFError('pkt_h和pkt_w在CDHW方法中需要相同')
        assert pkt_c == 1

        self.pkt_num = self.pkt_h * self.pkt_w
        self.init_flow_numpy()
    
    def init_flow_numpy(self):
        # HWCN
        self.idx = 0
        self.flow_instance = np.empty((self.pkt_c * self.pkts_d, self.pkt_h, self.pkt_w), dtype=np.int32)
        self.flow_instance.fill(self.mask)
        # print(self.flow_instance.shape)

    def add_pkt(self, pkt):
        temp_pkt = np.empty((self.pkt_num), dtype=np.int32)
        temp_pkt.fill(self.mask)
        curr_pkt_len = self.pkt_num if len(pkt) > self.pkt_num else len(pkt)
        temp_pkt[:curr_pkt_len] = pkt[:curr_pkt_len]
        temp_pkt.resize(self.pkt_h, self.pkt_w)
        # print(temp_pkt)
        self.flow_instance[self.idx, :, :] = temp_pkt
        self.idx += 1


class CHDW(ConvertFlow):
    def __init__(self, pkts_d, pkt_h, pkt_w, pkt_c, mask) -> None:
        super().__init__(pkts_d, pkt_h, pkt_w, pkt_c, mask)
        # 该方法要求pkt_h * pkts_d 和 pkt_w相同
        if pkt_h * pkts_d != pkt_w:
            raise EOFError('pkt_h * pkts_d和pkt_w在CHDW方法中需要相同')
        assert pkt_c == 1

        self.pkt_num = self.pkt_h * self.pkt_w
        self.init_flow_numpy()
    
    def init_flow_numpy(self):
        # HWCN
        self.idx = 0
        self.flow_instance = np.empty((self.pkt_c, self.pkt_h * self.pkts_d, self.pkt_w), dtype=np.int32)
        self.flow_instance.fill(self.mask)
        # print(self.flow_instance.shape)

    def add_pkt(self, pkt):
        temp_pkt = np.empty((self.pkt_num), dtype=np.int32)
        temp_pkt.fill(self.mask)
        curr_pkt_len = self.pkt_num if len(pkt) > self.pkt_num else len(pkt)
        temp_pkt[:curr_pkt_len] = pkt[:curr_pkt_len]
        temp_pkt.resize(self.pkt_h, self.pkt_w)
        self.flow_instance[self.pkt_c - 1, self.idx * self.pkt_h:(self.idx + 1) * self.pkt_h, :] = temp_pkt
        self.idx += 1


class CDHWFCNet(ConvertFlow):
    def __init__(self, pkts_d, pkt_h, pkt_w, pkt_c, mask) -> None:
        super().__init__(pkts_d, pkt_h, pkt_w, pkt_c, mask)

        self.pkt_num = self.pkt_h * self.pkt_w
        self.init_flow_numpy()

    def init_flow_numpy(self):
        self.idx = 0
        self.flow_instance = np.empty((self.pkt_c, self.pkts_d, self.pkt_h, self.pkt_w), dtype=np.int32)
        self.flow_instance.fill(self.mask)

    def add_pkt(self, pkt):
        temp_pkt = np.empty((self.pkt_num), dtype=np.int32)
        temp_pkt.fill(self.mask)
        curr_pkt_len = self.pkt_num if len(pkt) > self.pkt_num else len(pkt)
        temp_pkt[:curr_pkt_len] = pkt[:curr_pkt_len]
        temp_pkt.resize(self.pkt_h, self.pkt_w)
        self.flow_instance[self.pkt_c - 1, self.idx, :, :] = temp_pkt
        self.idx += 1


def pcapToVetors(pcap_path, pkts_d=20, pkt_h=8, pkt_w=8, pkt_c=1, mask = 0,  mode='CDHW'):
    if not os.path.exists(pcap_path) or not os.path.isfile(pcap_path) or not pcap_path.endswith('.pcap'):
        raise EOFError('路径或文件不存在, 或文件格式错误')

    if mode == 'CHDW': # such as: C x DH x W
        OBJFlow = CHDW
    elif mode == 'CDHWFCNet': # such as: C x D x H x W
        OBJFlow = CDHWFCNet
    else:
        raise EOFError(f'mode={mode}不存在!')

    convertObj = OBJFlow(pkts_d, pkt_h, pkt_w, pkt_c, mask)

    with PcapReader(pcap_path) as pkts:
        for idx, pkt in enumerate(pkts):
            if idx >= pkts_d:
                break

            pkt = reset_addr(pkt)
            pkt_pixels = pkt_to_pixel(pkt)
            convertObj.add_pkt(pkt=pkt_pixels)
    return convertObj.get_flow()


if __name__ == "__main__":
    pcap_path = 'sql-injection_22-02.pcap'
    mode = "CDHWFCNet"
    flow = pcapToVetors(pcap_path, pkts_d=16, pkt_h=16, pkt_w=16, pkt_c=1, mask = 0,  mode=mode)
    print('process')
    print(flow.shape)
    print(flow)