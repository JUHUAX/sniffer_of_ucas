from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils

import dpkt
import time
import datetime
import sys

ans = {}

def http_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    print(eth.data.__class__.__name__)
    sys.exit()

def forIP(device_name):
    WinPcapUtils.capture_on_device_name(device_name=device_name, callback=http_callback)


forIP("\\Device\\NPF_{5D0D792C-E3F1-484E-8D1F-9C224535DEB6}")
