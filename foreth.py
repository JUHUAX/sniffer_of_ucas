from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils
from socket import *
import dpkt
import time
from forIP import doIP, doIP6, analysisIP
from forTransport import analysisTrans
from dpkt.utils import mac_to_str

curPacket = []

def ethernetCallback(win_pcap, param, header, pkt_data):
    global curPacket
    eth = dpkt.ethernet.Ethernet(pkt_data)
    curPacket.append(eth)
    #判断是否为IP数据报
    # print(eth.data.__class__.__name__)
    if isinstance(eth.data, dpkt.ip.IP):
        doIP(eth.data)
        # doIP(dpkt.ip.IP(eth.data))
    elif isinstance(eth.data, dpkt.ip6.IP6):
        # doIP6(dpkt.ip6.IP6(eth.data)) 
        doIP6(eth.data)     

def analysisEth(eth):
    ethCurPacket = {"dst":mac_to_str(eth.dst),
                 "src":mac_to_str(eth.src),
                 "type":hex(eth.type),
                 "data":eth.data
    }
    return ethCurPacket

def analyCurPacket(index):
    global curPacket
    ethLayerPacket = analysisEth(curPacket[index])
    ipLayerPacket = analysisIP(ethLayerPacket["data"])
    transLayerPacket = analysisTrans(ipLayerPacket["data"])
    return {"ethLayer": ethLayerPacket,
            "ipLayer": ipLayerPacket,
            "transLayer": transLayerPacket
            }
    
def readcurPacket():
    global curPacket
    return curPacket

def sendPacket(data):
    global curPacket
    for i in range(len(data)):
        data[i] = dpkt.ethernet.Ethernet(data[i])
    curPacket = data